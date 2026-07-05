// WhereECH service worker — the only part of the extension that touches the
// network or persistent storage.
//
// What this file does:
//   * Watches top-frame navigations (via chrome.webNavigation) so it can
//     identify the hostname of the page you just loaded.
//   * Sends ONE DNS-over-HTTPS query per hostname to the resolver you chose
//     in Settings, asking for that hostname's HTTPS resource record (RFC
//     9460). That record is public DNS data — anyone can look it up.
//   * Parses the record to see whether it advertises an ECH key, and sets
//     the toolbar badge accordingly.
//
// What this file does NOT do:
//   * It does not read, record, or transmit the URL path, query string,
//     cookies, form data, request/response bodies, or anything else about
//     the page beyond the hostname.
//   * It does not read from other tabs, inject content scripts, open
//     connections to any host except the DoH resolver you picked (and the
//     visited site itself, only if you explicitly enabled the Cloudflare
//     trace probe in Settings).
//   * It does not contact any analytics, telemetry, logging, update, or
//     crash-report endpoint. There is no "phone home".
//   * It does not access browser history, bookmarks, downloads, saved
//     passwords, or any other browser data. The manifest does not even
//     request those permissions.
//
// The only permissions the manifest asks for are:
//   tabs           — to read the active tab's URL for the popup view
//   webNavigation  — to know when you navigate so we can refresh the badge
//   storage        — to persist your Settings choices locally
//   host_permissions — ONLY the four hardcoded DoH providers
//   optional_host_permissions — https://*/*, requested ONLY if you opt into
//                    the trace probe or set a custom resolver

import { parseHttpsRr } from "./ech.js";
import {
  recordEchHost,
  listEchHosts,
  removeEchHost,
  clearEchHistory,
  getHistoryBlob,
  importHistoryBlob,
} from "./history.js";

// How long a successful lookup stays in the in-memory cache. Used to avoid
// repeating the same DoH query for a site you just visited. 10 minutes is
// short enough to pick up real DNS changes, long enough to hide most
// re-navigations from the resolver.
const SUCCESS_TTL_MS = 10 * 60 * 1000;
// Failed lookups cache much more briefly so a transient error (offline,
// resolver hiccup) clears quickly.
const FAILURE_TTL_MS = 30 * 1000;

const STATUS = {
  ADVERTISED: "advertised",
  CONFIRMED: "confirmed",
  OFFERED: "offered",       // ECH in DNS but trace probe says it wasn't negotiated
  NOT_ADVERTISED: "not_advertised",
  HISTORY: "history",
  UNKNOWN: "unknown",
  CHECKING: "checking",     // lookup in flight — transient, never stored in cache
  SKIPPED: "skipped",
};

// The only DNS-over-HTTPS endpoints this extension can contact without
// additional user consent. These four URLs are mirrored in manifest.json
// under "host_permissions" — the browser itself blocks requests to any
// other host unless the user explicitly grants extra permissions.
const DOH_PROVIDERS = {
  cloudflare: "https://cloudflare-dns.com/dns-query",
  // Quad9's secured endpoint on 443: blocklist of known-malicious domains,
  // no EDNS Client Subnet. (The :5053 variant is the *unsecured*, no-blocklist
  // service — it would contradict the "blocks malicious domains" UI label.)
  quad9: "https://dns.quad9.net/dns-query",
  controld: "https://freedns.controld.com/p0",
};

const DEFAULTS = {
  resolver: "cloudflare",
  customResolver: "",
  customPresets: [],
  nextdnsId: "",
  autoLookup: true,
  traceProbe: false,
  keepHistory: false,
  historyFastPath: false,
  noCache: false,
  notifyOnChange: false,
  allowlist: [],
  blocklist: [],
  compareResolvers: false,
  theme: "system",
};

// In-memory only. Lives inside this service worker and is wiped whenever
// the browser restarts the worker (which happens frequently). Nothing in
// this Map is ever written to disk. It exists purely to coalesce repeated
// lookups of the same host during one browsing session. A hard size cap
// prevents unbounded growth on long-lived workers: insertion order + a
// move-to-end on hit gives cheap LRU eviction.
const CACHE_MAX = 500;
const cache = new Map(); // host -> result

function cacheGet(host) {
  const v = cache.get(host);
  if (v === undefined) return undefined;
  // Move to end to mark as most-recently-used.
  cache.delete(host);
  cache.set(host, v);
  return v;
}

function cacheSet(host, value) {
  if (cache.has(host)) cache.delete(host);
  cache.set(host, value);
  while (cache.size > CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

// In-flight deduplication: if evaluateHost is already running for a given
// host, subsequent callers wait on the same Promise rather than firing a
// duplicate DoH query. Keyed by hostname; entries are deleted when the
// lookup settles. Force-mode lookups bypass this map entirely.
const pending = new Map(); // host → Promise<result>

// In-memory Set of hosts known to support ECH, derived lazily from the
// encrypted history store. null means "not yet loaded". Once populated it
// stays in sync via optimistic adds (after recordEchHost) and explicit
// removals (after removeEchHost / clearEchHistory). This avoids the cost
// of decrypting and JSON-parsing the full history blob on every navigation
// when the history fast-path is enabled — a Set.has() is O(1) in memory.
let echHostSet = null;
let echHostSetLoading = null;

// Populate echHostSet from the encrypted history store on first use, then
// cache the result. Concurrent callers share the same single-decrypt promise
// rather than each decrypting the blob independently. A catch-all prevents
// a decryption failure from breaking the whole fast-path (the lookup falls
// through to a live DoH query instead).
async function getEchHostSet() {
  if (echHostSet !== null) return echHostSet;
  if (!echHostSetLoading) {
    echHostSetLoading = (async () => {
      const entries = await listEchHosts().catch(() => []);
      echHostSet = new Set(entries.map(e => e.host));
      return echHostSet;
    })();
  }
  return echHostSetLoading;
}

// Lets us correlate an async lookup that finishes late with the tab it
// started in, so we don't paint a stale badge on a tab that has since
// navigated elsewhere. In-memory only, wiped with the worker.
const tabHost = new Map(); // tabId -> host

// Reads Settings from chrome.storage.local. This is the ONLY source of
// persistent configuration the extension uses; it never syncs anywhere,
// never leaves the device, and is scoped to this extension's own storage
// area — other extensions and websites cannot read it.
// Memoized in-memory copy of the merged settings. The service worker reads
// settings on every navigation (handleNavigation) and again inside the lookup
// pipeline (performLookup); without this memo that's two storage reads per
// page load on the hot path. The cache is invalidated whenever any local
// storage key changes (see chrome.storage.onChanged below) and is naturally
// empty after a worker restart, so it can never serve stale config across a
// settings change.
let cachedSettings = null;
async function getSettings() {
  if (cachedSettings) return cachedSettings;
  cachedSettings = await chrome.storage.local.get(DEFAULTS); // get() with defaults already merges
  return cachedSettings;
}

// Detects raw IP literals so we don't do a useless DNS lookup on them.
// ECH is a property of a name, so there's nothing to look up for an IP.
// We handle both IPv4 (dotted-quad) and IPv6 (RFC 4291, including
// ::-compressed forms and bracketed forms like [::1]). URL.hostname
// strips brackets, but we accept the colons-containing form explicitly.
const IPV4_RE = /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/;
// IPv6: a single "::" compression marker, hex groups separated by colons,
// optional trailing IPv4 dotted-quad (RFC 4291 §2.2). Loose but practical.
const IPV6_RE = /^(([0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}?)(::?(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){0,6}(\d{1,3}\.){3}\d{1,3}))?$/;
function isIpLiteral(host) {
  if (!host) return false;
  if (IPV4_RE.test(host)) {
    // Validate each octet is 0–255.
    return host.split(".").every((o) => {
      const n = Number(o);
      return n >= 0 && n <= 255;
    });
  }
  return IPV6_RE.test(host);
}

// Gatekeeper: decides whether a URL is even eligible for a lookup. Any URL
// that isn't a plain https:// site on a real hostname is dropped here —
// chrome://, about:, file://, data:, view-source:, extension pages, raw
// IP addresses, localhost, and anything that fails to parse all return
// true. Nothing downstream of this function will ever be asked about a
// URL that didn't clear this filter. The only thing we ever retain from
// a URL that does clear it is the hostname.
function shouldSkipUrl(url) {
  if (!url) return true;
  let u;
  try { u = new URL(url); } catch { return true; }
  if (u.protocol !== "https:") return true; // ECH only meaningful on HTTPS
  if (!u.hostname) return true;
  if (u.hostname === "localhost") return true;
  if (isIpLiteral(u.hostname)) return true;
  return false;
}

// Per-site list helpers. The allowlist, if non-empty, restricts automatic
// lookups to ONLY the listed hosts (a positive filter). The blocklist
// always excludes its entries from automatic lookups (a negative filter).
// Both are optional and empty by default. Manual lookups (clicking the
// popup or Re-check) always bypass these filters — the user explicitly
// asked, so we honor the request regardless.
//
// Lists are stored as plain arrays of host strings in chrome.storage.local.
// They are NOT encrypted: they contain only hosts the user typed in on
// purpose, not observed-browsing data, so the encryption-at-rest guarantee
// of the ECH history feature doesn't apply here.
function listContains(list, host) {
  if (!Array.isArray(list) || list.length === 0) return false;
  const h = String(host || "").toLowerCase();
  return list.some((x) => typeof x === "string" && x.toLowerCase() === h);
}

function isAutoLookupAllowed(host, settings) {
  if (listContains(settings.blocklist, host)) return false;
  if (Array.isArray(settings.allowlist) && settings.allowlist.length > 0) {
    return listContains(settings.allowlist, host);
  }
  return true;
}

// Turns your Settings into the concrete URL we will fetch for DNS lookups.
// This function never contacts the network by itself; it only chooses a
// URL. The real request happens in dohLookupHttpsRR below. Three trust
// checks live here:
//   1. For NextDNS, the profile ID must be 1–32 alphanumeric characters.
//      This bound prevents someone from stuffing path traversal or query
//      strings into what's supposed to be an opaque ID.
//   2. Whichever URL is chosen MUST parse cleanly.
//   3. Whichever URL is chosen MUST use https:. We refuse plain http,
//      ws, file, data, and any other scheme — because the whole point of
//      this extension is to avoid leaking hostnames in cleartext, and a
//      non-HTTPS DoH query would do exactly that.
// The options page enforces HTTPS at save time, but this check runs at
// USE time as well — the service worker refuses to trust settings blindly.
function resolverUrl(settings) {
  let raw;
  if (settings.resolver === "custom" && settings.customResolver) {
    raw = settings.customResolver;
  } else if (settings.resolver === "nextdns") {
    const id = (settings.nextdnsId || "").trim();
    if (!id) throw new Error("NextDNS profile ID is not set — open Settings.");
    if (!/^[A-Za-z0-9]{1,32}$/.test(id)) {
      throw new Error("NextDNS profile ID is invalid.");
    }
    raw = `https://dns.nextdns.io/${id}`;
  } else {
    raw = DOH_PROVIDERS[settings.resolver] || DOH_PROVIDERS.cloudflare;
  }
  // Defense in depth: whatever came out of settings MUST be a real https URL.
  // Options-page validation is only advisory; the service worker is the last
  // line of defense before a cleartext lookup could leak a hostname.
  let parsed;
  try { parsed = new URL(raw); } catch { throw new Error("Resolver URL is not a valid URL."); }
  if (parsed.protocol !== "https:") {
    throw new Error("Resolver URL must use HTTPS.");
  }
  return parsed.toString();
}

// Performs exactly one DNS-over-HTTPS query using RFC 8484 wireformat GET.
//
// Why RFC 8484 instead of the earlier JSON DoH format:
//   RFC 8484 (dns-message) is the IETF standard and is supported by every
//   major DoH provider. The JSON format (application/dns-json) was a
//   non-standard extension used by Cloudflare and Google but never
//   standardised; Quad9 retired their JSON endpoint in May 2025, and
//   ControlD returns binary wireformat regardless of the Accept header.
//   Switching to RFC 8484 makes all four built-in resolvers work correctly
//   and removes the limitation on which custom resolvers users can use.
//
// What it sends:
//   A single GET request with one query parameter: dns=<base64url-encoded
//   DNS query message>. The DNS message asks for the HTTPS record (type 65)
//   of the hostname. That is the only piece of user-derived data that leaves
//   the device, and it goes to exactly one host.
//
// What it does NOT send:
//   * No cookies (credentials: "omit")
//   * No Referer header (referrerPolicy: "no-referrer")
//   * No custom fingerprinting headers
//   * No request body; redirects refused (redirect: "error")
//
// Failure-mode guarantees:
//   * 5-second AbortController timeout; 64 KB response size cap.

// Build a minimal DNS query wire message for an HTTPS (type 65) lookup.
//
// We also include an OPT pseudo-RR (RFC 6891) carrying an EDNS(0) Padding
// option (RFC 8467). Padding the query to a uniform target size frustrates
// traffic analysis based on hostname length: without padding, a passive
// observer of the DoH request stream can use the request size to fingerprint
// which site is being looked up, because the DNS query size is roughly
// proportional to the hostname length. Padding to a power-of-two target
// (default 256 bytes) collapses many distinct hostname lengths into the
// same wire size, leaking far less about the query.
//
// The PAD option's data field is filled with zero bytes; only the length
// matters for confidentiality. We never pad the response — that's the
// resolver's job, and most major DoH providers already do it.
function buildDnsQuery(host, targetSize = 256) {
  const labels = host.split(".");
  let qnameLen = 1; // root 0x00
  for (const l of labels) qnameLen += 1 + l.length;
  const headerLen = 12;
  const questionLen = qnameLen + 4; // qname + qtype + qclass

  // OPT RR (RFC 6891): name=root(1), type=41(2), class=udp payload size(2),
  // ttl=extended-rcode+flags(4), rdlen(2), then options.
  // Padding option (RFC 8467): code=12(2), len(2), padding bytes.
  // We compute the padding length so the entire message lands on targetSize.
  const optName = 1;       // root label
  const optFixed = 10;     // type + class + ttl + rdlen
  const padOptHeader = 4;  // option-code + option-len
  const fixedLen = headerLen + questionLen + optName + optFixed + padOptHeader;
  let padLen = Math.max(0, targetSize - fixedLen);
  // RFC 8467 recommends the padding be at least enough to reach the target
  // block size; we cap at the target to avoid unbounded growth on huge hosts.
  if (padLen > targetSize) padLen = targetSize;

  const buf = new Uint8Array(fixedLen + padLen);
  const view = new DataView(buf.buffer);
  view.setUint16(0, (Math.random() * 0xffff) >>> 0); // random ID (reply-matching only)
  view.setUint16(2, 0x0100); // flags: RD=1
  view.setUint16(4, 1);  // QDCOUNT = 1
  view.setUint16(6, 0);  // ANCOUNT = 0
  view.setUint16(8, 0);  // NSCOUNT = 0
  view.setUint16(10, 1); // ARCOUNT = 1 (the OPT RR)
  let off = 12;
  for (const l of labels) {
    buf[off++] = l.length;
    for (let i = 0; i < l.length; i++) buf[off++] = l.charCodeAt(i);
  }
  buf[off++] = 0; // root label
  view.setUint16(off, 65); off += 2; // QTYPE=HTTPS
  view.setUint16(off, 1); off += 2; // QCLASS=IN

  // OPT pseudo-RR (RFC 6891).
  buf[off++] = 0; // root name
  view.setUint16(off, 41); off += 2; // TYPE = OPT
  view.setUint16(off, 1232); off += 2; // CLASS = advertised UDP payload size (RFC 6891 §6.2.3 recommendation)
  view.setUint32(off, 0); off += 4; // TTL = extended-RCODE(1)+version(1)+flags(2); all zero
  view.setUint16(off, padOptHeader + padLen); off += 2; // RDLEN = options length
  // Padding option (RFC 8467): OPTION-CODE=12, OPTION-LENGTH, then padding.
  view.setUint16(off, 12); off += 2; // OPTION-CODE = Padding
  view.setUint16(off, padLen); off += 2; // OPTION-LENGTH
  for (let i = 0; i < padLen; i++) buf[off + i] = 0; // zero padding
  return buf;
}

// RFC 4648 §5 base64url without padding — required by RFC 8484.
function base64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Skip a DNS name (labels or a 2-byte pointer) starting at `off`.
// Returns the offset immediately after the name. Does NOT follow pointers —
// we only need to advance past names, not resolve them.
function skipDnsName(msg, off) {
  while (off < msg.length) {
    const len = msg[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2; // pointer: fixed 2-byte hop
    off += 1 + len;
  }
  return off;
}

// Parse a DNS wire-format response and return the RDATA of every type-65
// (HTTPS) record in the Answer section as hex-formatted wire strings that
// ech.js already knows how to parse (the `\# len hex` presentation form).
function parseDnsResponse(buf) {
  const msg = new Uint8Array(buf);
  if (msg.length < 12) return [];
  const view = new DataView(buf);
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);
  let off = 12;
  for (let i = 0; i < qdcount && off < msg.length; i++) {
    off = skipDnsName(msg, off);
    off += 4; // QTYPE + QCLASS
  }
  const results = [];
  for (let i = 0; i < ancount && off + 10 <= msg.length; i++) {
    off = skipDnsName(msg, off);
    if (off + 10 > msg.length) break;
    const type = view.getUint16(off); off += 2;
    off += 6; // CLASS(2) + TTL(4)
    const rdlen = view.getUint16(off); off += 2;
    if (off + rdlen > msg.length) break;
    if (type === 65) {
      const rdata = msg.slice(off, off + rdlen);
      let hex = "";
      for (let j = 0; j < rdata.length; j++) hex += rdata[j].toString(16).padStart(2, "0");
      results.push(`\\# ${rdata.length} ${hex}`);
    }
    off += rdlen;
  }
  return results;
}

async function dohLookupHttpsRR(host, settings) {
  const url = new URL(resolverUrl(settings));
  url.searchParams.set("dns", base64url(buildDnsQuery(host)));

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const res = await fetch(url.toString(), {
      headers: { Accept: "application/dns-message" },
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      redirect: "error",
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
    const buf = await res.arrayBuffer();
    if (buf.byteLength > 65536) throw new Error("DoH response too large");
    return parseDnsResponse(buf);
  } finally {
    clearTimeout(timer);
  }
}

// OPTIONAL feature — disabled by default. Only runs if you explicitly
// enable "Confirm with Cloudflare" in Settings
// AND you grant the extra host permission it asks for at that time.
//
// What it does: fetches a single URL (https://<host>/cdn-cgi/trace) on
// the site you just visited. That endpoint is a well-known, documented
// Cloudflare feature that simply reports metadata about the connection
// you just made — including whether your browser used ECH on the TLS
// handshake. The response is a few hundred bytes of key=value lines.
//
// What it does NOT do: it sends no cookies, no referrer, and refuses
// redirects. It reads only the `sni=` line from the response;
// everything else is discarded. It is never called for a host that is
// not the one you're currently visiting, so it does not generate any
// traffic you weren't already making to that site.
//
// Why it exists: a DNS lookup can only tell us whether a site *offers*
// ECH. It can't tell us whether your browser actually negotiated it.
// The trace endpoint closes that loop for Cloudflare-hosted sites.
//
// Anti-spoofing: any non-Cloudflare origin can serve a path called
// /cdn-cgi/trace and stuff `sni=encrypted` into the body to falsely
// claim ECH was used. To prevent that, we require the response to come
// from Cloudflare by checking for at least one of these headers:
//   * cf-ray (set on every Cloudflare response, format: <hex>-<airport>)
//   * server: cloudflare
// If neither is present, the response is discarded and treated as if
// the endpoint were unreachable. We also verify the response URL's host
// matches the host we requested, which protects against DNS-level
// redirection even though redirects are already refused.
//
// Returns { sni } or null if the endpoint is unreachable or unverified.
async function probeCloudflareTrace(host) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 3000);
  try {
    const url = new URL("/cdn-cgi/trace", `https://${host}`);
    const res = await fetch(url.toString(), {
      signal: ctrl.signal,
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      redirect: "error",
    });
    if (!res.ok) return null;
    // Anti-spoofing: refuse to trust the body unless Cloudflare's own
    // response headers confirm the request was actually served by
    // Cloudflare's edge. A non-Cloudflare origin could otherwise forge
    // an `sni=encrypted` line and falsely mark itself as ECH-confirmed.
    const cfRay = res.headers.get("cf-ray");
    const server = (res.headers.get("server") || "").toLowerCase();
    if (!cfRay && server !== "cloudflare") return null;
    // Defense in depth: even with redirects refused, verify the response
    // URL's host matches what we asked for (guards against any future
    // fetch behavior change or transparent proxy that rewrites hosts).
    try {
      if (new URL(res.url).hostname !== host) return null;
    } catch { return null; }
    // Cloudflare's real /cdn-cgi/trace response is a few hundred bytes.
    // Cap what we'll read so a misbehaving (or compromised) host can't
    // make us buffer an unbounded response into memory. We stream the
    // body and bail the moment we exceed the cap.
    const MAX_BYTES = 4096;
    const reader = res.body && res.body.getReader ? res.body.getReader() : null;
    let text;
    if (reader) {
      const chunks = [];
      let total = 0;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_BYTES) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        chunks.push(value);
      }
      const merged = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { merged.set(c, off); off += c.byteLength; }
      text = new TextDecoder().decode(merged);
    } else {
      text = await res.text();
      if (text.length > MAX_BYTES) return null;
    }
    const sniM = text.match(/^sni=(.*)$/m);
    return {
      sni: sniM ? sniM[1].trim() : null,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Maximum time the entire lookup pipeline may take. Individual network
// calls have their own shorter AbortController timeouts (5 s for DoH,
// 3 s for the trace probe), but this outer bound catches cases where
// the pipeline stalls before reaching the network — e.g. a hung
// IndexedDB read or an await that never resolves. If this fires, the
// caller gets a neutral "unknown" result rather than an indefinite
// "Checking…" badge.
const PIPELINE_TIMEOUT_MS = 15000;

// The main pipeline: takes a hostname, returns its ECH status.
//
// Flow:
//   1. Serve from in-memory cache if fresh (no network at all).
//   2. In-flight deduplication: if another lookup for this host is already
//      running, wait on it instead of firing a second DoH query.
//   3. History fast-path: if the host is in the in-memory ECH host Set,
//      skip DNS entirely and return STATUS.HISTORY immediately.
//   4. Otherwise, ONE DoH query to the resolver you chose.
//   5. Parse the DNS response locally (see ech.js).
//   6. Optionally, if you opted into the trace probe, make ONE extra
//      request to the visited site itself to confirm.
//   7. Cache the result in memory and, ONLY if you opted into history
//      AND the site actually supports ECH, hand the hostname off to the
//      encrypted history store and update the in-memory Set.
//
// Nothing in this function writes to disk except step 7, which is gated
// on an explicit opt-in you control from Settings. Non-ECH sites and
// inconclusive lookups are never recorded in history.
async function evaluateHost(host, { force = false } = {}) {
  // Step 1: in-memory result cache. Bypassed entirely when noCache mode
  // is enabled, so no result is ever retained between lookups — at the
  // cost of repeating the DoH query on every visit.
  const settings = await getSettings();
  if (!force && !settings.noCache) {
    const cached = cacheGet(host);
    if (cached) {
      const ttl = cached.error ? FAILURE_TTL_MS : SUCCESS_TTL_MS;
      if (Date.now() - cached.ts < ttl) return cached;
    }
  }

  // Step 2: in-flight deduplication. If a lookup is already running for
  // this host, return the same Promise so both callers share one result.
  // Force-mode bypasses this so "Re-check" always starts a fresh pipeline.
  if (!force && pending.has(host)) return pending.get(host);

  const promise = performLookupWithTimeout(host, force);
  if (!force) pending.set(host, promise);
  try {
    return await promise;
  } finally {
    // Only delete when we registered the entry. A force lookup never writes
    // to `pending`, so deleting unconditionally would evict a concurrent
    // normal lookup's entry and cause a duplicate DoH query for it.
    if (!force) pending.delete(host);
  }
}

// Wraps performLookup with an overall timeout so the badge never gets
// stuck on "Checking…" if something in the pipeline hangs.
async function performLookupWithTimeout(host, force) {
  let timer;
  const timeout = new Promise((_, reject) =>
    timer = setTimeout(() => reject(new Error("Lookup timed out")), PIPELINE_TIMEOUT_MS)
  );
  try {
    return await Promise.race([performLookup(host, force), timeout]);
  } catch (e) {
    return {
      host,
      status: STATUS.UNKNOWN,
      ts: Date.now(),
      rrRaw: [],
      summary: null,
      sni: null,
      error: String(e && e.message || e),
      resolver: "unknown",
    };
  } finally {
    clearTimeout(timer);
  }
}

// The actual lookup work, called exclusively by evaluateHost. Separated so
// evaluateHost can register the Promise in `pending` before awaiting it.
async function performLookup(host, force) {
  const settings = await getSettings();

  // History fast-path: O(1) in-memory Set check instead of decrypting the
  // full history blob on every navigation. Bypassed when force=true so
  // "Re-check" always issues a live DNS query. Also bypassed in noCache
  // mode — fast-path results are a form of cached state, so a user who
  // turned on noCache for maximum privacy almost certainly wants a live
  // query each time.
  if (!force && !settings.noCache && settings.historyFastPath && settings.keepHistory) {
    const set = await getEchHostSet();
    if (set.has(host)) {
      const histResult = {
        host,
        status: STATUS.HISTORY,
        ts: Date.now(),
        rrRaw: [],
        summary: null,
        sni: null,
        error: null,
        resolver: settings.resolver,
      };
      cacheSet(host, histResult);
      // Intentionally NOT re-recording here. Touching the LRU via
      // recordEchHost would force a full decrypt + re-encrypt + storage write
      // on every cache-miss navigation to a known host — exactly the cost this
      // fast-path exists to avoid. The trade-off: fast-path hits no longer
      // refresh history recency, so an entry only moves to the most-recent
      // slot when a live DoH lookup (cache expiry, Re-check, or first visit)
      // re-confirms it. Eviction only matters at the MAX_ENTRIES cap anyway.
      return histResult;
    }
  }

  const result = {
    host,
    status: STATUS.UNKNOWN,
    ts: Date.now(),
    rrRaw: [],
    summary: null,
    sni: null,
    error: null,
    resolver: settings.resolver,
  };

  try {
    result.rrRaw = await dohLookupHttpsRR(host, settings);
    let advertised = false;
    for (const data of result.rrRaw) {
      const rr = parseHttpsRr(data);
      if (!rr) continue;
      if (rr.echLength) advertised = true;
      if (!result.summary) result.summary = rr;
    }
    result.status = advertised ? STATUS.ADVERTISED : STATUS.NOT_ADVERTISED;
  } catch (e) {
    result.error = String(e && e.message || e);
    result.status = STATUS.UNKNOWN;
  }

  // The trace probe confirms whether ECH was actually negotiated,
  // via a single fetch to Cloudflare's /cdn-cgi/trace endpoint.
  if (settings.traceProbe && result.status !== STATUS.UNKNOWN) {
    const hasPerm = await chrome.permissions.contains({ origins: ["https://*/*"] }).catch(() => false);
    if (hasPerm) {
      const trace = await probeCloudflareTrace(host);
      if (trace && trace.sni) {
        result.sni = trace.sni;
        if (trace.sni === "encrypted") {
          result.status = STATUS.CONFIRMED;
        } else if (trace.sni === "plaintext" && result.status === STATUS.ADVERTISED) {
          // ECH key is in DNS but this connection didn't use it.
          result.status = STATUS.OFFERED;
        }
      }
    }
  }

  // Multi-resolver comparison: when enabled, fire the same lookup against
  // every built-in resolver in parallel and attach the per-resolver verdict
  // to the result. The popup renders discrepancies, which can indicate DNS
  // manipulation or split-horizon responses. This multiplies the number of
  // DoH queries per lookup by the number of built-in resolvers (4), so it
  // is opt-in and off by default.
  if (settings.compareResolvers && !force) {
    result.comparisons = await compareResolvers(host).catch(() => []);
  } else if (settings.compareResolvers && force) {
    // Re-check should still populate comparisons; force only bypasses cache.
    result.comparisons = await compareResolvers(host).catch(() => []);
  }

  // Status-change notification: compare this result against the last cached
  // status for the host and, if it changed, fire a notification. Gated on an
  // explicit opt-in to avoid surprising the user.
  if (settings.notifyOnChange) {
    maybeNotifyStatusChange(host, result.status, settings).catch(() => {});
  }

  // Cache the result unless noCache mode is on.
  if (!settings.noCache) cacheSet(host, result);

  if (
    settings.keepHistory &&
    (result.status === STATUS.ADVERTISED || result.status === STATUS.CONFIRMED || result.status === STATUS.OFFERED)
  ) {
    // Fire-and-forget; history failures must never break the main flow.
    // Only the hostname is handed off — no timestamps, no status.
    recordEchHost(host).catch(() => {});
    // Optimistically update the in-memory Set so the fast-path can serve
    // this host on the next navigation without touching IDB or crypto.
    // If the set hasn't been initialized yet, lazily populate it first so
    // this host is included.
    if (echHostSet) {
      echHostSet.add(host);
    } else {
      getEchHostSet().then(set => set.add(host)).catch(() => {});
    }
  }

  return result;
}

// Query every built-in resolver in parallel and report each one's verdict
// (true if it returned an HTTPS RR with an ECH param, false otherwise).
// Cloudflare/Quad9/Control D are always queried; NextDNS is only queried
// if the user has a configured profile ID, since without one the request
// would fail. The primary resolver's result is intentionally NOT reused
// here — we issue a fresh query for each resolver so timing and caching
// differences between providers don't contaminate the comparison.
async function compareResolvers(host) {
  const resolvers = ["cloudflare", "quad9", "controld"];
  const settings = await getSettings();
  if (settings.nextdnsId && /^[A-Za-z0-9]{1,32}$/.test(settings.nextdnsId)) {
    resolvers.push("nextdns");
  }
  const tasks = resolvers.map(async (name) => {
    const sub = { ...settings, resolver: name };
    try {
      const rrs = await dohLookupHttpsRR(host, sub);
      let advertised = false;
      for (const data of rrs) {
        const rr = parseHttpsRr(data);
        if (rr && rr.echLength) { advertised = true; break; }
      }
      return { resolver: name, status: advertised ? "advertised" : "not_advertised" };
    } catch (e) {
      return { resolver: name, status: "error", error: String(e && e.message || e) };
    }
  });
  return Promise.all(tasks);
}

// Fire a system notification when a site's ECH status changes between
// lookups. We track the last-seen status in chrome.storage.local under
// `lastStatus` so it survives service-worker restarts. Only status
// transitions between {advertised, confirmed, offered, not_advertised,
// unknown} are notified — a transient CHECKING state never fires a
// notification.
async function maybeNotifyStatusChange(host, newStatus, settings) {
  if (!host || !newStatus) return;
  // Only notify on the "interesting" transitions; CHECKING, SKIPPED, and
  // HISTORY (a fast-path replay of a prior result) are not changes.
  const NOTIFIABLE = new Set([STATUS.ADVERTISED, STATUS.CONFIRMED, STATUS.OFFERED, STATUS.NOT_ADVERTISED]);
  if (!NOTIFIABLE.has(newStatus)) return;
  const { lastStatus: stored = {} } = await chrome.storage.local.get({ lastStatus: {} });
  const prev = stored[host];
  if (prev === newStatus) return;
  stored[host] = newStatus;
  // Cap the map so it can't grow unbounded across many sites.
  const keys = Object.keys(stored);
  if (keys.length > 1000) {
    // Drop the oldest 200 entries (insertion order = first-seen order).
    for (let i = 0; i < 200 && i < keys.length; i++) delete stored[keys[i]];
  }
  await chrome.storage.local.set({ lastStatus: stored });
  if (!prev) return; // first time we saw this host — no transition to report.
  const messages = {
    [STATUS.ADVERTISED]: `${host} now supports ECH`,
    [STATUS.CONFIRMED]: `${host}: ECH confirmed active`,
    [STATUS.OFFERED]: `${host}: ECH offered but not negotiated`,
    [STATUS.NOT_ADVERTISED]: `${host} no longer supports ECH`,
  };
  const message = messages[newStatus];
  if (!message) return;
  try {
    await chrome.notifications.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: "WhereECH status changed",
      message,
      priority: 0,
    });
  } catch {
    // notifications permission may be missing or denied — fail silently.
  }
}

function badgeFor(status) {
  switch (status) {
    case STATUS.CONFIRMED:     return { text: "ECH", color: "#1a7f37" };
    case STATUS.ADVERTISED:    return { text: "ECH", color: "#2da44e" };
    case STATUS.HISTORY:       return { text: "ECH", color: "#2da44e" };
    case STATUS.OFFERED:       return { text: "ECH", color: "#d97706" }; // amber — offered but not negotiated
    case STATUS.NOT_ADVERTISED:return { text: "—",   color: "#6e7781" };
    case STATUS.CHECKING:      return { text: "",    color: "#0969da" }; // no badge while in flight
    case STATUS.SKIPPED:       return { text: "",    color: "#6e7781" };
    case STATUS.UNKNOWN:
    default:                   return { text: "?",   color: "#bf8700" };
  }
}

const BADGE_TITLE = {
  [STATUS.CONFIRMED]:     "ECH confirmed active",
  [STATUS.OFFERED]:       "ECH offered, not negotiated",
  [STATUS.ADVERTISED]:    "ECH supported",
  [STATUS.HISTORY]:       "ECH supported (from history)",
  [STATUS.NOT_ADVERTISED]:"No ECH support",
  [STATUS.CHECKING]:      "Checking ECH…",
  [STATUS.UNKNOWN]:       "ECH check failed",
  [STATUS.SKIPPED]:       "",
};

async function setBadge(tabId, status, host) {
  const { text, color } = badgeFor(status);
  const label = BADGE_TITLE[status] ?? "";
  const title = host && label ? `${host} — ${label}` : label || "whereECH";
  try {
    await chrome.action.setBadgeText({ tabId, text });
    if (text) await chrome.action.setBadgeBackgroundColor({ tabId, color });
    await chrome.action.setTitle({ tabId, title });
  } catch {}
}

// Called exactly once per top-frame navigation. This is where a page
// visit turns into (at most) one DoH query. If auto-lookup is off in
// Settings, we stop here without touching the network — the badge goes
// neutral and nothing happens until you explicitly click the popup.
//
// Subframes (iframes, ads, trackers embedded in a page) never reach
// this function; the caller below filters on frameId === 0.
async function handleNavigation(tabId, url) {
  if (shouldSkipUrl(url)) {
    tabHost.delete(tabId);
    await setBadge(tabId, STATUS.SKIPPED);
    return;
  }
  const settings = await getSettings();
  const host = new URL(url).hostname;
  tabHost.set(tabId, host);
  if (!settings.autoLookup) {
    // Privacy mode: leave the badge neutral until the user clicks the popup.
    await setBadge(tabId, STATUS.SKIPPED);
    return;
  }
  // Allowlist/blocklist only affect automatic lookups. A non-empty
  // allowlist makes WhereECH ignore every host not on it; the blocklist
  // always excludes its entries. Manual lookups (popup / Re-check) bypass
  // these filters because the user explicitly asked.
  if (!isAutoLookupAllowed(host, settings)) {
    await setBadge(tabId, STATUS.SKIPPED);
    return;
  }
  // STATUS.CHECKING shows no badge text (blank icon) while the lookup runs,
  // so the amber "?" only appears when a lookup actually fails — never as a
  // transient loading indicator.
  await setBadge(tabId, STATUS.CHECKING, host);
  const result = await evaluateHost(host);
  if (tabHost.get(tabId) === host) {
    await setBadge(tabId, result.status, host);
  }
}

// Invalidate the in-memory cache whenever a setting that affects results changes,
// so the popup never displays stale resolver/probe metadata.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  // Only drop the settings memo when an actual settings key changed, not on
  // every historyBlob write — which would re-read storage on every navigation
  // to a new ECH site when history is enabled.
  if (Object.keys(changes).some(k => k in DEFAULTS)) cachedSettings = null;
  if (changes.resolver || changes.customResolver || changes.nextdnsId || changes.traceProbe || changes.historyFastPath || changes.keepHistory || changes.noCache || changes.compareResolvers) {
    cache.clear();
  }
  // Allowlist/blocklist changes don't invalidate cached *results*, but they
  // do change which hosts are eligible for automatic lookup. No cache clear
  // needed: the filter is re-evaluated on the next navigation.
});

// We subscribe ONLY to top-frame navigations (frameId === 0). Iframes,
// background requests, subresource loads, prefetches, and service-worker
// fetches all pass by untouched. The extension only ever sees the URL of
// the main page you're looking at — not ad trackers embedded in it.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  handleNavigation(details.tabId, details.url).catch(() => {});
});

// Clean up per-tab state when a tab closes. Nothing persistent lives in
// tabHost, so this is just housekeeping for the in-memory Map.
chrome.tabs.onRemoved.addListener((tabId) => tabHost.delete(tabId));

// Keyboard shortcut handler: re-check the active tab when the user
// presses the configured shortcut (Ctrl+Shift+E / MacCtrl+Shift+E).
chrome.commands.onCommand.addListener((command) => {
  if (command !== "recheck") return;
  // Wrapped so a rejected chrome.* call (e.g. tabs.query) can't surface as an
  // unhandled promise rejection in the service worker.
  (async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url && !shouldSkipUrl(tab.url)) {
      const host = new URL(tab.url).hostname;
      const result = await evaluateHost(host, { force: true });
      if (tab.id != null) await setBadge(tab.id, result.status, host);
    }
  })().catch(() => {});
});

// Message handler for the popup and options pages. Chrome restricts
// chrome.runtime.onMessage to intra-extension senders by default (this
// extension does NOT declare externally_connectable), so no website and
// no other extension can invoke any of these actions. Every message
// name is handled explicitly — anything unrecognized returns an error.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Defense-in-depth: reject messages from any context other than this
  // extension itself. chrome.runtime.id is always the extension's own ID.
  if (!sender || sender.id !== chrome.runtime.id) {
    sendResponse({ ok: false, error: "unauthorized" });
    return false;
  }
  (async () => {
    try {
      if (msg && msg.type === "getForTab") {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url || shouldSkipUrl(tab.url)) {
          sendResponse({ ok: true, skipped: true, url: tab && tab.url });
          return;
        }
        const host = new URL(tab.url).hostname;
        const result = await evaluateHost(host, { force: !!msg.force });
        if (tab.id != null) await setBadge(tab.id, result.status, host);
        sendResponse({ ok: true, result });
        return;
      }
      if (msg && msg.type === "clearCache") {
        cache.clear();
        sendResponse({ ok: true });
        return;
      }
      if (msg && msg.type === "listHistory") {
        const entries = await listEchHosts();
        sendResponse({ ok: true, entries });
        return;
      }
      if (msg && msg.type === "removeHistory") {
        if (typeof msg.host !== "string" || !msg.host) {
          sendResponse({ ok: false, error: "invalid host" });
          return;
        }
        await removeEchHost(msg.host);
        if (echHostSet) echHostSet.delete(msg.host);
        // Drop any cached result for this host so a stale STATUS.HISTORY badge
        // doesn't keep showing "ECH supported" for up to SUCCESS_TTL_MS after
        // the entry was removed from history.
        cache.delete(msg.host);
        sendResponse({ ok: true });
        return;
      }
      if (msg && msg.type === "clearHistory") {
        await clearEchHistory();
        echHostSet = null;
        echHostSetLoading = null;
        // Purge cached STATUS.HISTORY results so no host keeps showing a stale
        // "ECH supported" badge after the whole list is wiped.
        cache.clear();
        sendResponse({ ok: true });
        return;
      }
      if (msg && msg.type === "addAllowlist") {
        if (typeof msg.host !== "string" || !msg.host) {
          sendResponse({ ok: false, error: "invalid host" });
          return;
        }
        const s = await getSettings();
        const list = Array.isArray(s.allowlist) ? s.allowlist.slice() : [];
        if (!list.some(h => h.toLowerCase() === msg.host.toLowerCase())) list.push(msg.host);
        await chrome.storage.local.set({ allowlist: list });
        sendResponse({ ok: true, allowlist: list });
        return;
      }
      if (msg && msg.type === "removeAllowlist") {
        const s = await getSettings();
        const list = (Array.isArray(s.allowlist) ? s.allowlist : [])
          .filter(h => typeof h === "string" && h.toLowerCase() !== String(msg.host || "").toLowerCase());
        await chrome.storage.local.set({ allowlist: list });
        sendResponse({ ok: true, allowlist: list });
        return;
      }
      if (msg && msg.type === "addBlocklist") {
        if (typeof msg.host !== "string" || !msg.host) {
          sendResponse({ ok: false, error: "invalid host" });
          return;
        }
        const s = await getSettings();
        const list = Array.isArray(s.blocklist) ? s.blocklist.slice() : [];
        if (!list.some(h => h.toLowerCase() === msg.host.toLowerCase())) list.push(msg.host);
        await chrome.storage.local.set({ blocklist: list });
        sendResponse({ ok: true, blocklist: list });
        return;
      }
      if (msg && msg.type === "removeBlocklist") {
        const s = await getSettings();
        const list = (Array.isArray(s.blocklist) ? s.blocklist : [])
          .filter(h => typeof h === "string" && h.toLowerCase() !== String(msg.host || "").toLowerCase());
        await chrome.storage.local.set({ blocklist: list });
        sendResponse({ ok: true, blocklist: list });
        return;
      }
      if (msg && msg.type === "exportHistory") {
        // Return the encrypted blob verbatim so the options page can offer
        // it as a download. The key is NOT exported — restoring requires the
        // same browser profile (where the IndexedDB key still lives) or a
        // fresh decrypt is impossible. This is intentional: exporting the
        // key would weaken the encryption-at-rest guarantee.
        const blob = await getHistoryBlob();
        sendResponse({ ok: true, blob });
        return;
      }
      if (msg && msg.type === "importHistory") {
        // Replace the current blob with the imported one. Validates shape
        // and attempts a decrypt before committing, so a corrupt or
        // wrong-key blob is rejected and the existing history is preserved.
        try {
          await importHistoryBlob(msg.blob);
        } catch (e) {
          sendResponse({ ok: false, error: String(e && e.message || e) });
          return;
        }
        echHostSet = null;
        echHostSetLoading = null;
        cache.clear();
        sendResponse({ ok: true });
        return;
      }
      if (msg && msg.type === "exportSettings") {
        const s = await getSettings();
        // Strip sensitive-ish fields we don't want to round-trip. None of
        // these are secrets, but exporting the encrypted history blob is a
        // separate, intentional action (exportHistory), and lastStatus is
        // machine state rather than a preference.
        const { historyBlob, lastStatus, ...prefs } = s;
        const full = await chrome.storage.local.get(null);
        sendResponse({ ok: true, settings: prefs, allKeys: Object.keys(full) });
        return;
      }
      if (msg && msg.type === "importSettings") {
        if (!msg.settings || typeof msg.settings !== "object") {
          sendResponse({ ok: false, error: "invalid settings" });
          return;
        }
        // Only accept keys that are in DEFAULTS to prevent an import file
        // from injecting arbitrary storage keys.
        const clean = {};
        for (const k of Object.keys(DEFAULTS)) {
          if (k in msg.settings) clean[k] = msg.settings[k];
        }
        await chrome.storage.local.set(clean);
        cache.clear();
        sendResponse({ ok: true });
        return;
      }
      if (msg && msg.type === "getChangelog") {
        try {
          const resp = await fetch(chrome.runtime.getURL("CHANGELOG.md"), { cache: "no-store" });
          if (!resp.ok) throw new Error("no changelog");
          const text = await resp.text();
          sendResponse({ ok: true, text });
        } catch (e) {
          sendResponse({ ok: false, error: String(e && e.message || e) });
        }
        return;
      }
      sendResponse({ ok: false, error: "unknown message" });
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message || e) });
    }
  })();
  return true;
});
