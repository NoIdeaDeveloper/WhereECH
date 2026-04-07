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
  NOT_ADVERTISED: "not_advertised",
  UNKNOWN: "unknown",
  SKIPPED: "skipped",
};

// The only DNS-over-HTTPS endpoints this extension can contact without
// additional user consent. These four URLs are mirrored in manifest.json
// under "host_permissions" — the browser itself blocks requests to any
// other host unless the user explicitly grants extra permissions.
const DOH_PROVIDERS = {
  cloudflare: "https://cloudflare-dns.com/dns-query",
  quad9: "https://dns.quad9.net:5053/dns-query",
  controld: "https://freedns.controld.com/p0",
};

const DEFAULTS = {
  resolver: "cloudflare",
  customResolver: "",
  nextdnsId: "",
  autoLookup: true,
  traceProbe: false,
  keepHistory: false,
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

// Lets us correlate an async lookup that finishes late with the tab it
// started in, so we don't paint a stale badge on a tab that has since
// navigated elsewhere. In-memory only, wiped with the worker.
const tabHost = new Map(); // tabId -> host

// Reads Settings from chrome.storage.local. This is the ONLY source of
// persistent configuration the extension uses; it never syncs anywhere,
// never leaves the device, and is scoped to this extension's own storage
// area — other extensions and websites cannot read it.
async function getSettings() {
  return chrome.storage.local.get(DEFAULTS); // get() with defaults already merges
}

// Detects raw IP literals so we don't do a useless DNS lookup on them.
// ECH is a property of a name, so there's nothing to look up for an IP.
function isIpLiteral(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
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

// Performs exactly one DNS-over-HTTPS query for a single hostname.
//
// What it sends:
//   A single GET request with two query parameters: name=<the hostname>
//   and type=HTTPS. That's it. The hostname is the only piece of user-
//   derived data that leaves the device on this call, and it goes to
//   exactly one host — whichever DoH provider you picked in Settings.
//
// What it does NOT send:
//   * No cookies (credentials: "omit")
//   * No Referer header (referrerPolicy: "no-referrer")
//   * No User-Agent extras, no custom fingerprinting headers
//   * No request body
//   * No follow-up requests: redirects are refused (redirect: "error"),
//     so a malicious or compromised resolver cannot bounce us to a
//     tracking URL on another domain.
//
// Failure-mode guarantees:
//   * A 5-second AbortController timeout prevents hung requests from
//     leaking resources.
//   * HTTP errors throw and are converted upstream into a neutral
//     "unknown" status — no data is logged, nothing is retried.
async function dohLookupHttpsRR(host, settings) {
  // Build URL safely so a custom resolver with an existing query string still works.
  const url = new URL(resolverUrl(settings));
  url.searchParams.set("name", host);
  url.searchParams.set("type", "HTTPS");

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const res = await fetch(url.toString(), {
      headers: { Accept: "application/dns-json" },
      credentials: "omit",
      cache: "force-cache",
      referrerPolicy: "no-referrer",
      redirect: "error", // refuse 3xx — a malicious resolver can't bounce us to a tracker
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
    const json = await res.json();
    const answers = (json.Answer || []).filter(a => a.type === 65);
    return answers.map(a => a.data);
  } finally {
    clearTimeout(timer);
  }
}

// OPTIONAL feature — disabled by default. Only runs if you explicitly
// enable "Confirm with Cloudflare" in Settings AND you grant the extra
// host permission it asks for at that time.
//
// What it does: fetches a single URL (https://<host>/cdn-cgi/trace) on
// the site you just visited. That endpoint is a well-known, documented
// Cloudflare feature that simply reports metadata about the connection
// you just made — including whether your browser used ECH on the TLS
// handshake. The response is a few hundred bytes of key=value lines.
//
// What it does NOT do: it sends no cookies, no referrer, and refuses
// redirects. It reads ONLY the `sni=` line from the response; everything
// else is discarded. It is never called for a host that is not the one
// you're currently visiting, so it does not generate any traffic you
// weren't already making to that site.
//
// Why it exists: a DNS lookup can only tell us whether a site *offers*
// ECH. It can't tell us whether your browser actually negotiated it.
// The trace endpoint closes that loop for Cloudflare-hosted sites.
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
    const m = text.match(/^sni=(.*)$/m);
    return m ? m[1].trim() : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// The main pipeline: takes a hostname, returns its ECH status.
//
// Flow:
//   1. Serve from in-memory cache if fresh (no network at all).
//   2. Otherwise, ONE DoH query to the resolver you chose.
//   3. Parse the DNS response locally (see ech.js).
//   4. Optionally, if you opted into the trace probe, make ONE extra
//      request to the visited site itself to confirm.
//   5. Cache the result in memory and, ONLY if you opted into history
//      AND the site actually supports ECH, hand the hostname off to the
//      encrypted history store.
//
// Nothing in this function writes to disk except step 5, which is gated
// on an explicit opt-in you control from Settings. Non-ECH sites and
// inconclusive lookups are never recorded in history.
async function evaluateHost(host, { force = false } = {}) {
  const cached = cacheGet(host);
  if (!force && cached) {
    const ttl = cached.error ? FAILURE_TTL_MS : SUCCESS_TTL_MS;
    if (Date.now() - cached.ts < ttl) return cached;
  }

  const settings = await getSettings();
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

  if (settings.traceProbe && result.status !== STATUS.UNKNOWN) {
    const hasPerm = await chrome.permissions.contains({ origins: ["https://*/*"] }).catch(() => false);
    if (hasPerm) {
      const sni = await probeCloudflareTrace(host);
      if (sni) {
        result.sni = sni;
        if (sni === "encrypted") result.status = STATUS.CONFIRMED;
      }
    }
  }

  cacheSet(host, result);

  if (
    settings.keepHistory &&
    (result.status === STATUS.ADVERTISED || result.status === STATUS.CONFIRMED)
  ) {
    // Fire-and-forget; history failures must never break the main flow.
    // Only the hostname is handed off — no timestamps, no status.
    recordEchHost(host).catch(() => {});
  }

  return result;
}

function badgeFor(status) {
  switch (status) {
    case STATUS.CONFIRMED: return { text: "ECH", color: "#1a7f37" };
    case STATUS.ADVERTISED: return { text: "ECH", color: "#2da44e" };
    case STATUS.NOT_ADVERTISED: return { text: "—", color: "#6e7781" };
    case STATUS.SKIPPED: return { text: "", color: "#6e7781" };
    case STATUS.UNKNOWN:
    default: return { text: "?", color: "#bf8700" };
  }
}

async function setBadge(tabId, status) {
  const { text, color } = badgeFor(status);
  try {
    await chrome.action.setBadgeText({ tabId, text });
    if (text) await chrome.action.setBadgeBackgroundColor({ tabId, color });
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
  await setBadge(tabId, STATUS.UNKNOWN);
  const result = await evaluateHost(host);
  if (tabHost.get(tabId) === host) {
    await setBadge(tabId, result.status);
  }
}

// Invalidate the in-memory cache whenever a setting that affects results changes,
// so the popup never displays stale resolver/probe metadata.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.resolver || changes.customResolver || changes.nextdnsId || changes.traceProbe) {
    cache.clear();
  }
});

// We subscribe ONLY to top-frame navigations (frameId === 0). Iframes,
// background requests, subresource loads, prefetches, and service-worker
// fetches all pass by untouched. The extension only ever sees the URL of
// the main page you're looking at — not ad trackers embedded in it.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  handleNavigation(details.tabId, details.url);
});

// Clean up per-tab state when a tab closes. Nothing persistent lives in
// tabHost, so this is just housekeeping for the in-memory Map.
chrome.tabs.onRemoved.addListener((tabId) => tabHost.delete(tabId));

// Message handler for the popup and options pages. Chrome restricts
// chrome.runtime.onMessage to intra-extension senders by default (this
// extension does NOT declare externally_connectable), so no website and
// no other extension can invoke any of these actions. Every message
// name is handled explicitly — anything unrecognized returns an error.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
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
        if (tab.id != null) await setBadge(tab.id, result.status);
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
        await removeEchHost(msg.host);
        sendResponse({ ok: true });
        return;
      }
      if (msg && msg.type === "clearHistory") {
        await clearEchHistory();
        sendResponse({ ok: true });
        return;
      }
      sendResponse({ ok: false, error: "unknown message" });
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message || e) });
    }
  })();
  return true;
});
