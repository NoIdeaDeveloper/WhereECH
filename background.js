// WhereECH service worker
// Privacy-respecting Encrypted Client Hello detector.

import { parseHttpsRr } from "./ech.js";
import {
  recordEchHost,
  listEchHosts,
  removeEchHost,
  clearEchHistory,
} from "./history.js";

const SUCCESS_TTL_MS = 10 * 60 * 1000;
const FAILURE_TTL_MS = 30 * 1000;

const STATUS = {
  ADVERTISED: "advertised",
  CONFIRMED: "confirmed",
  NOT_ADVERTISED: "not_advertised",
  UNKNOWN: "unknown",
  SKIPPED: "skipped",
};

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

const cache = new Map(); // host -> result
const tabHost = new Map(); // tabId -> host

async function getSettings() {
  return chrome.storage.local.get(DEFAULTS); // get() with defaults already merges
}

function isIpLiteral(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

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

function resolverUrl(settings) {
  if (settings.resolver === "custom" && settings.customResolver) {
    return settings.customResolver;
  }
  if (settings.resolver === "nextdns") {
    const id = (settings.nextdnsId || "").trim();
    if (!id) throw new Error("NextDNS profile ID is not set — open Settings.");
    if (!/^[A-Za-z0-9]{1,32}$/.test(id)) {
      throw new Error("NextDNS profile ID is invalid.");
    }
    return `https://dns.nextdns.io/${id}`;
  }
  return DOH_PROVIDERS[settings.resolver] || DOH_PROVIDERS.cloudflare;
}

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
    const text = await res.text();
    const m = text.match(/^sni=(.*)$/m);
    return m ? m[1].trim() : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function evaluateHost(host, { force = false } = {}) {
  const cached = cache.get(host);
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

  cache.set(host, result);

  if (
    settings.keepHistory &&
    (result.status === STATUS.ADVERTISED || result.status === STATUS.CONFIRMED)
  ) {
    // Fire-and-forget; history failures must never break the main flow.
    recordEchHost(host, result.status).catch(() => {});
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

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  handleNavigation(details.tabId, details.url);
});

chrome.tabs.onRemoved.addListener((tabId) => tabHost.delete(tabId));

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
