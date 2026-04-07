// WhereECH — Settings page controller.
//
// What this file does:
//   * Renders the Settings UI.
//   * Reads your current preferences from chrome.storage.local and
//     writes them back when you change one.
//   * When you enable the Cloudflare trace probe or set a custom DoH
//     resolver, it asks the browser for the extra host permission that
//     feature needs, via the browser's own permission prompt. You can
//     always say no.
//   * Sends messages to the background service worker to list, remove,
//     or clear the encrypted history.
//
// What this file does NOT do:
//   * No network I/O whatsoever. It never calls fetch().
//   * No access to the encryption key. The key lives in the service
//     worker's IndexedDB; this page can only ask the worker for the
//     decrypted list via chrome.runtime.sendMessage, which Chrome
//     restricts to intra-extension senders.
//   * No dynamic HTML. Every value rendered on this page is written
//     with .textContent, which does not interpret HTML. There is no
//     innerHTML, no eval, no script-src beyond 'self' (see manifest).
//   * No telemetry, no analytics, no external fonts, no remote images.
//     The page loads only the local CSS file listed in options.html.

const DEFAULTS = {
  resolver: "cloudflare",
  customResolver: "",
  nextdnsId: "",
  autoLookup: true,
  traceProbe: false,
  keepHistory: false,
};

const TRACE_ORIGINS = { origins: ["https://*/*"] };

function $(id) { return document.getElementById(id); }

async function load() {
  const s = await chrome.storage.local.get(DEFAULTS);
  for (const r of document.querySelectorAll('input[name="resolver"]')) {
    r.checked = r.value === s.resolver;
  }
  $("customResolver").value = s.customResolver;
  $("customResolver").disabled = s.resolver !== "custom";
  $("nextdnsId").value = s.nextdnsId;
  $("nextdnsId").disabled = s.resolver !== "nextdns";
  $("autoLookup").checked = !!s.autoLookup;
  $("traceProbe").checked = !!s.traceProbe;
  $("keepHistory").checked = !!s.keepHistory;
  await updatePermStatus();
  await refreshHistory();
}

function sendMessage(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
      } else {
        resolve(resp || { ok: false, error: "no response" });
      }
    });
  });
}

// Asks the service worker for the current decrypted history list and
// renders it. Every value below is written with .textContent, so even
// if a hostname somehow contained HTML-like characters (it can't —
// URL.hostname is already normalized upstream), there is no way for
// this function to introduce a script-injection vector.
async function refreshHistory() {
  const list = $("historyList");
  const empty = $("historyEmpty");
  list.textContent = "";
  const resp = await sendMessage({ type: "listHistory" });
  if (!resp.ok) {
    empty.textContent = "Couldn't load history: " + (resp.error || "unknown error");
    empty.classList.remove("hidden");
    return;
  }
  const entries = resp.entries || [];
  if (entries.length === 0) {
    empty.textContent = "No entries yet.";
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  for (const e of entries) {
    const li = document.createElement("li");
    li.className = "history-item";

    // Each entry is rendered as a plain hyperlink to the site's HTTPS
    // root. The href is set via the DOM URL API, not string concat, so
    // the hostname cannot introduce a different scheme or inject
    // anything into the link target. Link text uses .textContent, so
    // no HTML interpretation is possible regardless of hostname.
    const link = document.createElement("a");
    try {
      link.href = new URL(`https://${e.host}/`).toString();
    } catch {
      link.href = "#";
    }
    link.textContent = e.host;
    link.title = e.host;
    link.className = "history-host";
    link.target = "_blank";
    link.rel = "noopener noreferrer";

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ghost-small";
    btn.textContent = "Remove";
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const r = await sendMessage({ type: "removeHistory", host: e.host });
      if (r.ok) {
        await refreshHistory();
      } else {
        btn.disabled = false;
        toast("Couldn't remove entry");
      }
    });

    li.appendChild(link);
    li.appendChild(btn);
    list.appendChild(li);
  }
}

// Ensure host permission is in place for whatever custom resolver URL is
// currently saved. Called when switching to the custom radio so an upgraded
// install whose saved URL predates this check gets prompted, not silently
// broken. No-op if no URL is saved or permission is already granted.
async function ensureCustomResolverPermission() {
  const v = ($("customResolver").value || "").trim();
  if (!v) return;
  let parsed;
  try { parsed = new URL(v); } catch { return; }
  if (parsed.protocol !== "https:") return;
  const origin = `${parsed.protocol}//${parsed.host}/*`;
  // request() is idempotent: it returns true immediately without prompting
  // if the permission is already held. We avoid an intermediate `contains`
  // await that could burn the user-gesture needed to show the prompt.
  const granted = await chrome.permissions.request({ origins: [origin] }).catch(() => false);
  if (!granted) {
    toast("Permission denied — lookups to that host will fail");
  }
}

async function updatePermStatus() {
  const has = await chrome.permissions.contains(TRACE_ORIGINS).catch(() => false);
  const el = $("permStatus");
  if ($("traceProbe").checked && !has) {
    el.textContent = "Permission not yet granted — toggling on will prompt.";
  } else if (has) {
    el.textContent = "Host permission granted.";
  } else {
    el.textContent = "";
  }
}

function toast(msg) {
  const el = $("saved");
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 1200);
}

async function save(partial) {
  await chrome.storage.local.set(partial);
  toast("Saved");
}

document.addEventListener("DOMContentLoaded", () => {
  load();

  for (const r of document.querySelectorAll('input[name="resolver"]')) {
    r.addEventListener("change", async () => {
      const value = r.value;
      $("customResolver").disabled = value !== "custom";
      $("nextdnsId").disabled = value !== "nextdns";
      if (value === "custom") {
        await ensureCustomResolverPermission();
      }
      await save({ resolver: value });
    });
  }
  $("customResolver").addEventListener("change", async (e) => {
    const v = e.target.value.trim();
    if (!v) {
      await save({ customResolver: "" });
      return;
    }
    let parsed;
    try { parsed = new URL(v); } catch {
      toast("Resolver URL is invalid");
      return;
    }
    if (parsed.protocol !== "https:") {
      toast("Resolver must be HTTPS");
      return;
    }
    // MV3 requires host permission for cross-origin fetch from the service
    // worker. Without this, lookups against a custom resolver would silently
    // fail. optional_host_permissions: ["https://*/*"] lets us request any
    // https origin as a subset.
    const origin = `${parsed.protocol}//${parsed.host}/*`;
    const granted = await chrome.permissions.request({ origins: [origin] }).catch(() => false);
    if (!granted) {
      toast("Permission for that host was denied");
      e.target.value = "";
      await save({ customResolver: "" });
      return;
    }
    await save({ customResolver: v });
  });
  $("nextdnsId").addEventListener("change", async (e) => {
    const v = e.target.value.trim();
    if (v && !/^[A-Za-z0-9]{1,32}$/.test(v)) {
      toast("Profile ID should be 1–32 letters and digits");
      return;
    }
    await save({ nextdnsId: v });
  });
  $("autoLookup").addEventListener("change", async (e) => {
    await save({ autoLookup: e.target.checked });
  });
  $("traceProbe").addEventListener("change", async (e) => {
    if (e.target.checked) {
      const granted = await chrome.permissions.request(TRACE_ORIGINS).catch(() => false);
      if (!granted) {
        e.target.checked = false;
        toast("Permission denied");
        return;
      }
    } else {
      await chrome.permissions.remove(TRACE_ORIGINS).catch(() => {});
    }
    await save({ traceProbe: e.target.checked });
    await updatePermStatus();
  });
  $("keepHistory").addEventListener("change", async (e) => {
    await save({ keepHistory: e.target.checked });
  });
  $("refreshHistory").addEventListener("click", () => { refreshHistory(); });
  $("clearHistory").addEventListener("click", async () => {
    if (!confirm("Clear the entire ECH site history? This cannot be undone.")) return;
    const r = await sendMessage({ type: "clearHistory" });
    if (r.ok) {
      toast("History cleared");
      await refreshHistory();
    } else {
      toast("Couldn't clear history");
    }
  });
  $("clearCache").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "clearCache" }, () => {
      if (chrome.runtime.lastError) toast("Error clearing cache");
      else toast("Cache cleared");
    });
  });
});
