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
//     or clear the encrypted history, manage per-site lists, and import
//     or export settings and history.
//
// What this file does NOT do:
//   * No network I/O whatsoever. It never calls fetch(). (The only
//     fetch is the background worker fetching CHANGELOG.md for the
//     "What's new" link — that runs in the service worker, not here.)
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
  customPresets: [],
  nextdnsId: "",
  autoLookup: true,
  traceProbe: false,

  keepHistory: false,
  historyFastPath: false,
  noCache: false,
  notifyOnChange: false,
  compareResolvers: false,
  allowlist: [],
  blocklist: [],
  theme: "system",
};

const TRACE_ORIGINS = { origins: ["https://*/*"] };

function $(id) { return document.getElementById(id); }

let historyEntries = [];      // last loaded history, newest-first
let historySortAZ = false;    // false = newest-first (insertion order)
let historySearchTerm = "";

async function load() {
  const s = await chrome.storage.local.get(DEFAULTS);
  for (const r of document.querySelectorAll('input[name="resolver"]')) {
    r.checked = r.value === s.resolver;
  }
  for (const r of document.querySelectorAll('input[name="theme"]')) {
    r.checked = r.value === s.theme;
  }
  $("customResolver").value = s.customResolver;
  $("customResolver").disabled = s.resolver !== "custom";
  $("nextdnsId").value = s.nextdnsId;
  $("nextdnsId").disabled = s.resolver !== "nextdns";
  $("autoLookup").checked = !!s.autoLookup;
  $("noCache").checked = !!s.noCache;
  $("traceProbe").checked = !!s.traceProbe;
  $("compareResolvers").checked = !!s.compareResolvers;
  $("notifyOnChange").checked = !!s.notifyOnChange;

  $("keepHistory").checked = !!s.keepHistory;
  $("historyFastPath").checked = !!s.historyFastPath;
  updateHistoryFastPathVisibility(!!s.keepHistory, !!s.historyFastPath);
  refreshPresets(s.customPresets || []);
  await renderLists(s);
  await updatePermStatus();
  await refreshHistory();
  applyTheme(s.theme || "system");
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
  const setButtons = (disabled) => {
    const ids = ["refreshHistory", "clearHistory", "removeSelected", "exportHistory", "importHistory", "selectAllHistory", "historySearch", "sortHistory"];
    for (const id of ids) $(id).disabled = disabled;
  };
  setButtons(true);
  try {
    const resp = await sendMessage({ type: "listHistory" });
    if (!resp.ok) {
      empty.textContent = "Couldn't load history: " + (resp.error || "unknown error");
      empty.classList.remove("hidden");
      historyEntries = [];
    } else {
      historyEntries = resp.entries || [];
    }
  } catch (e) {
    empty.textContent = "Couldn't load history: " + String(e && e.message || e);
    empty.classList.remove("hidden");
    historyEntries = [];
  }
  renderHistory();
  setButtons(false);
  // Disable Remove Selected unless something is checked.
  updateRemoveSelectedState();
}

// Render the current historyEntries filtered by the search term and
// sorted by the current order. Updates the entry count and the empty
// state.
function renderHistory() {
  const list = $("historyList");
  const empty = $("historyEmpty");
  const countEl = $("historyCount");
  list.textContent = "";
  const total = historyEntries.length;
  countEl.textContent = total === 1 ? "1 entry" : `${total} entries`;

  let entries = historyEntries;
  if (historySearchTerm) {
    const q = historySearchTerm.toLowerCase();
    entries = entries.filter((e) => e.host.toLowerCase().includes(q));
  }
  const shown = entries.slice();
  if (historySortAZ) shown.sort((a, b) => a.host.localeCompare(b.host));

  if (shown.length === 0) {
    empty.classList.remove("hidden");
    empty.textContent = historySearchTerm
      ? "No entries match your filter."
      : total === 0
        ? "No entries yet. Enable history above to start tracking sites that support ECH."
        : "No entries.";
    return;
  }
  empty.classList.add("hidden");

  const fragment = document.createDocumentFragment();
  for (const e of shown) {
    const li = document.createElement("li");
    li.className = "history-item";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "history-check";
    checkbox.dataset.host = e.host;
    checkbox.addEventListener("change", updateRemoveSelectedState);

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

    li.appendChild(checkbox);
    li.appendChild(link);
    li.appendChild(btn);
    fragment.appendChild(li);
  }
  list.appendChild(fragment);
}

function updateRemoveSelectedState() {
  const anyChecked = document.querySelectorAll(".history-check:checked").length > 0;
  $("removeSelected").disabled = !anyChecked;
  const allCount = document.querySelectorAll(".history-check").length;
  const checkedCount = document.querySelectorAll(".history-check:checked").length;
  const selectAll = $("selectAllHistory");
  if (checkedCount === 0) selectAll.checked = false;
  else if (checkedCount === allCount) selectAll.checked = true;
}

// Render the per-site allowlist and blocklist.
async function renderLists(s) {
  for (const [name, key] of [["allowlist", "allowlist"], ["blocklist", "blocklist"]]) {
    const ul = $(`${name}View`);
    ul.textContent = "";
    const list = Array.isArray(s[key]) ? s[key] : [];
    for (const host of list) {
      const li = document.createElement("li");
      li.className = "host-list-item";
      const span = document.createElement("span");
      span.className = "host-list-host";
      span.textContent = host;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "ghost-small";
      btn.textContent = "Remove";
      btn.addEventListener("click", async () => {
        const resp = await sendMessage({ type: `remove${cap(name)}`, host });
        if (resp.ok) {
          const stored = await chrome.storage.local.get(DEFAULTS);
          await renderLists(stored);
        } else {
          toast("Couldn't remove entry");
        }
      });
      li.appendChild(span);
      li.appendChild(btn);
      ul.appendChild(li);
    }
  }
}

function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

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
  const granted = await chrome.permissions.request({ origins: [origin] }).catch(() => false);
  if (!granted) {
    toast("Permission denied — lookups to that host will fail");
  }
}

async function updatePermStatus() {
  const has = await chrome.permissions.contains(TRACE_ORIGINS).catch(() => false);
  const traceEl = $("permStatus");
  if ($("traceProbe").checked && !has) {
    traceEl.textContent = "Permission not yet granted — toggling on will prompt.";
  } else if (has) {
    traceEl.textContent = "Host permission granted.";
  } else {
    traceEl.textContent = "";
  }
}

function updateHistoryFastPathVisibility(keepHistoryOn, currentFastPath) {
  const row = $("historyFastPathRow");
  if (keepHistoryOn) {
    row.classList.remove("hidden");
  } else {
    row.classList.add("hidden");
    $("historyFastPath").checked = false;
    if (currentFastPath) {
      chrome.storage.local.set({ historyFastPath: false });
      toast("History fast-path disabled");
    }
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

// Show inline error text under the custom resolver input. Pass null/empty
// to clear the error.
function setCustomResolverError(msg) {
  const el = $("customResolverError");
  if (!msg) {
    el.classList.add("hidden");
    el.textContent = "";
    $("customResolver").classList.remove("invalid");
    return;
  }
  el.classList.remove("hidden");
  el.textContent = msg;
  $("customResolver").classList.add("invalid");
}

// Refresh the preset <select> from settings.
function refreshPresets(presets) {
  const sel = $("presetSelect");
  const cur = sel.value;
  sel.textContent = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "— choose —";
  sel.appendChild(placeholder);
  for (const p of presets) {
    const opt = document.createElement("option");
    opt.value = p.url;
    opt.textContent = p.name || p.url;
    sel.appendChild(opt);
  }
  sel.value = cur;
}

function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "dark") root.setAttribute("data-theme", "dark");
  else if (theme === "light") root.setAttribute("data-theme", "light");
  else root.removeAttribute("data-theme");
}

// Trigger a download of a JSON object as a file.
function downloadJson(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Read a File as parsed JSON.
function readJsonFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => {
      try { resolve(JSON.parse(reader.result)); }
      catch (e) { reject(e); }
    };
    reader.readAsText(file);
  });
}

function openChangelogModal(text) {
  const existing = document.getElementById("changelog-modal");
  if (existing) existing.remove();
  const overlay = document.createElement("div");
  overlay.id = "changelog-modal";
  overlay.className = "modal-overlay";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-label", "What's new");
  const dialog = document.createElement("div");
  dialog.className = "modal-dialog";
  const header = document.createElement("div");
  header.className = "modal-header";
  const title = document.createElement("strong");
  title.textContent = "What's new";
  const close = document.createElement("button");
  close.type = "button";
  close.className = "icon-btn";
  close.setAttribute("aria-label", "Close");
  close.textContent = "×";
  close.addEventListener("click", () => overlay.remove());
  header.appendChild(title);
  header.appendChild(close);
  const pre = document.createElement("pre");
  pre.className = "modal-pre";
  pre.textContent = text;
  dialog.appendChild(header);
  dialog.appendChild(pre);
  overlay.appendChild(dialog);
  overlay.addEventListener("click", (e) => { if (e.target === overlay) overlay.remove(); });
  document.body.appendChild(overlay);
}

document.addEventListener("DOMContentLoaded", () => {
  load();

  // Theme.
  for (const r of document.querySelectorAll('input[name="theme"]')) {
    r.addEventListener("change", async () => {
      const value = r.value;
      await save({ theme: value });
      applyTheme(value);
    });
  }

  for (const r of document.querySelectorAll('input[name="resolver"]')) {
    r.addEventListener("change", async () => {
      const value = r.value;
      $("customResolver").disabled = value !== "custom";
      $("nextdnsId").disabled = value !== "nextdns";
      setCustomResolverError(null);
      if (value === "custom") {
        await ensureCustomResolverPermission();
      }
      if (value === "nextdns" && !($("nextdnsId").value || "").trim()) {
        toast("Enter your NextDNS profile ID below");
        $("nextdnsId").focus();
      }
      await save({ resolver: value });
    });
  }
  $("customResolver").addEventListener("change", async (e) => {
    const v = e.target.value.trim();
    setCustomResolverError(null);
    if (!v) {
      await save({ customResolver: "" });
      return;
    }
    let parsed;
    try { parsed = new URL(v); } catch {
      setCustomResolverError("That doesn't look like a valid URL.");
      return;
    }
    if (parsed.protocol !== "https:") {
      setCustomResolverError("Resolver must be HTTPS.");
      return;
    }
    const origin = `${parsed.protocol}//${parsed.host}/*`;
    const granted = await chrome.permissions.request({ origins: [origin] }).catch(() => false);
    if (!granted) {
      setCustomResolverError("Permission for that host was denied.");
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
  $("noCache").addEventListener("change", async (e) => {
    await save({ noCache: e.target.checked });
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
  $("compareResolvers").addEventListener("change", async (e) => {
    await save({ compareResolvers: e.target.checked });
  });
  $("notifyOnChange").addEventListener("change", async (e) => {
    await save({ notifyOnChange: e.target.checked });
  });

  // Per-site lists.
  $("addAllowlist").addEventListener("click", async () => {
    const v = $("allowlistInput").value.trim().toLowerCase();
    if (!v) return;
    const resp = await sendMessage({ type: "addAllowlist", host: v });
    if (resp.ok) {
      $("allowlistInput").value = "";
      const stored = await chrome.storage.local.get(DEFAULTS);
      await renderLists(stored);
    } else {
      toast("Couldn't add entry");
    }
  });
  $("addBlocklist").addEventListener("click", async () => {
    const v = $("blocklistInput").value.trim().toLowerCase();
    if (!v) return;
    const resp = await sendMessage({ type: "addBlocklist", host: v });
    if (resp.ok) {
      $("blocklistInput").value = "";
      const stored = await chrome.storage.local.get(DEFAULTS);
      await renderLists(stored);
    } else {
      toast("Couldn't add entry");
    }
  });

  // Custom resolver presets.
  $("presetSelect").addEventListener("change", async (e) => {
    const url = e.target.value;
    if (!url) return;
    $("customResolver").value = url;
    // Trigger the change handler's validation + permission flow.
    $("customResolver").dispatchEvent(new Event("change"));
  });
  $("savePreset").addEventListener("click", async () => {
    const url = $("customResolver").value.trim();
    if (!url) { toast("Enter a URL first"); return; }
    const name = prompt("Name this preset:", url);
    if (!name) return;
    const s = await chrome.storage.local.get(DEFAULTS);
    const presets = (s.customPresets || []).filter((p) => p.url !== url);
    presets.push({ name, url });
    await save({ customPresets: presets });
    refreshPresets(presets);
  });
  $("deletePreset").addEventListener("click", async () => {
    const sel = $("presetSelect");
    const url = sel.value;
    if (!url) return;
    const s = await chrome.storage.local.get(DEFAULTS);
    const presets = (s.customPresets || []).filter((p) => p.url !== url);
    await save({ customPresets: presets });
    refreshPresets(presets);
    sel.value = "";
  });

  // History controls.
  $("keepHistory").addEventListener("change", async (e) => {
    if (!e.target.checked) {
      const resp = await sendMessage({ type: "listHistory" });
      const hasEntries = resp.ok && resp.entries && resp.entries.length > 0;
      if (hasEntries) {
        if (!confirm("Delete existing ECH history? This cannot be undone.")) {
          e.target.checked = true;
          return;
        }
        await sendMessage({ type: "clearHistory" });
        await refreshHistory();
      }
    }
    await save({ keepHistory: e.target.checked });
    updateHistoryFastPathVisibility(e.target.checked, $("historyFastPath").checked);
  });
  $("historyFastPath").addEventListener("change", async (e) => {
    await save({ historyFastPath: e.target.checked });
  });
  chrome.permissions.onAdded.addListener(updatePermStatus);
  chrome.permissions.onRemoved.addListener(updatePermStatus);

  $("refreshHistory").addEventListener("click", () => { refreshHistory(); });
  $("clearHistory").addEventListener("click", async (e) => {
    if (!confirm("Clear the entire ECH site history? This cannot be undone.")) return;
    e.target.disabled = true;
    const r = await sendMessage({ type: "clearHistory" });
    e.target.disabled = false;
    if (r.ok) {
      toast("History cleared");
      await refreshHistory();
    } else {
      toast("Couldn't clear history");
    }
  });
  $("historySearch").addEventListener("input", (e) => {
    historySearchTerm = e.target.value.trim();
    renderHistory();
  });
  $("sortHistory").addEventListener("click", (e) => {
    historySortAZ = !historySortAZ;
    e.target.textContent = historySortAZ ? "Newest" : "A–Z";
    renderHistory();
  });
  $("selectAllHistory").addEventListener("change", (e) => {
    const checked = e.target.checked;
    for (const cb of document.querySelectorAll(".history-check")) cb.checked = checked;
    updateRemoveSelectedState();
  });
  $("removeSelected").addEventListener("click", async (e) => {
    const hosts = Array.from(document.querySelectorAll(".history-check:checked")).map((c) => c.dataset.host);
    if (hosts.length === 0) return;
    e.target.disabled = true;
    for (const host of hosts) {
      await sendMessage({ type: "removeHistory", host });
    }
    await refreshHistory();
  });
  $("exportHistory").addEventListener("click", async () => {
    const resp = await sendMessage({ type: "exportHistory" });
    if (!resp.ok || !resp.blob) { toast("Nothing to export"); return; }
    downloadJson({ whereech: "history", version: 1, blob: resp.blob }, "whereech-history.json");
  });
  $("importHistory").addEventListener("click", () => $("importHistoryFile").click());
  $("importHistoryFile").addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    try {
      const parsed = await readJsonFile(file);
      if (!parsed || !parsed.blob) throw new Error("no blob in file");
      const resp = await sendMessage({ type: "importHistory", blob: parsed.blob });
      if (!resp.ok) throw new Error(resp.error || "import failed");
      toast("History imported");
      await refreshHistory();
    } catch (err) {
      toast("Import failed: " + String(err && err.message || err));
    } finally {
      e.target.value = "";
    }
  });

  // Settings export / import.
  $("exportSettingsBtn").addEventListener("click", async () => {
    const resp = await sendMessage({ type: "exportSettings" });
    if (!resp.ok) { toast("Couldn't export settings"); return; }
    downloadJson({ whereech: "settings", version: 1, settings: resp.settings }, "whereech-settings.json");
  });
  $("importSettingsBtn").addEventListener("click", () => $("importSettingsFile").click());
  $("importSettingsFile").addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    try {
      const parsed = await readJsonFile(file);
      if (!parsed || !parsed.settings) throw new Error("no settings in file");
      const resp = await sendMessage({ type: "importSettings", settings: parsed.settings });
      if (!resp.ok) throw new Error(resp.error || "import failed");
      toast("Settings imported");
      await load();
    } catch (err) {
      toast("Import failed: " + String(err && err.message || err));
    } finally {
      e.target.value = "";
    }
  });

  // What's new.
  $("whatsNewLink").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.sendMessage({ type: "getChangelog" }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.ok) {
        // Fallback: open the README on GitHub? No — keep offline. Just toast.
        toast("Couldn't load changelog");
        return;
      }
      openChangelogModal(resp.text);
    });
  });

  $("clearCache").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "clearCache" }, () => {
      if (chrome.runtime.lastError) toast("Error clearing cache");
      else toast("Cache cleared");
    });
  });
});