// WhereECH — toolbar popup UI.
//
// What this file does:
//   * When you click the toolbar icon, it asks the background service
//     worker for the ECH status of the current tab's hostname and
//     displays the result.
//   * It renders the result into the popup DOM using textContent only.
//
// What this file does NOT do:
//   * No network I/O. It never calls fetch(). Any lookup that happens
//     as a side-effect of opening the popup happens inside the service
//     worker, which does it subject to ALL the privacy rules documented
//     in background.js.
//   * No storage access. It does not read or write chrome.storage,
//     IndexedDB, cookies, localStorage, or any other persistent state.
//   * No access to the page you're visiting. The popup can only read
//     the active tab's URL via the service worker; it cannot run
//     scripts in the page, read its DOM, or see its cookies.
//   * No dynamic HTML. Every value on the popup is set with .textContent.
//     There is no innerHTML, no eval, no inline scripts (blocked by CSP).
//   * No access to the encrypted history — the popup does not even
//     have the message types to list or read it.

// Popup UI: queries the service worker, renders results with safe DOM APIs only.

const STATUS_LABEL = {
  confirmed: "ECH active",
  offered: "ECH offered, not used",
  advertised: "ECH supported",
  history: "ECH supported",
  not_advertised: "No ECH",
  unknown: "Unavailable",
  checking: "Checking…",
  skipped: "Not applicable",
};

const NOTES = {
  confirmed: "Your browser negotiated Encrypted Client Hello with this site. The hostname you visited (the SNI) was hidden from anyone watching the network — only your DNS resolver and the site itself know what you connected to.",
  offered: "This site publishes an ECH key in DNS, but Cloudflare's trace endpoint reports that your browser did not negotiate ECH on this connection. This can happen if your browser doesn't support ECH or if it was temporarily disabled. Hit Re-check to try again.",
  advertised: "This site publishes an ECH key in DNS, so a browser that supports ECH will use it automatically on the TLS handshake. WhereECH can't see inside your actual handshake, so it can't 100% confirm ECH was used — enable the Cloudflare trace probe in Settings for proof on Cloudflare-hosted sites.",
  history: "This site was found in your ECH history from a previous visit, so WhereECH skipped the DNS lookup. Hit Re-check to run a fresh lookup instead.",
  not_advertised: "This site does not publish an ECH key in DNS. Your browser sent the hostname (SNI) in the clear during the TLS handshake, where any on-path observer could read it. The traffic itself is still encrypted.",
  unknown: "WhereECH couldn't reach the DNS-over-HTTPS resolver. Check your network connection, or pick a different resolver in Settings.",
  skipped: "WhereECH only inspects regular HTTPS websites. Browser pages, local files, and IP-literal addresses don't apply.",
  skippedHttp: "This page is loaded over plain HTTP, not HTTPS. The hostname is visible to anyone watching the network during both the DNS lookup and the connection — there's no encryption layer for ECH to protect.",
};

function $(id) { return document.getElementById(id); }

// Apply the manual theme override. "system" defers to prefers-color-scheme
// via the CSS media query; "light" / "dark" set an explicit attribute on
// <html> that the CSS honors over the media query.
function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "dark") root.setAttribute("data-theme", "dark");
  else if (theme === "light") root.setAttribute("data-theme", "light");
  else root.removeAttribute("data-theme");
}

// Lookup table for KEM IDs used in ECHConfig (RFC 9460 §6.1). Only the
// values WhereECH is likely to encounter are named; unknown IDs are shown
// as hex so power users still get the raw value.
const KEM_NAMES = {
  0x0020: "X25519",
  0x0021: "P-256",
  0x0022: "X448",
  0x0023: "P-521",
};
const KDF_NAMES = { 0x0001: "HKDF-SHA256", 0x0002: "HKDF-SHA384", 0x0003: "HKDF-SHA512" };
const AEAD_NAMES = { 0x0001: "AES-128-GCM", 0x0002: "AES-256-GCM", 0x0003: "ChaCha20-Poly1305" };

function fmtKem(id) {
  return KEM_NAMES[id] || `0x${id.toString(16).padStart(4, "0")}`;
}
function fmtCipherSuite(cs) {
  const kdf = KDF_NAMES[cs.kdf] || `0x${cs.kdf.toString(16).padStart(4, "0")}`;
  const aead = AEAD_NAMES[cs.aead] || `0x${cs.aead.toString(16).padStart(4, "0")}`;
  return `${kdf}+${aead}`;
}

function setRow(rowId, valueId, value) {
  const row = $(rowId);
  if (value == null || value === "" || (Array.isArray(value) && value.length === 0)) {
    row.classList.add("hidden");
    return;
  }
  row.classList.remove("hidden");
  $(valueId).textContent = Array.isArray(value) ? value.join(", ") : String(value);
}

function setHero(state, label) {
  $("hero").dataset.state = state;
  $("status-label").textContent = label;
}

// Hide every data row in the info card so a re-render (e.g. after a
// failed recheck) never leaves stale values visible from a prior result.
function resetRows() {
  for (const id of [
    "resolver-row", "ech-row", "echname-row", "echconfig-row", "alpn-row",
    "ipv4-row", "ipv6-row", "sni-row", "compare-row", "error-row",
  ]) {
    $(id).classList.add("hidden");
  }
  $("rr").textContent = "";
}

function render(resp) {
  resetRows();
  if (!resp.ok) {
    setHero("unknown", "Error");
    $("host").textContent = "";
    $("note").textContent = resp.error || "Unknown error";
    return;
  }
  if (resp.skipped) {
    setHero("skipped", "Not applicable");
    $("host").textContent = "";
    const isHttp = resp.url && resp.url.startsWith("http://");
    $("note").textContent = isHttp ? NOTES.skippedHttp : NOTES.skipped;
    $("recheck").disabled = true;
    return;
  }
  $("recheck").disabled = false;

  const r = resp.result;
  setHero(r.status, STATUS_LABEL[r.status] || r.status);
  $("host").textContent = r.host;
  $("host").title = r.host;
  $("note").textContent = NOTES[r.status] || "";

  setRow("resolver-row", "resolver-v", r.resolver);

  const s = r.summary || {};
  setRow("ech-row", "ech-v", s.echLength ? `${s.echLength} bytes` : null);
  setRow("echname-row", "echname-v", s.echPublicName || null);
  // ECH config details: config_id, KEM, and cipher suites. Only shown
  // when the site actually advertises an ECH key.
  if (s.echLength) {
    const parts = [];
    if (s.echConfigId != null) parts.push(`id ${s.echConfigId}`);
    if (s.echKemId != null) parts.push(fmtKem(s.echKemId));
    if (Array.isArray(s.echCipherSuites) && s.echCipherSuites.length) {
      parts.push(s.echCipherSuites.map(fmtCipherSuite).join(", "));
    }
    setRow("echconfig-row", "echconfig-v", parts.length ? parts.join(" · ") : null);
  } else {
    setRow("echconfig-row", "echconfig-v", null);
  }
  setRow("alpn-row", "alpn-v", s.alpn);
  setRow("ipv4-row", "ipv4-v", s.ipv4);
  setRow("ipv6-row", "ipv6-v", s.ipv6);
  const sniText = r.sni === "encrypted" ? "hostname was hidden (ECH used)"
    : r.sni === "plaintext" ? "hostname was visible (ECH not used)"
    : r.sni;
  setRow("sni-row", "sni-v", sniText);
  // Multi-resolver comparison: each entry is { resolver, status, error? }.
  if (Array.isArray(r.comparisons) && r.comparisons.length > 1) {
    const lines = r.comparisons.map((c) => {
      const label = c.status === "advertised" ? "ECH"
        : c.status === "not_advertised" ? "—"
        : c.status === "error" ? "?"
        : c.status;
      return `${c.resolver}: ${label}`;
    });
    setRow("compare-row", "compare-v", lines.join("  ·  "));
  } else {
    setRow("compare-row", "compare-v", null);
  }
  setRow("error-row", "error-v", r.error);

  $("rr").textContent = (r.rrRaw && r.rrRaw.length) ? r.rrRaw.join("\n\n") : "(none)";
}

let requestInFlight = false;
let lastResp = null;

function request(force = false) {
  if (requestInFlight) return;
  requestInFlight = true;
  setHero("unknown", "Checking…");
  // Mark the view busy so assistive tech announces the pending lookup and
  // doesn't read the stale result mid-update.
  $("app").setAttribute("aria-busy", "true");
  $("recheck").classList.add("loading");
  chrome.runtime.sendMessage({ type: "getForTab", force }, (resp) => {
    requestInFlight = false;
    $("app").setAttribute("aria-busy", "false");
    $("recheck").classList.remove("loading");
    if (chrome.runtime.lastError) {
      lastResp = { ok: false, error: chrome.runtime.lastError.message };
      render(lastResp);
      return;
    }
    lastResp = resp;
    render(resp);
  });
}

// Build a plain-text summary of the current result suitable for pasting
// into a bug report or chat. Includes host, status, resolver, ECH
// parameters, and any error. No PII beyond the hostname the user is
// already visiting — and the user explicitly clicked "Copy summary".
function buildSummary(resp) {
  if (!resp || !resp.ok || !resp.result) return "(no result)";
  const r = resp.result;
  const s = r.summary || {};
  const lines = [
    `host: ${r.host}`,
    `status: ${r.status}`,
    `resolver: ${r.resolver}`,
  ];
  if (s.echLength) {
    lines.push(`ech_key_size: ${s.echLength}`);
    if (s.echPublicName) lines.push(`ech_outer_name: ${s.echPublicName}`);
    if (s.echConfigId != null) lines.push(`ech_config_id: ${s.echConfigId}`);
    if (s.echKemId != null) lines.push(`ech_kem: ${fmtKem(s.echKemId)}`);
    if (Array.isArray(s.echCipherSuites) && s.echCipherSuites.length) {
      lines.push(`ech_cipher_suites: ${s.echCipherSuites.map(fmtCipherSuite).join(", ")}`);
    }
  }
  if (Array.isArray(s.alpn) && s.alpn.length) lines.push(`alpn: ${s.alpn.join(",")}`);
  if (r.sni) lines.push(`trace_sni: ${r.sni}`);
  if (Array.isArray(r.comparisons) && r.comparisons.length > 1) {
    lines.push("comparison:");
    for (const c of r.comparisons) lines.push(`  - ${c.resolver}: ${c.status}${c.error ? ` (${c.error})` : ""}`);
  }
  if (r.error) lines.push(`error: ${r.error}`);
  return lines.join("\n");
}

document.addEventListener("DOMContentLoaded", () => {
  // Apply manual theme override before first paint to avoid a flash.
  chrome.storage.local.get({ theme: "system" }, ({ theme }) => applyTheme(theme));
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.theme) applyTheme(changes.theme.newValue || "system");
  });
  request(false);
  $("recheck").addEventListener("click", () => request(true));
  $("open-options").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("copy-host").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("host").textContent || "");
      const btn = $("copy-host");
      btn.title = "Copied!";
      setTimeout(() => { btn.title = "Copy hostname"; }, 1200);
    } catch {}
  });
  $("copy-rr").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("rr").textContent || "");
      const btn = $("copy-rr");
      const old = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = old; }, 1200);
    } catch {}
  });
  $("copy-summary").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(buildSummary(lastResp));
      const btn = $("copy-summary");
      const old = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = old; }, 1200);
    } catch {}
  });
  $("whats-new").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.sendMessage({ type: "getChangelog" }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.ok) {
        chrome.runtime.openOptionsPage();
        return;
      }
      openChangelogModal(resp.text);
    });
  });
});

// Open a lightweight modal showing the changelog text. Built with safe
// DOM APIs only — the markdown source is rendered as preformatted text,
// never interpreted as HTML.
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
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.remove();
  });
  document.body.appendChild(overlay);
}
