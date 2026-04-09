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
  advertised: "ECH supported",
  not_advertised: "No ECH",
  unknown: "Unavailable",
  skipped: "Not applicable",
};

const NOTES = {
  confirmed: "Your browser negotiated Encrypted Client Hello with this site. The hostname you visited (the SNI) was hidden from anyone watching the network — only your DNS resolver and the site itself know what you connected to.",
  advertised: "This site publishes an ECH key in DNS, so a browser that supports ECH will use it automatically on the TLS handshake. WhereECH can't see inside your actual handshake, so it can't 100% confirm ECH was used — enable the Cloudflare trace probe in Settings for proof on Cloudflare-hosted sites.",
  not_advertised: "This site does not publish an ECH key in DNS. Your browser sent the hostname (SNI) in the clear during the TLS handshake, where any on-path observer could read it. The traffic itself is still encrypted.",
  unknown: "WhereECH couldn't reach the DNS-over-HTTPS resolver. Check your network connection, or pick a different resolver in Settings.",
  skipped: "WhereECH only inspects regular HTTPS websites. Browser pages, local files, and IP-literal addresses don't apply.",
};

function $(id) { return document.getElementById(id); }

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

function render(resp) {
  if (!resp.ok) {
    setHero("unknown", "Error");
    $("host").textContent = "";
    $("note").textContent = resp.error || "Unknown error";
    return;
  }
  if (resp.skipped) {
    setHero("skipped", "Not applicable");
    $("host").textContent = "";
    $("note").textContent = NOTES.skipped;
    setRow("resolver-row", "resolver-v", null);
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
  setRow("alpn-row", "alpn-v", s.alpn);
  setRow("ipv4-row", "ipv4-v", s.ipv4);
  setRow("ipv6-row", "ipv6-v", s.ipv6);
  const sniText = r.sni === "encrypted" ? "hostname was hidden (ECH used)"
    : r.sni === "plaintext" ? "hostname was visible (ECH not used)"
    : r.sni;
  setRow("sni-row", "sni-v", sniText);
  setRow("kex-row", "kex-v", r.kex || null);
  const pqText = r.kex
    ? (r.pq ? "Yes — quantum-resistant key exchange" : "No — classical key exchange")
    : null;
  setRow("pq-row", "pq-v", pqText);
  setRow("error-row", "error-v", r.error);

  $("rr").textContent = (r.rrRaw && r.rrRaw.length) ? r.rrRaw.join("\n\n") : "(none)";
}

function request(force = false) {
  setHero("unknown", "Checking…");
  $("recheck").classList.add("loading");
  chrome.runtime.sendMessage({ type: "getForTab", force }, (resp) => {
    $("recheck").classList.remove("loading");
    if (chrome.runtime.lastError) {
      render({ ok: false, error: chrome.runtime.lastError.message });
      return;
    }
    render(resp);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  request(false);
  $("recheck").addEventListener("click", () => request(true));
  $("open-options").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("copy-rr").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("rr").textContent || "");
      const btn = $("copy-rr");
      const old = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = old; }, 1200);
    } catch {}
  });
});
