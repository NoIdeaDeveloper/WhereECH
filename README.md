# WhereECH

A privacy-respecting browser extension that tells you which sites support **Encrypted Client Hello (ECH)**, the TLS extension that hides the hostname you're visiting from anyone watching the network during the handshake.

Without ECH, even though page contents are encrypted, the site name still leaks in the clear via the TLS Server Name Indication (SNI) field. WhereECH inspects each site's DNS HTTPS resource record (RFC 9460) to see whether it advertises an ECH configuration, and surfaces the result on the toolbar.

## Features

- **Toolbar badge** — green `ECH` when a site advertises ECH, gray `—` when it doesn't, `?` if the lookup failed, `⊘` if the host was skipped by your allowlist/blocklist.
- **Multiple DoH resolvers** — Cloudflare, Quad9, Control D, NextDNS (with your personal profile), or any custom JSON DoH endpoint. Save your favorites as reusable **presets**.
- **Resolver comparison** — optionally query every built-in resolver in parallel and show each one's verdict side-by-side, so you can spot a resolver that disagrees with the others.
- **Privacy mode** — disable automatic lookups so DNS queries only happen when you explicitly click the toolbar icon.
- **Per-site allowlist/blocklist** — restrict automatic lookups to a specific set of hosts (allowlist) or silence them for hosts you don't care about (blocklist). Manual lookups always bypass both.
- **No-cache mode** — disable the in-memory result cache entirely. Every lookup hits the resolver fresh; nothing is retained between navigations.
- **Keyboard shortcut** — re-check the current site with `Ctrl+Shift+E` (`MacCtrl+Shift+E` on macOS). If that combination is already taken by another extension, Chrome leaves it unbound; you can assign your own at `chrome://extensions/shortcuts`.
- **ECH config details** — the popup shows the `config_id`, KEM algorithm, and cipher suites each site offers, so you can see exactly which ECH parameters are in use (not just "ECH yes/no").
- **ECH outer name** — shows the public name from each site's ECH configuration (e.g. `cloudflare-ech.com` for Cloudflare-hosted sites vs. a self-hosted domain), so you can see whose infrastructure is providing the ECH layer.
- **Optional Cloudflare trace confirmation** — for Cloudflare-hosted sites, verify via `/cdn-cgi/trace` that your actual connection used ECH (not just that the site offers it). The response is checked for a Cloudflare `cf-ray`/`server` header and a matching final URL to prevent spoofed confirmations.
- **Status-change notifications** — optionally get a system notification when a site's ECH status changes (e.g. starts offering ECH, stops offering it, or confirms live negotiation).
- **Optional encrypted history** — keep a local, opt-in list of sites you've seen supporting ECH. The list is encrypted with AES-GCM using a non-extractable key that never leaves your device, and the key automatically **rotates every 30 days** (re-encrypting existing entries) so any exfiltrated ciphertext has a short shelf life. You can review, search, filter, sort, bulk-remove, export, import, or wipe the list from Settings.
- **Settings export/import** — back up or transfer all preferences (resolvers, presets, lists, theme, toggles) as a JSON file. History ciphertext is never included.
- **Theme override** — follow the system theme, or force light/dark explicitly.
- **In-extension changelog** — the options page and popup both offer a "What's new" link that reads `CHANGELOG.md` from the extension bundle.
- **No telemetry.** No analytics, no remote logging, no third parties beyond the DNS resolver you pick. The result cache lives only in memory and is wiped on browser restart.

## How it works

1. On navigation, WhereECH extracts the hostname of the current tab and checks it against your allowlist/blocklist.
2. It sends a DNS-over-HTTPS query for the `HTTPS` (type 65) record to your chosen resolver. The query is padded to 256 bytes following RFC 8467 to limit traffic-analysis fingerprinting.
3. It parses the resource record (both wire-format and presentation-format are supported) and checks for an `ech=` SvcParam. When present, the `config_id`, KEM, and cipher suites are extracted for the popup.
4. The toolbar badge updates to reflect the result. Optionally, a follow-up request to `/cdn-cgi/trace` confirms whether the live connection actually negotiated ECH. If resolver comparison is on, all built-in resolvers are queried in parallel and each verdict is shown in the popup.
5. If status-change notifications are enabled, the new status is compared against the last one seen for that host (kept in `chrome.storage.local`) and a notification is fired on transition.

Lookups are cached in memory for 10 minutes (30 seconds for failures) to avoid repeating the same query. The cache can be disabled entirely with no-cache mode, or cleared on demand from Settings.

## Installation (unpacked)

1. Clone this repository.
2. Open `chrome://extensions` (or your Chromium browser's equivalent).
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the repository folder.
5. Pin the WhereECH icon to the toolbar.

The extension uses Manifest V3 and requires the `tabs`, `webNavigation`, `storage`, and `notifications` permissions. Host permissions are limited to the four built-in DoH endpoints; broader host permission is only requested on demand, and only for the specific origin you need — either the site you're visiting (if you enable Cloudflare trace confirmation) or the specific host of a custom DoH resolver you enter.

## Settings

Open the options page from the extension's menu to:

- Pick a DoH resolver (or supply your own) and save custom resolver presets.
- Toggle automatic lookups on/off, and restrict them to your allowlist or blocklist.
- Enable optional Cloudflare trace confirmation.
- Turn on resolver comparison, status-change notifications, and no-cache mode.
- Force a light/dark theme or follow the system.
- Enable or disable the optional ECH site history; review, search, sort, bulk-remove, export, or import entries; or clear the entire list.
- Export or import all preferences as a JSON file.
- Clear the in-memory cache.

## Privacy

Each automatic lookup discloses one hostname — the site you're visiting — to the DoH resolver you've chosen. Pick a resolver you trust with your browsing history, or switch to manual mode so lookups only occur when you ask. Enabling resolver comparison multiplies this disclosure across all built-in resolvers in parallel, which is useful for cross-checking but increases how many parties see each query.

WhereECH never sends data anywhere else. There is no telemetry, no analytics, no remote logging, and no "phone home" endpoint of any kind.

### Query timing side-channel

Because the extension fires a DoH query the moment you navigate to a new host, the resolver sees your browsing pattern reflected as a stream of queries timed to your navigation. If an observer controls the resolver, they can correlate query timing with your other network activity. Mitigations in this extension: queries are padded (RFC 8467), failed results are short-lived (30s cache) to avoid repeat bursts, and no-cache mode is available for users who'd rather trade freshness for a single query per visit. A resolver still learns the hostname itself — there's no way around that without a full oblivious-DOH setup, which is out of scope here.

### ECH site history (optional, off by default)

If you enable the history feature, WhereECH keeps a list of hostnames it has observed supporting ECH. A few things to know:

- **Opt-in.** The feature is off by default. Nothing is recorded until you turn it on in Settings.
- **Positive only.** Only sites that successfully advertise or negotiate ECH are recorded. Sites without ECH, failed lookups, and skipped URLs leave no trace.
- **Minimal data.** Each entry is ONLY the hostname. No visit counts, no timestamps, no status — just the name, rendered as a clickable link in Settings.
- **Local only.** The list lives on your device, in this extension's own storage area. It is never uploaded, synced, or shared.
- **Encrypted at rest.** Entries are stored as an AES-GCM-256 ciphertext blob. The encryption key is a non-extractable `CryptoKey` held in the extension's IndexedDB: the browser itself refuses to let any JavaScript — including this extension — read the raw key bytes. The key can only be *used* via the WebCrypto API.
- **Periodic key rotation.** The master key is regenerated and all existing entries are re-encrypted under the new key every 30 days, so any exfiltrated ciphertext blob has a limited shelf life. The rotation timestamp is stored alongside the key in IndexedDB.
- **Under your control.** Settings lets you review, search, filter, sort, bulk-remove, export, or import entries, or wipe the whole list. Clearing the list also destroys and regenerates the encryption key, so any leftover copy of the old ciphertext (in disk snapshots, for example) becomes permanently undecryptable.
- **Honest limitation.** Because the extension can decrypt the list itself without a passphrase, an attacker who can run code as you inside your browser profile could ask the extension to decrypt on their behalf. This design protects against casual disk inspection and other extensions — not against full device compromise.

### History fast-path side-channel

When the history feature is enabled and no-cache mode is off, the extension uses a fast path: it checks an in-memory `Set` of known-ECH hostnames before doing a full DNS lookup, so repeat visits to a known-ECH site don't trigger a resolver query at all. The flip side is that an attacker who can observe the extension's memory (or time the absence of a DNS query right after navigation) can infer that a host is in the history set. This is a deliberate trade-off for speed. To avoid the side-channel entirely, enable no-cache mode — every lookup is fresh and the fast path is skipped.

## Files

- [manifest.json](manifest.json) — extension manifest (MV3)
- [background.js](background.js) — service worker: navigation handling, DoH lookups (with EDNS(0) padding), caching, allowlist/blocklist enforcement, multi-resolver comparison, status-change notifications, badge updates
- [ech.js](ech.js) — HTTPS RR parser (wire and presentation formats; extracts `config_id`, KEM, cipher suites)
- [history.js](history.js) — opt-in encrypted ECH site history (AES-GCM-256, non-extractable key in IndexedDB, 30-day key rotation, encrypted-blob export/import)
- [popup.html](popup.html) / [popup.js](popup.js) / [popup.css](popup.css) — toolbar popup UI
- [options.html](options.html) / [options.js](options.js) / [options.css](options.css) — settings page
- [CHANGELOG.md](CHANGELOG.md) — human-readable release notes, also viewable in-extension via "What's new"
- [_locales/en/messages.json](_locales/en/messages.json) — default-locale strings for `__MSG_*__` substitution in the manifest

Each source file opens with a header describing what it does, what it explicitly does NOT do, and what data it has access to — so you can audit the extension one file at a time.

## References

- [RFC 9460 — Service Binding and Parameter Specification via the DNS (SVCB and HTTPS RRs)](https://www.rfc-editor.org/rfc/rfc9460.html)
- [RFC 8467 — Padding Policies for Extension Mechanisms for DNS (EDNS(0))](https://www.rfc-editor.org/rfc/rfc8467.html)
- [RFC 6891 — Extension Mechanisms for DNS (EDNS(0))](https://www.rfc-editor.org/rfc/rfc6891.html)
- [RFC 8484 — DNS Queries over HTTPS (DoH)](https://www.rfc-editor.org/rfc/rfc8484.html)
- [TLS Encrypted Client Hello (draft-ietf-tls-esni)](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
