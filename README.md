# WhereECH

A privacy-respecting browser extension that tells you which sites support **Encrypted Client Hello (ECH)**, the TLS extension that hides the hostname you're visiting from anyone watching the network during the handshake.

Without ECH, even though page contents are encrypted, the site name still leaks in the clear via the TLS Server Name Indication (SNI) field. WhereECH inspects each site's DNS HTTPS resource record (RFC 9460) to see whether it advertises an ECH configuration, and surfaces the result on the toolbar.

## Features

- **Toolbar badge** — green `ECH` when a site advertises ECH, gray `—` when it doesn't, `?` if the lookup failed.
- **Multiple DoH resolvers** — Cloudflare, Quad9, Control D, NextDNS (with your personal profile), or any custom JSON DoH endpoint.
- **Privacy mode** — disable automatic lookups so DNS queries only happen when you explicitly click the toolbar icon.
- **ECH outer name** — shows the public name from each site's ECH configuration (e.g. `cloudflare-ech.com` for Cloudflare-hosted sites vs. a self-hosted domain), so you can see whose infrastructure is providing the ECH layer.
- **Optional Cloudflare trace confirmation** — for Cloudflare-hosted sites, verify via `/cdn-cgi/trace` that your actual connection used ECH (not just that the site offers it).

- **Optional encrypted history** — keep a local, opt-in list of sites you've seen supporting ECH. The list is encrypted with AES-GCM using a non-extractable key that never leaves your device, and you can review, remove individual entries, or wipe it all from Settings.
- **No telemetry.** No analytics, no remote logging, no third parties beyond the DNS resolver you pick. The result cache lives only in memory and is wiped on browser restart.

## How it works

1. On navigation, WhereECH extracts the hostname of the current tab.
2. It sends a DNS-over-HTTPS query for the `HTTPS` (type 65) record to your chosen resolver.
3. It parses the resource record (both wire-format and presentation-format are supported) and checks for an `ech=` SvcParam.
4. The toolbar badge updates to reflect the result. Optionally, a follow-up request to `/cdn-cgi/trace` confirms whether the live connection actually negotiated ECH.

Lookups are cached in memory for 10 minutes (30 seconds for failures) to avoid repeating the same query.

## Installation (unpacked)

1. Clone this repository.
2. Open `chrome://extensions` (or your Chromium browser's equivalent).
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the repository folder.
5. Pin the WhereECH icon to the toolbar.

The extension uses Manifest V3 and requires the `tabs`, `webNavigation`, and `storage` permissions. Host permissions are limited to the four built-in DoH endpoints; broader host permission is only requested on demand, and only for the specific origin you need — either the site you're visiting (if you enable Cloudflare trace confirmation) or the specific host of a custom DoH resolver you enter.

## Settings

Open the options page from the extension's menu to:

- Pick a DoH resolver (or supply your own).
- Toggle automatic lookups on/off.
- Enable optional Cloudflare trace confirmation.

- Enable or disable the optional ECH site history, review or remove individual entries, or clear the entire list.
- Clear the in-memory cache.

## Privacy

Each automatic lookup discloses one hostname — the site you're visiting — to the DoH resolver you've chosen. Pick a resolver you trust with your browsing history, or switch to manual mode so lookups only occur when you ask.

WhereECH never sends data anywhere else. There is no telemetry, no analytics, no remote logging, and no "phone home" endpoint of any kind.

### ECH site history (optional, off by default)

If you enable the history feature, WhereECH keeps a list of hostnames it has observed supporting ECH. A few things to know:

- **Opt-in.** The feature is off by default. Nothing is recorded until you turn it on in Settings.
- **Positive only.** Only sites that successfully advertise or negotiate ECH are recorded. Sites without ECH, failed lookups, and skipped URLs leave no trace.
- **Minimal data.** Each entry is ONLY the hostname. No visit counts, no timestamps, no status — just the name, rendered as a clickable link in Settings.
- **Local only.** The list lives on your device, in this extension's own storage area. It is never uploaded, synced, or shared.
- **Encrypted at rest.** Entries are stored as an AES-GCM-256 ciphertext blob. The encryption key is a non-extractable `CryptoKey` held in the extension's IndexedDB: the browser itself refuses to let any JavaScript — including this extension — read the raw key bytes. The key can only be *used* via the WebCrypto API.
- **Under your control.** Settings lets you review the list, remove individual entries, or wipe the whole thing. Clearing the list also destroys and regenerates the encryption key, so any leftover copy of the old ciphertext (in disk snapshots, for example) becomes permanently undecryptable.
- **Honest limitation.** Because the extension can decrypt the list itself without a passphrase, an attacker who can run code as you inside your browser profile could ask the extension to decrypt on their behalf. This design protects against casual disk inspection and other extensions — not against full device compromise.

## Files

- [manifest.json](manifest.json) — extension manifest (MV3)
- [background.js](background.js) — service worker: navigation handling, DoH lookups, caching, badge updates
- [ech.js](ech.js) — HTTPS RR parser (wire and presentation formats)
- [history.js](history.js) — opt-in encrypted ECH site history (AES-GCM, non-extractable key in IndexedDB)
- [popup.html](popup.html) / [popup.js](popup.js) / [popup.css](popup.css) — toolbar popup UI
- [options.html](options.html) / [options.js](options.js) / [options.css](options.css) — settings page

Each source file opens with a header describing what it does, what it explicitly does NOT do, and what data it has access to — so you can audit the extension one file at a time.

## References

- [RFC 9460 — Service Binding and Parameter Specification via the DNS (SVCB and HTTPS RRs)](https://www.rfc-editor.org/rfc/rfc9460.html)
- [TLS Encrypted Client Hello (draft-ietf-tls-esni)](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
