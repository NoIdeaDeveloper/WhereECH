# WhereECH

A privacy-respecting browser extension that tells you which sites support **Encrypted Client Hello (ECH)**, the TLS extension that hides the hostname you're visiting from anyone watching the network during the handshake.

Without ECH, even though page contents are encrypted, the site name still leaks in the clear via the TLS Server Name Indication (SNI) field. WhereECH inspects each site's DNS HTTPS resource record (RFC 9460) to see whether it advertises an ECH configuration, and surfaces the result on the toolbar.

## Features

- **Toolbar badge** — green `ECH` when a site advertises ECH, gray `—` when it doesn't, `?` if the lookup failed.
- **Multiple DoH resolvers** — Cloudflare, Quad9, Control D, NextDNS (with your personal profile), or any custom JSON DoH endpoint.
- **Privacy mode** — disable automatic lookups so DNS queries only happen when you explicitly click the toolbar icon.
- **Optional Cloudflare trace confirmation** — for Cloudflare-hosted sites, verify via `/cdn-cgi/trace` that your actual connection used ECH (not just that the site offers it).
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

The extension uses Manifest V3 and requires the `tabs`, `webNavigation`, and `storage` permissions. Host permissions are limited to the four DoH endpoints; the broader `https://*/*` permission is only requested if you opt into Cloudflare trace confirmation.

## Settings

Open the options page from the extension's menu to:

- Pick a DoH resolver (or supply your own).
- Toggle automatic lookups on/off.
- Enable optional Cloudflare trace confirmation.
- Clear the in-memory cache.

## Privacy

Each automatic lookup discloses one hostname — the site you're visiting — to the DoH resolver you've chosen. Pick a resolver you trust with your browsing history, or switch to manual mode so lookups only occur when you ask.

WhereECH never sends data anywhere else.

## Files

- [manifest.json](manifest.json) — extension manifest (MV3)
- [background.js](background.js) — service worker: navigation handling, DoH lookups, caching, badge updates
- [ech.js](ech.js) — HTTPS RR parser (wire and presentation formats)
- [popup.html](popup.html) / [popup.js](popup.js) / [popup.css](popup.css) — toolbar popup UI
- [options.html](options.html) / [options.js](options.js) / [options.css](options.css) — settings page

## References

- [RFC 9460 — Service Binding and Parameter Specification via the DNS (SVCB and HTTPS RRs)](https://www.rfc-editor.org/rfc/rfc9460.html)
- [TLS Encrypted Client Hello (draft-ietf-tls-esni)](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
