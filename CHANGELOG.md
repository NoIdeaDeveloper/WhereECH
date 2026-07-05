# Changelog

## 1.4.0

### Security

- **Cloudflare trace spoofing fix.** The trace probe now verifies the
  response actually came from Cloudflare by checking for a `cf-ray` or
  `server: cloudflare` header, and confirms the response URL's host
  matches the requested host. A non-Cloudflare origin can no longer
  forge `sni=encrypted` to falsely claim ECH was negotiated.
- **DNS query padding (RFC 8467).** Outgoing DoH queries are now padded
  to a uniform 256-byte target via an EDNS(0) Padding option, reducing
  traffic-analysis leakage of hostname length to passive observers.
- **Periodic key rotation.** The AES-GCM key protecting the optional ECH
  history now rotates at most once every 30 days, limiting the blast
  radius of a compromised key. Old ciphertext on disk becomes permanently
  undecryptable after rotation.
- **Tighter IP-literal detection.** `isIpLiteral` now properly validates
  IPv6 (including `::`-compressed and IPv4-mapped forms) instead of
  matching any string containing a colon.

### Privacy

- **No-cache mode.** New setting disables the in-memory result cache
  entirely, so no lookup result is retained between visits. Costs an
  extra DoH query per navigation in exchange for zero retention.
- **Per-site allowlist / blocklist.** Restrict automatic lookups to a
  specific set of hosts, or exclude hosts you never want queried.
  Manual lookups (popup / Re-check) always bypass the filters.

### Features

- **ECH config details in popup.** The popup now shows `config_id`,
  `kem_id`, and the list of cipher suites from the site's ECHConfig,
  for users who want to see exactly which ECH parameters are advertised.
- **ECH status-change notifications.** Opt in to be notified when a
  site you've previously visited starts or stops supporting ECH.
- **Multi-resolver comparison.** Optionally query every built-in DoH
  resolver in parallel and surface discrepancies in the popup, which
  can indicate DNS manipulation or split-horizon responses.
- **History export / import.** Back up the encrypted history blob and
  restore it later. The encryption key is never exported — restoring
  requires the same browser profile.
- **Settings export / import.** Back up or transfer your preferences
  across devices / profiles.
- **Custom resolver presets.** Save frequently used custom resolver
  URLs as named presets for quick switching.

### UI

- **History search / filter.** A search box above the history list
  filters entries as you type.
- **History count display.** Shows "472 entries" above the list so you
  always know how much is stored.
- **Bulk history actions.** Select multiple entries and remove them in
  one click.
- **Sortable history list.** Toggle between newest-first and A–Z.
- **Busy state on history buttons.** Refresh and Clear now show a
  spinner and disable themselves while the operation is in flight.
- **Keyboard shortcut hint in popup.** The `Ctrl+Shift+E` shortcut is
  now surfaced near the Re-check button.
- **Inline validation for custom resolver.** The custom resolver input
  shows a red border and inline error text instead of only a toast.
- **Copy full result summary.** A new button copies a text summary of
  the full lookup result, handy for bug reports.
- **Manual theme toggle.** Choose Light, Dark, or follow system.
- **Responsive popup width.** The popup now adapts gracefully to a
  wider range of widths instead of being fixed at 360px.
- **Version / changelog in-extension.** A "What's new" link in the
  popup opens the changelog.
- **Better empty history state.** A friendly prompt replaces the bare
  "No entries yet." text.

### Internationalization

- **Lightweight i18n setup.** The extension now ships with a
  `chrome.i18n` message catalog and uses `__MSG_*__` substitution for
  user-visible strings, making it ready for translation.

## 1.3.0

- Initial public release.