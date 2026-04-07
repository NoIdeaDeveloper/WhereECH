// WhereECH — encrypted ECH-site history.
//
// READ THIS FIRST if you care about what the extension remembers about you.
//
// What this file does:
//   An OPT-IN, on-disk log of sites that WhereECH has observed to support
//   Encrypted Client Hello. Nothing in this file does any kind of network
//   I/O — it only reads and writes to two pieces of local, per-extension
//   storage (chrome.storage.local and IndexedDB). No history data ever
//   leaves your device. There is no sync, no upload, no backup.
//
// What it does NOT do:
//   * It never records a hostname unless you have explicitly turned on
//     "Remember sites that support ECH" in Settings.
//   * It never records a hostname that did NOT successfully advertise or
//     use ECH — there is no list of sites-without-ECH.
//   * It does not record URLs, paths, query strings, timestamps of any
//     kind, visit counts, or any page content. Each entry is ONLY the
//     hostname — a bare string — and nothing else.
//   * It does not share this data with the popup, with the active tab,
//     with any content script, or with any network endpoint. The only
//     callers are the background service worker (to write) and the
//     options page (to display, remove, or wipe).
//
// Encryption design:
//   * The list is serialized to JSON and encrypted with AES-GCM-256
//     before being written to chrome.storage.local. A reader with raw
//     file-level access to your browser profile sees only opaque bytes.
//   * The encryption key is an AES-GCM CryptoKey generated on YOUR
//     device with extractable:false. That flag is enforced by the
//     browser: no JavaScript — not even this file — can read the raw
//     key bytes. The only operation that ever touches the key material
//     is SubtleCrypto.encrypt / SubtleCrypto.decrypt inside the browser.
//   * The key is persisted in the extension's IndexedDB database, which
//     is origin-isolated: only this extension can open it. Other
//     extensions and websites cannot.
//   * Each encrypted blob uses a fresh 96-bit random IV generated via
//     crypto.getRandomValues, never reused.
//   * "Clear entire list" does two things: it deletes the ciphertext
//     blob AND rotates (deletes and re-generates) the key. Any stale
//     copy of the old ciphertext left behind in filesystem snapshots,
//     backups, or undeleted disk sectors becomes permanently
//     undecryptable because the key that produced it is gone.
//
// Honest limitations (stated here so you can make an informed choice):
//   * Because the extension can decrypt the data itself without any
//     passphrase, an attacker who can run code inside your browser
//     profile as you could also ask the extension to decrypt on their
//     behalf. This design protects against casual disk inspection and
//     other extensions, not against full-device compromise.
//   * chrome.storage.local data is not removed by "Clear browsing data"
//     unless you choose to remove extension data. Use "Clear entire
//     list" in Settings to be sure.

// Name of the IndexedDB database that holds the encryption key. This DB
// contains exactly ONE thing: the CryptoKey object. It does not contain
// any hostnames, any history entries, or any other user data.
const IDB_NAME = "whereech-keys";
const IDB_STORE = "keys";
const IDB_KEY_ID = "master";
// Name of the single key under chrome.storage.local where the encrypted
// history blob lives. The plaintext hostnames are NEVER stored anywhere
// else; only the ciphertext of the full serialized list sits here.
const STORAGE_BLOB = "historyBlob";
// Hard cap so even a heavy user can't grow the encrypted blob without
// bound. Past this count, the least-recently-seen entries are dropped
// first (see move-to-end LRU semantics in recordEchHost below).
const MAX_ENTRIES = 5000;
// Format version for the encrypted blob envelope. Bumping this lets
// future code recognize and migrate (or refuse) older layouts instead
// of silently misparsing them.
const BLOB_VERSION = 1;

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(IDB_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbRun(mode, fn) {
  return idbOpen().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, mode);
    const store = tx.objectStore(IDB_STORE);
    let result;
    Promise.resolve(fn(store)).then((r) => { result = r; }, reject);
    tx.oncomplete = () => { db.close(); resolve(result); };
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  }));
}

function idbGet(key) {
  return idbRun("readonly", (store) => new Promise((resolve, reject) => {
    const r = store.get(key);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  }));
}

function idbPut(key, value) {
  return idbRun("readwrite", (store) => { store.put(value, key); });
}

function idbDelete(key) {
  return idbRun("readwrite", (store) => { store.delete(key); });
}

// Returns the AES-GCM CryptoKey used to encrypt and decrypt the history
// blob, creating one on first use. The key is generated entirely locally
// by the browser's crypto primitives — it is never fetched, never
// derived from anything the user types, never sent anywhere, and never
// leaves the browser's cryptography subsystem as raw bytes. The second
// argument to generateKey is `false` (extractable), which is a hard
// browser-enforced guarantee that crypto.subtle.exportKey() on this key
// will throw. That means even a compromised copy of this file or a
// malicious other extension cannot read the key material — it can only
// *use* the key via encrypt/decrypt.
async function getOrCreateKey() {
  const existing = await idbGet(IDB_KEY_ID);
  if (existing) return existing;
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false, // non-extractable — browser refuses exportKey() on this key
    ["encrypt", "decrypt"]
  );
  await idbPut(IDB_KEY_ID, key);
  return key;
}

// Called only from clearEchHistory(). Deleting the key makes any older
// copies of the ciphertext (e.g. leftover in disk snapshots or recovered
// from a trash bin) permanently undecryptable, because the key itself
// is gone and was never exportable in the first place.
async function rotateKey() {
  await idbDelete(IDB_KEY_ID);
  return getOrCreateKey();
}

function b64enc(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64dec(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// Encrypt a JSON-serializable object. Each call generates a brand-new
// 96-bit IV from crypto.getRandomValues (the browser's CSPRNG), so no
// IV is ever reused with the same key — a requirement for AES-GCM's
// confidentiality and integrity guarantees. Returns a plain object that
// chrome.storage.local can serialize: base64(iv), base64(ciphertext),
// and a version tag.
async function encryptJson(obj) {
  const key = await getOrCreateKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(obj));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));
  return { v: BLOB_VERSION, iv: b64enc(iv), ct: b64enc(ct) };
}

// Returns the decoded JSON on success, or throws on failure. Callers that
// encounter an undecryptable blob MUST NOT silently overwrite it — that would
// erase data the user might still be able to recover. We check the envelope
// version tag explicitly so a future format change can't be silently
// misparsed by old code; unknown versions throw rather than guess.
async function decryptJson(blob) {
  if (!blob || !blob.iv || !blob.ct) throw new Error("history blob malformed");
  if (blob.v !== BLOB_VERSION) {
    throw new Error(`history blob version ${blob.v} is not supported`);
  }
  const key = await getOrCreateKey();
  const iv = b64dec(blob.iv);
  const ct = b64dec(blob.ct);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

// Serialize read-modify-write operations so concurrent add/remove/clear can
// never race and clobber each other's updates.
let chain = Promise.resolve();
function withLock(fn) {
  const next = chain.then(fn, fn);
  chain = next.catch(() => {});
  return next;
}

// Returns { entries, present } where `present` is true iff a blob existed.
// If a blob exists but cannot be decrypted, throws — callers must decide
// whether to surface the error to the user or refuse to write.
async function loadEntriesRaw() {
  const { [STORAGE_BLOB]: blob } = await chrome.storage.local.get(STORAGE_BLOB);
  if (!blob) return { entries: [], present: false };
  const data = await decryptJson(blob);
  if (!data || !Array.isArray(data.entries)) {
    throw new Error("history blob has unexpected shape");
  }
  return { entries: data.entries, present: true };
}

async function saveEntries(entries) {
  const blob = await encryptJson({ v: BLOB_VERSION, entries });
  await chrome.storage.local.set({ [STORAGE_BLOB]: blob });
}

// Cheap structural sanity check on a hostname. We never interpolate this value
// into HTML, but we still don't want arbitrary junk occupying a slot in the
// encrypted store if some upstream bug hands us something unexpected.
function isPlausibleHost(host) {
  if (typeof host !== "string") return false;
  if (host.length === 0 || host.length > 253) return false;
  // Hostname charset per RFC 1123 plus IDNA-decoded dots. URL.hostname lowercases.
  return /^[a-z0-9.\-[\]:]+$/i.test(host);
}

// Add a hostname to the encrypted history.
//
// Trust boundary: this function is only reachable from background.js
// AND only when the user has set keepHistory=true AND only when a DoH
// lookup concluded that the host advertises or uses ECH. Non-ECH sites,
// failed lookups, and skipped URLs never reach this code path.
//
// The function performs NO network I/O. It touches only:
//   * chrome.storage.local[historyBlob] (read + write encrypted bytes)
//   * The in-memory CryptoKey obtained from IDB (use-only, not export)
//
// What we store per entry: ONLY the hostname. No visit count, no
// first-seen / last-seen timestamps, no status — just the bare name.
// Keeping the record minimal means there is less for anything to leak
// and less for a reviewer to worry about. The list is kept in
// insertion order, with re-encountered hosts moved to the end so the
// MAX_ENTRIES cap drops the least-recently-seen hosts first.
export function recordEchHost(host) {
  return withLock(async () => {
    if (!isPlausibleHost(host)) return;
    const { entries } = await loadEntriesRaw();
    // Drop any existing copy, then re-append so this host becomes the
    // most-recent entry. This gives us move-to-end LRU semantics
    // without having to store a timestamp.
    const next = entries.filter((e) => e.host !== host);
    next.push({ host });
    // Cap the list. We drop from the front (oldest), which is
    // least-recently-seen under the move-to-end rule above.
    while (next.length > MAX_ENTRIES) next.shift();
    await saveEntries(next);
  });
}

// Decrypts the blob and returns a copy of the entries for the options
// page to display. Order is newest-first. The decrypted plaintext only
// ever lives in memory inside the service-worker process, and only for
// the duration of this function call plus the structured-clone trip
// across the chrome.runtime message channel to the options page.
export function listEchHosts() {
  return withLock(async () => {
    const { entries } = await loadEntriesRaw();
    // Normalize: tolerate older blobs that may contain extra fields
    // (firstSeen/lastSeen/hits/status from pre-1.1.1 installs) by
    // projecting to just the hostname on the way out.
    return entries.slice().reverse().map((e) => ({ host: e.host }));
  });
}

// Removes a single hostname. The rest of the list is re-encrypted with
// a fresh IV on write, so an observer who had previously snapshotted
// the old ciphertext cannot tell which entry was removed by diffing.
export function removeEchHost(host) {
  return withLock(async () => {
    const { entries } = await loadEntriesRaw();
    const next = entries.filter((e) => e.host !== host);
    await saveEntries(next);
  });
}

// Wipes ALL history. The order matters: first we remove the ciphertext
// blob from chrome.storage.local, then we destroy the key. If that key
// deletion were skipped (or reversed), any leftover ciphertext copy on
// disk might still be readable. With both steps done, even a file-
// system forensic recovery of the old blob yields nothing — the key
// that could decrypt it is gone and the old key was never exportable.
export function clearEchHistory() {
  return withLock(async () => {
    await chrome.storage.local.remove(STORAGE_BLOB);
    await rotateKey();
  });
}
