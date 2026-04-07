// WhereECH — encrypted ECH-site history.
//
// Privacy design:
//   * Opt-in. The caller only records a host after it has been confirmed to
//     advertise ECH, and only while the user has turned this feature on.
//   * Stored as an AES-GCM ciphertext blob in chrome.storage.local. Anyone
//     reading the extension's on-disk profile data sees only opaque bytes.
//   * The key is an AES-GCM 256 CryptoKey created with extractable:false and
//     persisted in IndexedDB. IDB is origin-isolated to this extension, and
//     because the key is non-extractable no JavaScript — not even code running
//     inside the extension — can read its raw bytes; it can only be used via
//     SubtleCrypto.encrypt/decrypt.
//   * "Clear all" deletes the blob AND rotates the key so any leftover copies
//     of the old ciphertext (e.g. in filesystem snapshots) become permanently
//     undecryptable.

const IDB_NAME = "whereech-keys";
const IDB_STORE = "keys";
const IDB_KEY_ID = "master";
const STORAGE_BLOB = "historyBlob";
const MAX_ENTRIES = 5000;

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

async function getOrCreateKey() {
  const existing = await idbGet(IDB_KEY_ID);
  if (existing) return existing;
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false, // non-extractable — cannot be exported by any JS
    ["encrypt", "decrypt"]
  );
  await idbPut(IDB_KEY_ID, key);
  return key;
}

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

async function encryptJson(obj) {
  const key = await getOrCreateKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(obj));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));
  return { v: 1, iv: b64enc(iv), ct: b64enc(ct) };
}

// Returns the decoded JSON on success, or throws on failure. Callers that
// encounter an undecryptable blob MUST NOT silently overwrite it — that would
// erase data the user might still be able to recover.
async function decryptJson(blob) {
  if (!blob || !blob.iv || !blob.ct) throw new Error("history blob malformed");
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
  const blob = await encryptJson({ v: 1, entries });
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

export function recordEchHost(host, status) {
  return withLock(async () => {
    if (!isPlausibleHost(host)) return;
    const { entries } = await loadEntriesRaw();
    const now = Date.now();
    const existing = entries.find((e) => e.host === host);
    if (existing) {
      existing.lastSeen = now;
      existing.hits = (existing.hits || 1) + 1;
      if (status) existing.status = status;
    } else {
      entries.push({ host, firstSeen: now, lastSeen: now, hits: 1, status: status || "advertised" });
      if (entries.length > MAX_ENTRIES) {
        entries.sort((a, b) => b.lastSeen - a.lastSeen);
        entries.length = MAX_ENTRIES;
      }
    }
    await saveEntries(entries);
  });
}

export function listEchHosts() {
  return withLock(async () => {
    const { entries } = await loadEntriesRaw();
    return entries.slice().sort((a, b) => b.lastSeen - a.lastSeen);
  });
}

export function removeEchHost(host) {
  return withLock(async () => {
    const { entries } = await loadEntriesRaw();
    const next = entries.filter((e) => e.host !== host);
    await saveEntries(next);
  });
}

export function clearEchHistory() {
  return withLock(async () => {
    await chrome.storage.local.remove(STORAGE_BLOB);
    await rotateKey();
  });
}
