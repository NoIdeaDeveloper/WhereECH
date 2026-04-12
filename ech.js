// HTTPS Resource Record (RFC 9460) parser.
//
// What this file is:
//   A pure, self-contained parser. It takes a string (the DNS record
//   data that came back from the DoH resolver) and returns a structured
//   summary. That's it.
//
// What this file does NOT do:
//   * No network I/O. It never makes a fetch, XHR, or WebSocket call.
//   * No storage access. It does not touch chrome.storage, IndexedDB,
//     localStorage, cookies, or anything else persistent.
//   * No access to tabs, URLs, the DOM, or any other browser data.
//   * No use of eval, Function, innerHTML, or any dynamic code path.
//   * No regex or string operation that can reach outside the input
//     string it was handed.
//
// The only inputs this code ever sees are strings that background.js
// already fetched from your chosen DoH resolver. Worst case for this
// file is a malformed input, for which all code paths return null or
// a partial object — there are no unbounded loops, all byte reads are
// length-checked, and DNS compression pointers are explicitly refused
// to prevent any chance of walking outside the buffer.
//
// Cloudflare DoH JSON returns rdata for type=65 in one of two forms:
//   1. Generic wire format:  `\# 64 0001000001000C0268330268310003...`
//   2. Presentation format:  `1 . alpn="h3,h2" ipv4hint=1.2.3.4 ech="AEX+..."`
// We handle both and return a single uniform shape:
//   { priority, alpn[], port|null, ipv4[], ipv6[], echLength|null, echPublicName|null }
//
// echPublicName is the "outer SNI" — the hostname the browser sends to
// the network during the TLS handshake while the real hostname stays
// encrypted. Cloudflare always uses "cloudflare-ech.com". A site
// self-hosting ECH will use its own domain or a different provider's.

const KEY_ALPN = 1, KEY_PORT = 3, KEY_IPV4 = 4, KEY_ECH = 5, KEY_IPV6 = 6;

function emptySummary(priority = 0) {
  return { priority, alpn: [], port: null, ipv4: [], ipv6: [], echLength: null, echPublicName: null };
}

// Parse an ECHConfigList (RFC 9460 §4) and return the public_name of the
// first recognisable ECHConfig entry, or null on any failure. The public_name
// is the outer SNI — what the network actually sees — while the real hostname
// stays encrypted inside the ECH extension. We only need the first entry
// because all entries in a well-formed list share the same public_name.
//
// ECHConfigList wire layout:
//   uint16  list_length   (total bytes of what follows)
//   ECHConfig[] {
//     uint16  version       (0xfe0d for RFC 9460)
//     uint16  entry_length  (bytes of contents, skip if version unknown)
//     // if version == 0xfe0d:
//     uint8   config_id
//     uint16  kem_id
//     uint16  public_key_length  + public_key bytes
//     uint16  cipher_suites_length + cipher_suite bytes
//     uint8   maximum_name_length
//     uint8   public_name_length  + public_name bytes   ← we want this
//     uint16  extensions_length   + extension bytes
//   }
function parseEchConfigListPublicName(bytes) {
  if (bytes.length < 2) return null;
  const listLen = (bytes[0] << 8) | bytes[1];
  if (listLen + 2 > bytes.length) return null;

  let off = 2;
  const end = 2 + listLen;
  while (off + 4 <= end) {
    const version = (bytes[off] << 8) | bytes[off + 1];
    const entryLen = (bytes[off + 2] << 8) | bytes[off + 3];
    off += 4;
    if (off + entryLen > end) break;
    const entryEnd = off + entryLen;

    if (version === 0xfe0d) {
      const name = readEchPublicName(bytes, off, entryEnd);
      if (name) return name;
    }
    off = entryEnd; // skip unknown version or failed parse
  }
  return null;
}

// Walks bytes[off..end) following the ECHConfigContents field layout
// (RFC 9460 §4) to locate and return the public_name string. Returns
// null if any length check fails, keeping the caller safe against
// malformed or deliberately crafted inputs.
function readEchPublicName(bytes, off, end) {
  if (off + 1 > end) return null;
  off += 1; // config_id (uint8)

  if (off + 2 > end) return null;
  off += 2; // kem_id (uint16)

  if (off + 2 > end) return null;
  const pkLen = (bytes[off] << 8) | bytes[off + 1];
  off += 2;
  if (off + pkLen > end) return null;
  off += pkLen; // public_key

  if (off + 2 > end) return null;
  const csLen = (bytes[off] << 8) | bytes[off + 1];
  off += 2;
  if (off + csLen > end) return null;
  off += csLen; // cipher_suites

  if (off + 1 > end) return null;
  off += 1; // maximum_name_length (uint8)

  if (off + 1 > end) return null;
  const nameLen = bytes[off];
  off += 1;
  if (nameLen === 0 || off + nameLen > end) return null;
  return new TextDecoder().decode(bytes.subarray(off, off + nameLen));
}

function parseWire(data) {
  const m = data.match(/^\\#\s*\d+\s*([0-9a-fA-F\s]+)$/);
  if (!m) return null;
  const hex = m[1].replace(/\s+/g, "");
  if (hex.length % 2 !== 0) return null;
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  if (b.length < 3) return null;

  const out = emptySummary((b[0] << 8) | b[1]);

  // Skip TargetName: length-prefixed labels ending in 0.
  let off = 2;
  while (off < b.length) {
    const len = b[off];
    if (len === 0) { off++; break; }
    if ((len & 0xC0) !== 0) return null;
    off += 1 + len;
    if (off > b.length) return null;
  }

  while (off + 4 <= b.length) {
    const key = (b[off] << 8) | b[off + 1];
    const len = (b[off + 2] << 8) | b[off + 3];
    off += 4;
    if (off + len > b.length) break;
    const v = b.subarray(off, off + len);
    off += len;
    switch (key) {
      case KEY_ALPN: {
        let p = 0;
        while (p < v.length) {
          const n = v[p++];
          if (p + n > v.length) break;
          out.alpn.push(new TextDecoder().decode(v.subarray(p, p + n)));
          p += n;
        }
        break;
      }
      case KEY_PORT:
        if (v.length >= 2) out.port = (v[0] << 8) | v[1];
        break;
      case KEY_IPV4:
        for (let i = 0; i + 4 <= v.length; i += 4) {
          out.ipv4.push(`${v[i]}.${v[i+1]}.${v[i+2]}.${v[i+3]}`);
        }
        break;
      case KEY_IPV6:
        for (let i = 0; i + 16 <= v.length; i += 16) {
          const parts = [];
          for (let j = 0; j < 16; j += 2) parts.push(((v[i+j] << 8) | v[i+j+1]).toString(16));
          out.ipv6.push(parts.join(":"));
        }
        break;
      case KEY_ECH:
        if (v.length > 0) {
          out.echLength = v.length;
          out.echPublicName = parseEchConfigListPublicName(v);
        }
        break;
    }
  }
  return out;
}

function parsePresentation(data) {
  // Tokenize, respecting double-quoted strings.
  const tokens = [];
  let i = 0;
  while (i < data.length) {
    while (i < data.length && /\s/.test(data[i])) i++;
    if (i >= data.length) break;
    if (data[i] === '"') {
      const j = data.indexOf('"', ++i);
      if (j === -1) { tokens.push(data.slice(i)); break; }
      tokens.push(data.slice(i, j));
      i = j + 1;
    } else {
      let j = i;
      while (j < data.length && !/\s/.test(data[j])) j++;
      tokens.push(data.slice(i, j));
      i = j;
    }
  }
  if (tokens.length < 2) return null;
  const priority = parseInt(tokens[0], 10);
  if (!Number.isFinite(priority)) return null;

  const out = emptySummary(priority);
  for (let k = 2; k < tokens.length; k++) {
    const tok = tokens[k];
    const eq = tok.indexOf("=");
    const name = eq === -1 ? tok : tok.slice(0, eq);
    const value = eq === -1 ? "" : tok.slice(eq + 1).replace(/^"|"$/g, "");
    switch (name) {
      case "alpn":
        out.alpn = value.split(",").map(s => s.trim()).filter(Boolean).slice(0, 20);
        break;
      case "port":
        out.port = parseInt(value, 10) || null;
        break;
      case "ipv4hint":
        out.ipv4 = value.split(",").map(s => s.trim()).filter(Boolean).slice(0, 16);
        break;
      case "ipv6hint":
        out.ipv6 = value.split(",").map(s => s.trim()).filter(Boolean).slice(0, 16);
        break;
      case "ech":
        try {
          const raw = atob(value);
          const u8 = new Uint8Array(raw.length);
          for (let i = 0; i < raw.length; i++) u8[i] = raw.charCodeAt(i);
          out.echLength = u8.length;
          out.echPublicName = parseEchConfigListPublicName(u8);
        } catch {}
        break;
    }
  }
  return out;
}

export function parseHttpsRr(data) {
  if (typeof data !== "string") return null;
  const trimmed = data.trim();
  return trimmed.startsWith("\\#") ? parseWire(trimmed) : parsePresentation(trimmed);
}
