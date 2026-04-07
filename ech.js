// HTTPS Resource Record (RFC 9460) parser.
//
// Cloudflare DoH JSON returns rdata for type=65 in one of two forms:
//   1. Generic wire format:  `\# 64 0001000001000C0268330268310003...`
//   2. Presentation format:  `1 . alpn="h3,h2" ipv4hint=1.2.3.4 ech="AEX+..."`
// We handle both and return a single uniform shape:
//   { priority, alpn[], port|null, ipv4[], ipv6[], echLength|null }

const KEY_ALPN = 1, KEY_PORT = 3, KEY_IPV4 = 4, KEY_ECH = 5, KEY_IPV6 = 6;

function emptySummary(priority = 0) {
  return { priority, alpn: [], port: null, ipv4: [], ipv6: [], echLength: null };
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
        if (v.length > 0) out.echLength = v.length;
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
        out.alpn = value.split(",").map(s => s.trim()).filter(Boolean);
        break;
      case "port":
        out.port = parseInt(value, 10) || null;
        break;
      case "ipv4hint":
        out.ipv4 = value.split(",").map(s => s.trim()).filter(Boolean);
        break;
      case "ipv6hint":
        out.ipv6 = value.split(",").map(s => s.trim()).filter(Boolean);
        break;
      case "ech":
        try { out.echLength = atob(value).length; } catch {}
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
