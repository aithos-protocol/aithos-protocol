/**
 * Minimal RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
 *
 * Sufficient for the reference CLI. For production, use a heavily tested
 * implementation (e.g. `canonicalize` on npm, which is the one the reference
 * MCP server should pin to). This implementation handles only the subset of
 * JSON that appears in Aithos documents: strings, numbers (integers within
 * Number.MAX_SAFE_INTEGER), booleans, null, arrays, objects.
 *
 * Strings are serialized with the minimal-escape rules of RFC 8785 §3.2.2.
 * Numbers are serialized per ES6 ToString, which matches JCS for safe
 * integers and common fractions but may diverge for pathological floats. The
 * Aithos protocol does not rely on floating-point in any signed field.
 */

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) throw new Error("Cannot canonicalize `undefined`");
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`Cannot canonicalize non-finite number: ${value}`);
    }
    if (Number.isInteger(value) && Math.abs(value) <= Number.MAX_SAFE_INTEGER) {
      return value.toString();
    }
    // Defer to ES6 ToString. Good enough for the Aithos protocol, which does
    // not use floats in any signed field.
    return value.toString();
  }
  if (typeof value === "string") return canonicalizeString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    // RFC 8785 §3.2.3: sort by UTF-16 code units of the keys.
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const body = entries
      .map(([k, v]) => `${canonicalizeString(k)}:${canonicalize(v)}`)
      .join(",");
    return "{" + body + "}";
  }
  throw new Error(`Cannot canonicalize value of type ${typeof value}`);
}

function canonicalizeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    switch (c) {
      case 0x08:
        out += "\\b";
        continue;
      case 0x09:
        out += "\\t";
        continue;
      case 0x0a:
        out += "\\n";
        continue;
      case 0x0c:
        out += "\\f";
        continue;
      case 0x0d:
        out += "\\r";
        continue;
      case 0x22:
        out += '\\"';
        continue;
      case 0x5c:
        out += "\\\\";
        continue;
    }
    if (c < 0x20) {
      out += "\\u" + c.toString(16).padStart(4, "0");
    } else {
      out += s[i];
    }
  }
  return out + '"';
}
