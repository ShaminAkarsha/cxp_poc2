/**
 * JSON Canonicalization Scheme (RFC 8785) for the JSON values CXP messages
 * contain. Object members are sorted by UTF-16 code units (RFC 8785 §3.2.3,
 * which is JavaScript's default string sort); strings and numbers use the
 * ECMAScript JSON serialisation (§3.2.2), as JSON.stringify does.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JCS: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
  }
  throw new TypeError(`JCS: unsupported type ${typeof value}`);
}
