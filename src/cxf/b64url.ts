/**
 * CXF §2.1: `b64url` is a JSON string holding RFC 4648 URL-safe Base64.
 * Lengths stated in bytes apply to the decoded value.
 *
 * Padding and canonical form are not specified by CXF — GAP-20.
 */

const B64URL_BODY = /^[A-Za-z0-9_-]*$/;

/**
 * Structural check applied in both profiles: base64url alphabet, optional
 * `=` padding, and a length that can encode whole bytes.
 */
export function isB64url(value: string): boolean {
  const padStart = value.indexOf("=");
  const body = padStart === -1 ? value : value.slice(0, padStart);
  const padding = padStart === -1 ? "" : value.slice(padStart);
  if (!B64URL_BODY.test(body)) return false;
  if (body.length % 4 === 1) return false;
  if (padding === "") return true;
  // RFC 4648 §3.2: padding only as needed to reach a multiple of 4.
  return /^={1,2}$/.test(padding) && value.length % 4 === 0 && padding.length === (4 - (body.length % 4)) % 4;
}

export function decodeB64url(value: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

export function encodeB64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** GAP-20 (hardened): unpadded and canonical, i.e. it re-encodes to itself. */
export function isCanonicalB64url(value: string): boolean {
  return isB64url(value) && !value.includes("=") && encodeB64url(decodeB64url(value)) === value;
}

export function b64urlByteLength(value: string): number {
  return Buffer.from(value, "base64url").length;
}
