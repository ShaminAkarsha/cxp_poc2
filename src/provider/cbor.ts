/**
 * Minimal CBOR encoder (RFC 8949) for the structures a WebAuthn
 * authenticator emits: the COSE public key and the attestation object.
 *
 * Maps are written in insertion order; callers pass keys in CTAP2 canonical
 * order (CTAP 2.1 §8, length-first then bytewise). Decoding is left to the
 * relying party library, which gives an independent cross-check in tests.
 */

export type CborValue =
  | number
  | string
  | Uint8Array
  | readonly CborValue[]
  | ReadonlyMap<number | string, CborValue>
  | { readonly [key: string]: CborValue };

const MT_UINT = 0;
const MT_NINT = 1;
const MT_BYTES = 2;
const MT_TEXT = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;

function head(majorType: number, argument: number): Uint8Array {
  if (!Number.isSafeInteger(argument) || argument < 0) throw new RangeError(`bad CBOR argument ${argument}`);
  const mt = majorType << 5;
  if (argument < 24) return Uint8Array.of(mt | argument);
  if (argument <= 0xff) return Uint8Array.of(mt | 24, argument);
  if (argument <= 0xffff) return Uint8Array.of(mt | 25, argument >> 8, argument & 0xff);
  const out = new DataView(new ArrayBuffer(argument <= 0xffffffff ? 5 : 9));
  if (argument <= 0xffffffff) {
    out.setUint8(0, mt | 26);
    out.setUint32(1, argument);
  } else {
    out.setUint8(0, mt | 27);
    out.setBigUint64(1, BigInt(argument));
  }
  return new Uint8Array(out.buffer);
}

function encodeInto(value: CborValue, parts: Uint8Array[]): void {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new RangeError("only safe integers are supported");
    parts.push(value >= 0 ? head(MT_UINT, value) : head(MT_NINT, -1 - value));
  } else if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    parts.push(head(MT_TEXT, bytes.length), bytes);
  } else if (value instanceof Uint8Array) {
    parts.push(head(MT_BYTES, value.length), value);
  } else if (Array.isArray(value)) {
    parts.push(head(MT_ARRAY, value.length));
    for (const v of value as readonly CborValue[]) encodeInto(v, parts);
  } else {
    const entries: [number | string, CborValue][] =
      value instanceof Map ? [...value.entries()] : Object.entries(value);
    parts.push(head(MT_MAP, entries.length));
    for (const [k, v] of entries) {
      encodeInto(k, parts);
      encodeInto(v, parts);
    }
  }
}

export function encodeCbor(value: CborValue): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [];
  encodeInto(value, parts);
  return concatBytes(...parts);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
