import { isoCBOR } from "@simplewebauthn/server/helpers";
import { describe, expect, it } from "vitest";
import { encodeCbor, type CborValue } from "../../src/provider/cbor.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** RFC 8949 Appendix A examples (the subset of types the encoder supports). */
const vectors: [CborValue, string][] = [
  [0, "00"],
  [23, "17"],
  [24, "1818"],
  [100, "1864"],
  [1000, "1903e8"],
  [1000000, "1a000f4240"],
  [1000000000000, "1b000000e8d4a51000"],
  [-1, "20"],
  [-10, "29"],
  [-100, "3863"],
  [-1000, "3903e7"],
  [new Uint8Array(0), "40"],
  [Uint8Array.of(1, 2, 3, 4), "4401020304"],
  ["", "60"],
  ["a", "6161"],
  ["IETF", "6449455446"],
  ["ü", "62c3bc"],
  [[], "80"],
  [[1, 2, 3], "83010203"],
  [[1, [2, 3], [4, 5]], "8301820203820405"],
  [new Map([[1, 2], [3, 4]]), "a201020304"],
  [{ a: 1, b: [2, 3] }, "a26161016162820203"],
];

describe("CBOR encoder (RFC 8949 Appendix A)", () => {
  it.each(vectors)("encodes %o as %s", (value, expected) => {
    expect(hex(encodeCbor(value))).toBe(expected);
  });

  it("round-trips through SimpleWebAuthn's independent decoder", () => {
    const value = new Map<number, CborValue>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(32).fill(0xaa)],
    ]);
    const decoded = isoCBOR.decodeFirst<Map<number, unknown>>(encodeCbor(value));
    expect(decoded.get(3)).toBe(-7);
    expect(decoded.get(-2)).toEqual(new Uint8Array(32).fill(0xaa));
  });

  it("rejects non-integer numbers", () => {
    expect(() => encodeCbor(1.5)).toThrow(RangeError);
  });
});
