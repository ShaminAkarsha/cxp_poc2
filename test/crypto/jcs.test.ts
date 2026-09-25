import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/crypto/jcs.js";

describe("RFC 8785 JSON canonicalization", () => {
  it("sorts members by UTF-16 code units (RFC 8785 §3.2.3 example)", () => {
    const input = {
      "\u20ac": "Euro Sign",
      "\r": "Carriage Return",
      "\ufb33": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "\ud83d\ude00": "Emoji: Grinning Face",
      "\u0080": "Control",
      "\u00f6": "Latin Small Letter O With Diaeresis",
    };
    const keys = Object.keys(JSON.parse(canonicalize(input)) as object);
    expect(canonicalize(input)).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis",' +
        '"\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}',
    );
    expect(keys).toHaveLength(7);
  });

  it("is independent of member order and whitespace, and recurses", () => {
    expect(canonicalize({ b: [3, { y: 1, x: true }], a: null })).toBe('{"a":null,"b":[3,{"x":true,"y":1}]}');
    expect(canonicalize({ a: null, b: [3, { x: true, y: 1 }] })).toBe(canonicalize({ b: [3, { y: 1, x: true }], a: null }));
  });

  it("serialises numbers as ECMAScript does and rejects non-finite ones", () => {
    expect(canonicalize([0, -0, 1e21, 1.5, 65535])).toBe("[0,0,1e+21,1.5,65535]");
    expect(() => canonicalize(Number.NaN)).toThrow(TypeError);
  });
});
