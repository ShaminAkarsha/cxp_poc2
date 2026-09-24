import { describe, expect, it } from "vitest";
import { b64urlByteLength, isB64url, isCanonicalB64url } from "../../src/cxf/index.js";

describe("CXF §2.1 b64url", () => {
  it.each(["", "YQ", "YWI", "YWJj", "YQ==", "YWI=", "_-8"])("accepts %j structurally", (s) => {
    expect(isB64url(s)).toBe(true);
  });

  it.each(["Y", "YQ=", "YQ===", "YWJj=", "a+b/", "YQ==YQ", "Y Q", "YWI=="])("rejects %j structurally", (s) => {
    expect(isB64url(s)).toBe(false);
  });

  it("GAP-20: canonical form is unpadded and re-encodes to itself", () => {
    expect(isCanonicalB64url("YQ")).toBe(true);
    expect(isCanonicalB64url("YQ==")).toBe(false); // padded
    expect(isCanonicalB64url("YR")).toBe(false); // non-zero trailing bits decode to the same byte as "YQ"
    expect(b64urlByteLength("YR")).toBe(1);
  });
});
