/**
 * M1 exit criterion: round-trip against the CXF Appendix A example payload.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { inflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  collectStrictViolations,
  isPasskey,
  parseCxfHeader,
  parseCxfHeaderJson,
  serializeCxfHeader,
  type Passkey,
} from "../../src/cxf/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";

const fixtureText = readFileSync(new URL("../fixtures/cxf-appendix-a.json", import.meta.url), "utf8");
const fixture: unknown = JSON.parse(fixtureText);

describe.each(PROFILE_NAMES)("CXF Appendix A under %s", (profile) => {
  const policy = getPolicy(profile);

  it("parses", () => {
    const header = parseCxfHeaderJson(fixtureText, policy);
    expect(header.version).toEqual({ major: 1, minor: 0 });
    expect(header.exporterRpId).toBe("exporter.example.com");
    expect(header.accounts).toHaveLength(1);
    expect(header.accounts[0]!.items).toHaveLength(14);
    expect(header.accounts[0]!.collections).toHaveLength(1);
  });

  // JSON member order is not significant (RFC 8259 §4); zod re-emits objects
  // in schema key order, so the round trip is compared as JSON values.
  it("round-trips to an identical JSON value", () => {
    const header = parseCxfHeader(fixture, policy);
    expect(JSON.parse(serializeCxfHeader(header))).toEqual(fixture);
  });

  it("keeps non-passkey credentials as opaque objects (README §5)", () => {
    const header = parseCxfHeader(fixture, policy);
    const types = header.accounts[0]!.items.flatMap((i) => i.credentials.map((c) => c.type));
    expect(types).toContain("basic-auth");
    expect(types).toContain("wifi");
    expect(types.filter((t) => t === "passkey")).toHaveLength(1);
  });
});

describe("CXF Appendix A passkey (CXF §3.3.12)", () => {
  const header = parseCxfHeader(fixture, getPolicy("hardened"));
  const passkey = header.accounts[0]!.items.flatMap((i) => i.credentials).find(isPasskey) as Passkey;

  it("has the typed fields", () => {
    expect(passkey.rpId).toBe("webauthn.io");
    expect(passkey.username).toBe("johndoe");
    expect(passkey.fido2Extensions?.hmacCredentials?.algorithm).toBe("hmac-sha256");
    expect(passkey.fido2Extensions?.payments).toBe(true);
  });

  it("key is a PKCS#8 DER P-256 private key from which a public key derives", () => {
    const key = createPrivateKey({ key: Buffer.from(passkey.key, "base64url"), format: "der", type: "pkcs8" });
    expect(key.asymmetricKeyType).toBe("ec");
    expect(key.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
    expect(createPublicKey(key).export({ format: "jwk" }).crv).toBe("P-256");
  });

  it("largeBlob is raw DEFLATE whose size matches the uncompressedSize claim", () => {
    const blob = passkey.fido2Extensions!.largeBlob!;
    expect(inflateRawSync(Buffer.from(blob.data, "base64url")).length).toBe(blob.uncompressedSize);
  });

  it("satisfies every GAP-20 producer check", () => {
    expect(collectStrictViolations(header)).toEqual([]);
  });
});
