import { createHash, createPublicKey, verify } from "node:crypto";
import { cose, decodeCredentialPublicKey, isoCBOR, parseAuthenticatorData } from "@simplewebauthn/server/helpers";
import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/server";
import { describe, expect, it } from "vitest";
import { decodeB64url, encodeB64url } from "../../src/cxf/b64url.js";
import { SoftwareAuthenticator, WebAuthnClientError, publicKeyOf } from "../../src/provider/authenticator.js";
import { Vault } from "../../src/provider/vault.js";

const ORIGIN = "https://rp.example";
const userId = encodeB64url(new Uint8Array(32).fill(7));

function creationOptions(over: Partial<PublicKeyCredentialCreationOptionsJSON> = {}): PublicKeyCredentialCreationOptionsJSON {
  return {
    rp: { id: "rp.example", name: "RP" },
    user: { id: userId, name: "alice", displayName: "Alice" },
    challenge: encodeB64url(new Uint8Array(32).fill(1)),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    ...over,
  };
}

const fresh = () => new SoftwareAuthenticator(new Vault());

function expectClientError(fn: () => unknown, code: string) {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(WebAuthnClientError);
    expect((err as WebAuthnClientError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

describe("SoftwareAuthenticator.create (WebAuthn L3 §5.1.3, §6.3.2)", () => {
  it("emits a `none` attestation with correct authenticator data", () => {
    const auth = fresh();
    const res = auth.create(creationOptions(), ORIGIN);

    const att = isoCBOR.decodeFirst<Map<string, unknown>>(decodeB64url(res.response.attestationObject));
    expect(att.get("fmt")).toBe("none");
    expect((att.get("attStmt") as Map<string, unknown>).size).toBe(0);

    const parsed = parseAuthenticatorData(att.get("authData") as Uint8Array<ArrayBuffer>);
    expect(Buffer.from(parsed.rpIdHash).equals(createHash("sha256").update("rp.example").digest())).toBe(true);
    expect(parsed.flags).toMatchObject({ up: true, uv: true, be: true, bs: true, at: true, ed: false });
    expect(parsed.counter).toBe(0);
    expect(encodeB64url(parsed.credentialID!)).toBe(res.rawId);

    const clientData = JSON.parse(Buffer.from(res.response.clientDataJSON, "base64url").toString()) as Record<string, unknown>;
    expect(clientData).toEqual({ type: "webauthn.create", challenge: creationOptions().challenge, origin: ORIGIN, crossOrigin: false });
  });

  it("the attested COSE key is the public half of the vault's private key", () => {
    const auth = fresh();
    const res = auth.create(creationOptions(), ORIGIN);
    const att = isoCBOR.decodeFirst<Map<string, unknown>>(decodeB64url(res.response.attestationObject));
    const parsed = parseAuthenticatorData(att.get("authData") as Uint8Array<ArrayBuffer>);
    const coseKey = decodeCredentialPublicKey(parsed.credentialPublicKey!) as unknown as Map<number, unknown>;
    expect(coseKey.get(cose.COSEKEYS.alg)).toBe(-7);

    const jwk = publicKeyOf(auth.vault.list()[0]!).export({ format: "jwk" });
    expect(encodeB64url(coseKey.get(cose.COSEKEYS.x) as Uint8Array)).toBe(jwk.x);
    expect(encodeB64url(coseKey.get(cose.COSEKEYS.y) as Uint8Array)).toBe(jwk.y);
  });

  it("stores the fields a CXF Passkey needs (CXF §3.3.12)", () => {
    const auth = fresh();
    const res = auth.create(creationOptions(), ORIGIN);
    const [record] = auth.vault.list();
    expect(encodeB64url(record!.credentialId)).toBe(res.rawId); // MUST equal rawId
    expect(record!.rpId).toBe("rp.example"); // MUST equal registration RP ID
    expect(encodeB64url(record!.userHandle)).toBe(userId); // MUST equal user.id
    expect(record!.username).toBe("alice");
    expect(record!.userDisplayName).toBe("Alice");
    expect(record!.signCount).toBe(0);
    const pkcs8 = record!.privateKey.export({ format: "der", type: "pkcs8" });
    expect(pkcs8.length).toBeGreaterThan(0);
  });

  it("accepts an RP ID that is a parent domain of the origin host", () => {
    expect(() => fresh().create(creationOptions(), "https://login.rp.example")).not.toThrow();
  });

  it("rejects an RP ID not valid for the origin (SecurityError)", () => {
    expectClientError(() => fresh().create(creationOptions(), "https://evil.example"), "SecurityError");
    expectClientError(() => fresh().create(creationOptions(), "https://notrp.example"), "SecurityError");
  });

  it("rejects a non-secure origin other than localhost (SecurityError)", () => {
    expectClientError(() => fresh().create(creationOptions(), "http://rp.example"), "SecurityError");
  });

  it("rejects when ES256 is not offered (NotSupportedError)", () => {
    const opts = creationOptions({ pubKeyCredParams: [{ type: "public-key", alg: -257 }] });
    expectClientError(() => fresh().create(opts, ORIGIN), "NotSupportedError");
  });

  it("honours excludeCredentials (InvalidStateError)", () => {
    const auth = fresh();
    const first = auth.create(creationOptions(), ORIGIN);
    expectClientError(() => auth.create(creationOptions({ excludeCredentials: [{ id: first.id, type: "public-key" }] }), ORIGIN), "InvalidStateError");
  });

  it("replaces a discoverable credential for the same RP and user", () => {
    const auth = fresh();
    auth.create(creationOptions(), ORIGIN);
    const second = auth.create(creationOptions(), ORIGIN);
    expect(auth.vault.size).toBe(1);
    expect(encodeB64url(auth.vault.list()[0]!.credentialId)).toBe(second.id);
  });
});

describe("SoftwareAuthenticator.get (WebAuthn L3 §5.1.4, §6.3.3)", () => {
  it("produces a valid ES256 signature over authData || SHA-256(clientDataJSON)", () => {
    const auth = fresh();
    auth.create(creationOptions(), ORIGIN);
    const res = auth.get({ challenge: encodeB64url(new Uint8Array(32).fill(2)), rpId: "rp.example" }, ORIGIN);

    const authData = decodeB64url(res.response.authenticatorData);
    const clientHash = createHash("sha256").update(decodeB64url(res.response.clientDataJSON)).digest();
    const ok = verify(
      "sha256",
      Buffer.concat([authData, clientHash]),
      createPublicKey(auth.vault.list()[0]!.privateKey),
      decodeB64url(res.response.signature),
    );
    expect(ok).toBe(true);

    const parsed = parseAuthenticatorData(authData as Uint8Array<ArrayBuffer>);
    expect(parsed.flags).toMatchObject({ up: true, uv: true, be: true, bs: true, at: false });
    expect(parsed.counter).toBe(0);
    expect(res.response.userHandle).toBe(userId);
  });

  it("never increments the signature counter (CXF §3.3.12 note, GAP-17)", () => {
    const auth = fresh();
    auth.create(creationOptions(), ORIGIN);
    for (let i = 0; i < 3; i++) {
      const res = auth.get({ challenge: encodeB64url(Uint8Array.of(i)), rpId: "rp.example" }, ORIGIN);
      expect(parseAuthenticatorData(decodeB64url(res.response.authenticatorData) as Uint8Array<ArrayBuffer>).counter).toBe(0);
    }
  });

  it("filters by allowCredentials and fails with NotAllowedError when nothing matches", () => {
    const auth = fresh();
    auth.create(creationOptions(), ORIGIN);
    expectClientError(
      () => auth.get({ challenge: "AA", rpId: "rp.example", allowCredentials: [{ id: "AAAA", type: "public-key" }] }, ORIGIN),
      "NotAllowedError",
    );
    expectClientError(() => auth.get({ challenge: "AA", rpId: "other.example" }, "https://other.example"), "NotAllowedError");
  });
});
