import { describe, expect, it } from "vitest";
import { ArchiveError, createZip, readZip } from "../../src/crypto/archive.js";
import {
  AEAD,
  createCipherSuite,
  generateKeyPair,
  HpkeParameterError,
  isSupportedSuite,
  jwkToPublicKey,
  jwkToPublicKeyBytes,
  KDF,
  KEM,
  MTI_SUITE,
  publicKeyToJwk,
  serializePublicKey,
} from "../../src/crypto/hpke.js";
import { decryptJwe, encryptJwe, JweError, jweEncForAead } from "../../src/crypto/jwe.js";

describe("HPKE suite support", () => {
  it("supports the MTI suite and P-256, not ChaCha20-Poly1305 or unknown ids", () => {
    expect(isSupportedSuite(MTI_SUITE)).toBe(true);
    expect(isSupportedSuite({ kem: KEM.P256_HKDF_SHA256, kdf: KDF.HKDF_SHA256, aead: AEAD.AES_128_GCM })).toBe(true);
    expect(isSupportedSuite({ ...MTI_SUITE, aead: AEAD.CHACHA20_POLY1305 })).toBe(false);
    expect(isSupportedSuite({ ...MTI_SUITE, kem: 0x0011 })).toBe(false);
    expect(isSupportedSuite({ ...MTI_SUITE, kdf: 0x0002 })).toBe(false);
    expect(() => createCipherSuite({ ...MTI_SUITE, kem: 0x9999 })).toThrow(HpkeParameterError);
  });
});

describe.each([
  ["X25519 (RFC 8037 OKP)", KEM.X25519_HKDF_SHA256, { kty: "OKP", crv: "X25519" }],
  ["P-256 (RFC 7518 EC)", KEM.P256_HKDF_SHA256, { kty: "EC", crv: "P-256" }],
] as const)("public key <-> JWK, %s", (_name, kem, shape) => {
  it("round-trips", async () => {
    const { publicKey } = await generateKeyPair(kem);
    const jwk = await publicKeyToJwk(kem, publicKey);
    expect(jwk).toMatchObject(shape);
    const back = await jwkToPublicKey(kem, jwk as Record<string, unknown>);
    expect(await serializePublicKey(kem, back)).toEqual(await serializePublicKey(kem, publicKey));
  });

  it("rejects a JWK for the other KEM, a short coordinate, or padded base64url", async () => {
    const jwk = (await publicKeyToJwk(kem, (await generateKeyPair(kem)).publicKey)) as Record<string, unknown>;
    const other = kem === KEM.X25519_HKDF_SHA256 ? KEM.P256_HKDF_SHA256 : KEM.X25519_HKDF_SHA256;
    expect(() => jwkToPublicKeyBytes(other, jwk)).toThrow(HpkeParameterError);
    expect(() => jwkToPublicKeyBytes(kem, { ...jwk, x: "AAAA" })).toThrow(/bytes/);
    expect(() => jwkToPublicKeyBytes(kem, { ...jwk, x: `${String(jwk.x)}=` })).toThrow(/base64url/);
  });
});

describe("JWE packaging (RFC 7516, GAP-07)", () => {
  const cek = new Uint8Array(32).fill(3);

  it("maps HPKE AEADs to JWE enc", () => {
    expect(jweEncForAead(AEAD.AES_128_GCM)).toBe("A128GCM");
    expect(jweEncForAead(AEAD.AES_256_GCM)).toBe("A256GCM");
    expect(jweEncForAead(AEAD.EXPORT_ONLY)).toBe("A256GCM");
    expect(jweEncForAead(AEAD.CHACHA20_POLY1305)).toBeUndefined();
  });

  it("round-trips as compact JWE with alg dir", async () => {
    const jwe = await encryptJwe(new TextEncoder().encode("secret"), cek, "A256GCM");
    expect(jwe.split(".")).toHaveLength(5);
    expect(jwe.split(".")[1]).toBe(""); // dir: empty encrypted key
    const { plaintext, protectedHeader } = await decryptJwe(jwe, cek, "A256GCM");
    expect(new TextDecoder().decode(plaintext)).toBe("secret");
    expect(protectedHeader).toEqual({ alg: "dir", enc: "A256GCM" });
  });

  it("fails with the wrong key, a tampered tag, or an unexpected enc", async () => {
    const jwe = await encryptJwe(new TextEncoder().encode("secret"), cek, "A256GCM");
    await expect(decryptJwe(jwe, new Uint8Array(32), "A256GCM")).rejects.toThrow(JweError);
    const parts = jwe.split(".");
    parts[4] = parts[4]!.startsWith("A") ? `B${parts[4]!.slice(1)}` : `A${parts[4]!.slice(1)}`;
    await expect(decryptJwe(parts.join("."), cek, "A256GCM")).rejects.toThrow(JweError);
    await expect(decryptJwe(jwe, new Uint8Array(16), "A128GCM")).rejects.toThrow(JweError);
  });

  it("rejects a key of the wrong length", async () => {
    await expect(encryptJwe(new Uint8Array(1), new Uint8Array(16), "A256GCM")).rejects.toThrow(JweError);
  });
});

describe("zip archive (GAP-10, GAP-27)", () => {
  it("round-trips and stores entries with DEFLATE (method 8)", () => {
    const files = new Map([
      ["CXP-Export/index.jwe", new TextEncoder().encode("index".repeat(50))],
      ["CXP-Export/documents/a.jwe", new TextEncoder().encode("doc")],
    ]);
    const zip = createZip(files);
    expect(readZip(zip)).toEqual(files);
    // First local file header: signature PK\x03\x04, compression method at offset 8.
    expect(Buffer.from(zip.subarray(0, 4)).toString("hex")).toBe("504b0304");
    expect(zip[8]).toBe(8);
  });

  it("rejects non-zip input", () => {
    expect(() => readZip(new Uint8Array([1, 2, 3, 4]))).toThrow(ArchiveError);
  });
});
