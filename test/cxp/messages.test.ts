import { describe, expect, it } from "vitest";
import { AEAD, KDF, KEM, MTI_SUITE } from "../../src/crypto/hpke.js";
import {
  correspondingEntry,
  createExportRequest,
  CXP_VERSION,
  CxpValidationError,
  parseExportRequest,
  parseExportRequestJson,
  parseExportResponse,
  selectArchive,
  selectHpkeParameters,
  serializeExportRequest,
  type HpkeParameters,
} from "../../src/cxp/index.js";

const key = { kty: "OKP", crv: "X25519", x: "AAAA" };
const entry = (over: Partial<HpkeParameters> = {}): HpkeParameters => ({ mode: "base", ...MTI_SUITE, key, ...over });
const baseRequest = () => ({ version: 0, hpke: [entry()], archive: ["deflate"], mode: "indirect", importer: "importer.test" });

describe("ExportRequest (CXP §3.2)", () => {
  it("createExportRequest builds a schema-valid request with the importer's public keys", async () => {
    const { request, keyring } = await createExportRequest({ importer: "importer.test", mode: "indirect" });
    expect(parseExportRequest(request)).toEqual(request);
    expect(request.version).toBe(CXP_VERSION); // GAP-24
    expect(request.archive).toEqual(["deflate"]);
    expect(request.hpke.map((h) => [h.mode, h.kem, h.kdf, h.aead])).toEqual([
      ["base", 0x20, 1, 2],
      ["base", 0x10, 1, 1],
    ]);
    expect(request.hpke[0]!.key).toMatchObject({ kty: "OKP", crv: "X25519" });
    expect(request.hpke[1]!.key).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(keyring.kems.sort()).toEqual([0x10, 0x20]);
  });

  it("round-trips as a JSON Export Request file (CXP §3.2.1)", async () => {
    const { request } = await createExportRequest({
      importer: "importer.test",
      mode: "indirect",
      credentialTypes: ["passkey"],
      knownExtensions: [],
    });
    expect(parseExportRequestJson(serializeExportRequest(request))).toEqual(request);
  });

  it("keeps unknown members (GAP-26)", () => {
    expect(parseExportRequest({ ...baseRequest(), challenge: "x" })).toMatchObject({ challenge: "x" });
  });

  it("accepts empty credentialTypes/knownExtensions and a missing key, following the prose (GAP-26)", () => {
    expect(() => parseExportRequest({ ...baseRequest(), credentialTypes: [], knownExtensions: [] })).not.toThrow();
    expect(() => parseExportRequest({ ...baseRequest(), hpke: [{ mode: "psk", ...MTI_SUITE }] })).not.toThrow();
  });

  it.each([
    ["empty hpke ([+ ...])", { hpke: [] }],
    ["empty archive ([+ ...])", { archive: [] }],
    ["version outside uint .size 2", { version: 70000 }],
    ["missing importer", { importer: undefined }],
    ["kem not a number", { hpke: [entry({ kem: "32" as unknown as number })] }],
  ])("rejects %s", (_name, over) => {
    expect(() => parseExportRequest({ ...baseRequest(), ...over })).toThrow(CxpValidationError);
  });

  it("rejects malformed JSON", () => {
    expect(() => parseExportRequestJson("{")).toThrow(CxpValidationError);
  });
});

describe("ExportResponse (CXP §3.3)", () => {
  const response = { version: 0, hpke: entry(), archive: "deflate", exporter: "exporter.test", payload: "UEsDBA" };

  it("parses and requires a b64url payload", () => {
    expect(parseExportResponse(response)).toEqual(response);
    expect(() => parseExportResponse({ ...response, payload: "not base64!" })).toThrow(CxpValidationError);
    expect(() => parseExportResponse({ ...response, hpke: [entry()] })).toThrow(CxpValidationError);
  });
});

describe("exporter negotiation (CXP §3.2, §3.5.1)", () => {
  it("takes the importer's first usable entry", () => {
    const p256 = entry({ kem: KEM.P256_HKDF_SHA256, aead: AEAD.AES_128_GCM });
    expect(selectHpkeParameters([p256, entry()])).toBe(p256);
  });

  it.each([
    ["unknown mode", entry({ mode: "quantum" })],
    ["psk mode (out of scope)", entry({ mode: "psk" })],
    ["auth mode (not a spec-minimal capability)", entry({ mode: "auth" })],
    ["unknown KEM", entry({ kem: 0x0999 })],
    ["unknown KDF", entry({ kdf: 0x0999 })],
    ["ChaCha20-Poly1305 (no JWE mapping, GAP-07)", entry({ aead: AEAD.CHACHA20_POLY1305 })],
    ["missing key", entry({ key: undefined })],
  ])("skips an entry with %s", (_name, bad) => {
    expect(selectHpkeParameters([bad])).toBeUndefined();
    expect(selectHpkeParameters([bad, entry()])).toEqual(entry());
  });

  it("ignores unknown archive values (MUST) and returns undefined when none match", () => {
    expect(selectArchive(["zstd", "deflate"])).toBe("deflate");
    expect(selectArchive(["zstd"])).toBeUndefined();
  });

  it("correspondence = equal mode/kem/kdf/aead, key ignored (GAP-28)", () => {
    const offered = [entry(), entry({ kem: KEM.P256_HKDF_SHA256, kdf: KDF.HKDF_SHA256, aead: AEAD.AES_128_GCM })];
    expect(correspondingEntry(offered, entry({ key: { kty: "OKP", x: "other" } }))).toBe(offered[0]);
    expect(correspondingEntry(offered, entry({ aead: AEAD.AES_128_GCM }))).toBeUndefined();
  });
});
