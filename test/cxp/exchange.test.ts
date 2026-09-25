/**
 * M3: Export Request -> Export Response -> decrypted CXF, at message level
 * (transport and response modes are M4).
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createZip, readZip } from "../../src/crypto/archive.js";
import { AEAD, generateKeyPair, KDF, KEM, MTI_SUITE } from "../../src/crypto/hpke.js";
import {
  createExportRequest,
  createExportResponse,
  CxpNegotiationError,
  DOCUMENTS_DIR,
  INDEX_PATH,
  openExportResponse,
  parseExportResponse,
  serializeExportResponse,
  type ExportResponse,
} from "../../src/cxp/index.js";
import { decodeB64url, encodeB64url, parseCxfHeader, type Header } from "../../src/cxf/index.js";
import { getPolicy, PROFILE_NAMES, type Policy } from "../../src/policy/index.js";

const fixture: unknown = JSON.parse(
  readFileSync(new URL("../fixtures/cxf-appendix-a.json", import.meta.url), "utf8"),
);
const specMinimal = getPolicy("spec-minimal");
const appendixA = (): Header => parseCxfHeader(fixture, specMinimal);
const itemIds = () => appendixA().accounts[0]!.items.map((i) => i.id);

/** Appendix A's exporterRpId, so the exporter identity matches (GAP-22). */
const EXPORTER = "exporter.example.com";

/**
 * One exchange under `policy`. The exporter has a static key (used in HPKE
 * auth mode under hardened, GAP-14) and the importer's user confirms it.
 */
async function exchange(policy: Policy, suites = [MTI_SUITE]) {
  const senderKey = await generateKeyPair(MTI_SUITE.kem);
  const { request, keyring } = await createExportRequest({ importer: "importer.test", mode: "indirect", suites, policy });
  const response = await createExportResponse({ request, header: appendixA(), exporter: EXPORTER, policy, senderKey });
  const open = (received: unknown, other = keyring) =>
    openExportResponse({ request, response: received, keyring: other, policy, confirmExporter: () => true });
  return { request, keyring, response, open };
}

function withArchive(response: ExportResponse, edit: (files: Map<string, Uint8Array>) => void): ExportResponse {
  const files = readZip(decodeB64url(response.payload));
  edit(files);
  return { ...response, payload: encodeB64url(createZip(files)) };
}

describe.each(PROFILE_NAMES)("export exchange under %s", (profile) => {
  const policy = getPolicy(profile);

  const suites = [
    ["MTI X25519/HKDF-SHA256/AES-256-GCM", MTI_SUITE],
    ["P-256/HKDF-SHA256/AES-128-GCM", { kem: KEM.P256_HKDF_SHA256, kdf: KDF.HKDF_SHA256, aead: AEAD.AES_128_GCM }],
    ["X25519/HKDF-SHA256/export-only", { ...MTI_SUITE, aead: AEAD.EXPORT_ONLY }],
  ] as const;
  // hardened offers only the MTI suite (GAP-02).
  it.each(profile === "hardened" ? suites.slice(0, 1) : suites)("round-trips CXF Appendix A with %s", async (_name, suite) => {
    const { response, open } = await exchange(policy, [suite]);
    // Response travels as a JSON document (CXP §3.3, indirect mode).
    const header = await open(JSON.parse(serializeExportResponse(response)));
    expect(JSON.parse(JSON.stringify(header))).toEqual(fixture);
  });

  it("response carries the selected suite, the chosen archive, and enc as a JWK", async () => {
    const { request, response } = await exchange(policy);
    expect(parseExportResponse(response)).toEqual(response);
    expect(response).toMatchObject({ version: 0, archive: "deflate", exporter: EXPORTER });
    const mode = profile === "hardened" ? "auth" : "base"; // GAP-14
    expect(response.hpke).toMatchObject({ mode, ...MTI_SUITE, key: { kty: "OKP", crv: "X25519" } });
    expect(response.hpke.key).not.toEqual(request.hpke[0]!.key); // enc, not the importer key (GAP-28)
  });

  it("fails for a different importer's keys", async () => {
    const { response, open } = await exchange(policy);
    const other = await createExportRequest({ importer: "other.test", mode: "indirect", suites: [MTI_SUITE], policy });
    await expect(open(response, other.keyring)).rejects.toThrow();
  });

  it("fails when a document's ciphertext is tampered with", async () => {
    const { response, open } = await exchange(policy);
    const tampered = withArchive(response, (files) => {
      const path = [...files.keys()].find((p) => p.startsWith(DOCUMENTS_DIR))!;
      const jwe = new TextDecoder().decode(files.get(path)).split(".");
      jwe[3] = jwe[3]!.startsWith("A") ? `B${jwe[3]!.slice(1)}` : `A${jwe[3]!.slice(1)}`;
      files.set(path, new TextEncoder().encode(jwe.join(".")));
    });
    await expect(open(tampered)).rejects.toThrow(/JWE|manifest/);
  });

  it("rejects hpke that corresponds to no request entry (GAP-28)", async () => {
    const { response, open } = await exchange(policy);
    await expect(open({ ...response, hpke: { ...response.hpke, aead: AEAD.AES_128_GCM } })).rejects.toThrow(CxpNegotiationError);
  });

  it("rejects an archive the importer did not offer (GAP-03, spec-minimal column)", async () => {
    const { response, open } = await exchange(policy);
    await expect(open({ ...response, archive: "zstd" })).rejects.toThrow(CxpNegotiationError);
  });

  it("exporter refuses when nothing is mutually supported", async () => {
    const { request } = await exchange(policy);
    const senderKey = await generateKeyPair(MTI_SUITE.kem);
    const base = { header: appendixA(), exporter: EXPORTER, policy, senderKey };
    await expect(createExportResponse({ ...base, request: { ...request, archive: ["zstd"] } })).rejects.toThrow(CxpNegotiationError);
    await expect(
      createExportResponse({ ...base, request: { ...request, hpke: [{ ...request.hpke[0]!, mode: "psk" }] } }),
    ).rejects.toThrow(CxpNegotiationError);
  });
});

/**
 * Characterisation of spec-minimal payload choices. These are the
 * preconditions later attack scenarios build on; the hardened counterparts
 * (GAP-07/08/09/10 flags) are implemented in M7.
 */
describe("spec-minimal payload properties", () => {
  it("archive layout: index.jwe plus one document per Item, named by CXF Item ID (GAP-08, GAP-10, GAP-18)", async () => {
    const { response } = await exchange(specMinimal);
    const names = [...readZip(decodeB64url(response.payload)).keys()].sort();
    expect(names).toEqual([INDEX_PATH, ...itemIds().map((id) => `${DOCUMENTS_DIR}${id}.jwe`)].sort());
    // A passive observer of the response learns every Item ID (A-12 precondition).
  });

  it("all documents share one key and no path binding, so two documents can be swapped undetected (GAP-07, GAP-09; A-06 precursor)", async () => {
    const { request, keyring, response } = await exchange(specMinimal);
    const [a, b] = [itemIds()[0]!, itemIds()[1]!].map((id) => `${DOCUMENTS_DIR}${id}.jwe`);
    const swapped = withArchive(response, (files) => {
      const docA = files.get(a!)!;
      files.set(a!, files.get(b!)!);
      files.set(b!, docA);
    });
    const header = await openExportResponse({ request, response: swapped, keyring, policy: specMinimal });
    const ids = header.accounts[0]!.items.map((i) => i.id);
    expect(ids.slice(0, 2)).toEqual([itemIds()[1], itemIds()[0]]);
  });

  it("a listed document that is removed is skipped silently (GAP-10; partial import)", async () => {
    const { request, keyring, response } = await exchange(specMinimal);
    const dropped = withArchive(response, (files) => files.delete(`${DOCUMENTS_DIR}${itemIds()[1]}.jwe`));
    const header = await openExportResponse({ request, response: dropped, keyring, policy: specMinimal });
    expect(header.accounts[0]!.items).toHaveLength(itemIds().length - 1);
  });

  it("the same response imports twice (GAP-11; A-03 precursor)", async () => {
    const { request, keyring, response } = await exchange(specMinimal);
    await openExportResponse({ request, response, keyring, policy: specMinimal });
    await expect(openExportResponse({ request, response, keyring, policy: specMinimal })).resolves.toBeDefined();
  });
});
