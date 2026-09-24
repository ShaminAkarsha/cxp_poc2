/**
 * M3: Export Request -> Export Response -> decrypted CXF, at message level
 * (transport and response modes are M4).
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createZip, readZip } from "../../src/crypto/archive.js";
import { AEAD, KDF, KEM, MTI_SUITE } from "../../src/crypto/hpke.js";
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
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";

const fixture: unknown = JSON.parse(
  readFileSync(new URL("../fixtures/cxf-appendix-a.json", import.meta.url), "utf8"),
);
const specMinimal = getPolicy("spec-minimal");
const appendixA = (): Header => parseCxfHeader(fixture, specMinimal);
const itemIds = () => appendixA().accounts[0]!.items.map((i) => i.id);

async function exchange(suites = [MTI_SUITE]) {
  const { request, keyring } = await createExportRequest({ importer: "importer.test", mode: "indirect", suites });
  const response = await createExportResponse({ request, header: appendixA(), exporter: "exporter.test" });
  return { request, keyring, response };
}

function withArchive(response: ExportResponse, edit: (files: Map<string, Uint8Array>) => void): ExportResponse {
  const files = readZip(decodeB64url(response.payload));
  edit(files);
  return { ...response, payload: encodeB64url(createZip(files)) };
}

describe.each(PROFILE_NAMES)("export exchange under %s", (profile) => {
  const policy = getPolicy(profile);

  it.each([
    ["MTI X25519/HKDF-SHA256/AES-256-GCM", MTI_SUITE],
    ["P-256/HKDF-SHA256/AES-128-GCM", { kem: KEM.P256_HKDF_SHA256, kdf: KDF.HKDF_SHA256, aead: AEAD.AES_128_GCM }],
    ["X25519/HKDF-SHA256/export-only", { ...MTI_SUITE, aead: AEAD.EXPORT_ONLY }],
  ])("round-trips CXF Appendix A with %s", async (_name, suite) => {
    const { request, keyring, response } = await exchange([suite]);
    // Response travels as a JSON document (CXP §3.3, indirect mode).
    const received: unknown = JSON.parse(serializeExportResponse(response));
    const header = await openExportResponse({ request, response: received, keyring, policy });
    expect(JSON.parse(JSON.stringify(header))).toEqual(fixture);
  });

  it("response carries the selected suite, the chosen archive, and enc as a JWK", async () => {
    const { request, response } = await exchange();
    expect(parseExportResponse(response)).toEqual(response);
    expect(response).toMatchObject({ version: 0, archive: "deflate", exporter: "exporter.test" });
    expect(response.hpke).toMatchObject({ mode: "base", ...MTI_SUITE, key: { kty: "OKP", crv: "X25519" } });
    expect(response.hpke.key).not.toEqual(request.hpke[0]!.key); // enc, not the importer key (GAP-28)
  });

  it("fails for a different importer's keys", async () => {
    const { request, response } = await exchange();
    const other = await createExportRequest({ importer: "other.test", mode: "indirect", suites: [MTI_SUITE] });
    await expect(openExportResponse({ request, response, keyring: other.keyring, policy })).rejects.toThrow();
  });

  it("fails when a document's ciphertext is tampered with", async () => {
    const { request, keyring, response } = await exchange();
    const tampered = withArchive(response, (files) => {
      const path = `${DOCUMENTS_DIR}${itemIds()[1]}.jwe`;
      const jwe = new TextDecoder().decode(files.get(path)).split(".");
      jwe[3] = jwe[3]!.startsWith("A") ? `B${jwe[3]!.slice(1)}` : `A${jwe[3]!.slice(1)}`;
      files.set(path, new TextEncoder().encode(jwe.join(".")));
    });
    await expect(openExportResponse({ request, response: tampered, keyring, policy })).rejects.toThrow(/JWE/);
  });

  it("rejects hpke that corresponds to no request entry (GAP-28)", async () => {
    const { request, keyring, response } = await exchange();
    const bad = { ...response, hpke: { ...response.hpke, aead: AEAD.AES_128_GCM } };
    await expect(openExportResponse({ request, response: bad, keyring, policy })).rejects.toThrow(CxpNegotiationError);
  });

  it("rejects an archive the importer did not offer (GAP-03, spec-minimal column)", async () => {
    const { request, keyring, response } = await exchange();
    await expect(
      openExportResponse({ request, response: { ...response, archive: "zstd" }, keyring, policy }),
    ).rejects.toThrow(CxpNegotiationError);
  });

  it("exporter refuses when nothing is mutually supported", async () => {
    const { request } = await exchange();
    await expect(
      createExportResponse({ request: { ...request, archive: ["zstd"] }, header: appendixA(), exporter: "e" }),
    ).rejects.toThrow(CxpNegotiationError);
    await expect(
      createExportResponse({ request: { ...request, hpke: [{ ...request.hpke[0]!, mode: "psk" }] }, header: appendixA(), exporter: "e" }),
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
    const { response } = await exchange();
    const names = [...readZip(decodeB64url(response.payload)).keys()].sort();
    expect(names).toEqual([INDEX_PATH, ...itemIds().map((id) => `${DOCUMENTS_DIR}${id}.jwe`)].sort());
    // A passive observer of the response learns every Item ID (A-12 precondition).
  });

  it("all documents share one key and no path binding, so two documents can be swapped undetected (GAP-07, GAP-09; A-06 precursor)", async () => {
    const { request, keyring, response } = await exchange();
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
    const { request, keyring, response } = await exchange();
    const dropped = withArchive(response, (files) => files.delete(`${DOCUMENTS_DIR}${itemIds()[1]}.jwe`));
    const header = await openExportResponse({ request, response: dropped, keyring, policy: specMinimal });
    expect(header.accounts[0]!.items).toHaveLength(itemIds().length - 1);
  });

  it("the same response imports twice (GAP-11; A-03 precursor)", async () => {
    const { request, keyring, response } = await exchange();
    await openExportResponse({ request, response, keyring, policy: specMinimal });
    await expect(openExportResponse({ request, response, keyring, policy: specMinimal })).resolves.toBeDefined();
  });
});
