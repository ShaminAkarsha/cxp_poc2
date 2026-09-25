/**
 * M4 exit criterion: `direct` and `indirect` modes work under both profiles.
 * (The RP login with the migrated passkey is M5.)
 */
import { createHash, createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createExportResponse } from "../../src/cxp/index.js";
import { decodeB64url, encodeB64url, isPasskey, parseCxfHeader, type Header } from "../../src/cxf/index.js";
import { createLoopbackTls, type LoopbackTls } from "../../src/crypto/test-ca.js";
import { getPolicy, isEnabled, PROFILE_NAMES, type Policy } from "../../src/policy/index.js";
import { SoftwareAuthenticator } from "../../src/provider/authenticator.js";
import {
  DIRECT_EXPORT_PATH,
  DirectModeError,
  importDirect,
  startExporterService,
  submitDirectRequest,
  type RunningExporterService,
} from "../../src/provider/direct.js";
import { ExportingProvider } from "../../src/provider/exporter.js";
import { ImportingProvider } from "../../src/provider/importer.js";
import { Vault, type StoredPasskey } from "../../src/provider/vault.js";

const ORIGIN = "https://rp.example";
const b64 = (n: number, fill: number) => encodeB64url(new Uint8Array(n).fill(fill));

function register(auth: SoftwareAuthenticator, user: string, fill: number) {
  return auth.create(
    {
      rp: { id: "rp.example", name: "RP" },
      user: { id: b64(32, fill), name: user, displayName: user.toUpperCase() },
      challenge: b64(32, 1),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    },
    ORIGIN,
  );
}

function setup(policy: Policy) {
  const vaultA = new Vault();
  const authA = new SoftwareAuthenticator(vaultA);
  register(authA, "alice", 2);
  register(authA, "bob", 3);
  const vaultB = new Vault();
  // A simulated user who approves when the two providers' fingerprints match (hardened prompts).
  // eslint-disable-next-line prefer-const -- referenced from the exporter's prompt, assigned below
  let importer: ImportingProvider;
  const exporter = new ExportingProvider({
    rpId: "provider-a.example",
    displayName: "Provider A",
    vault: vaultA,
    policy,
    account: { username: "alice", email: "alice@example.test" },
    approveExport: (p) => p.requestFingerprint === undefined || p.requestFingerprint === importer.requestFingerprint,
  });
  importer = new ImportingProvider({
    rpId: "provider-b.example",
    vault: vaultB,
    policy,
    confirmExporter: async (c) => c.fingerprint === (await exporter.keyFingerprint()),
  });
  return { vaultA, authA, exporter, vaultB, importer, authB: new SoftwareAuthenticator(vaultB) };
}

const publicJwk = (r: StoredPasskey) => createPublicKey(r.privateKey).export({ format: "jwk" });

/** Every migrated record matches its source on the fields WebAuthn needs, and can sign for it. */
function expectMigrated(vaultA: Vault, vaultB: Vault, authB: SoftwareAuthenticator) {
  expect(vaultB.size).toBe(vaultA.size);
  for (const source of vaultA.list()) {
    const copy = vaultB.get(source.credentialId)!;
    expect(copy).toBeDefined();
    expect(copy.itemId).toBe(source.itemId);
    expect(copy.rpId).toBe(source.rpId);
    expect(Buffer.from(copy.userHandle).equals(Buffer.from(source.userHandle))).toBe(true);
    expect([copy.username, copy.userDisplayName]).toEqual([source.username, source.userDisplayName]);
    expect(copy.signCount).toBe(0); // CXF §3.3.12 (MUST)
    expect(publicJwk(copy)).toEqual(publicJwk(source)); // CXF §3.3.12 (MUST) same public key
  }
  // Provider B signs; the signature verifies under Provider A's registered public key.
  const target = vaultA.list()[0]!;
  const assertion = authB.get(
    { challenge: b64(32, 9), rpId: "rp.example", allowCredentials: [{ id: encodeB64url(target.credentialId), type: "public-key" }] },
    ORIGIN,
  );
  const signed = Buffer.concat([
    decodeB64url(assertion.response.authenticatorData),
    createHash("sha256").update(decodeB64url(assertion.response.clientDataJSON)).digest(),
  ]);
  expect(verify("sha256", signed, createPublicKey(target.privateKey), decodeB64url(assertion.response.signature))).toBe(true);
}

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cxp-m4-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe.each(PROFILE_NAMES)("exporter CXF construction under %s", (profile) => {
  const policy = getPolicy(profile);

  it("maps vault records to CXF Passkeys that pass strict (GAP-20) validation", () => {
    const { exporter, vaultA } = setup(policy);
    const { header, report } = exporter.buildCxf({ version: 0, hpke: [], archive: [], mode: "indirect", importer: "x" });
    expect(() => parseCxfHeader(header, getPolicy("hardened"))).not.toThrow();
    expect(report).toEqual({ exported: 2, excludedNonZeroCounter: [], excludedByType: 0 });
    const [item] = header.accounts[0]!.items;
    const record = vaultA.list()[0]!;
    expect(item!.id).toBe(record.itemId);
    expect(item!.credentials[0]).toMatchObject({
      type: "passkey",
      credentialId: encodeB64url(record.credentialId),
      rpId: "rp.example",
      username: "alice",
      userHandle: encodeB64url(record.userHandle),
    });
  });

  it("excludes passkeys with a non-zero counter and reports them (CXF §3.3.12 MUST / SHOULD inform)", () => {
    const { exporter, vaultA } = setup(policy);
    const counting = { ...vaultA.list()[0]!, signCount: 5 };
    vaultA.add(counting);
    const { header, report } = exporter.buildCxf({ version: 0, hpke: [], archive: [], mode: "indirect", importer: "x" });
    expect(header.accounts[0]!.items.map((i) => i.id)).not.toContain(counting.itemId);
    expect(report.excludedNonZeroCounter).toEqual([counting.itemId]);
  });

  it.each([
    ["absent: all types", undefined, 2],
    ["listed, unknown values ignored (MUST)", ["passkey", "future-type"], 2],
    ["other types only", ["note"], 0],
    ["empty: Account only, no Collections (MUST)", [], 0],
  ])("credentialTypes %s", (_name, credentialTypes, expected) => {
    const { exporter } = setup(policy);
    const { header } = exporter.buildCxf({
      version: 0, hpke: [], archive: [], mode: "indirect", importer: "x",
      ...(credentialTypes ? { credentialTypes } : {}),
    });
    expect(header.accounts[0]!.items).toHaveLength(expected);
    expect(header.accounts[0]!.collections).toEqual([]);
  });
});

describe.each(PROFILE_NAMES)("indirect mode under %s (CXP §3.2.1, §3.2.2)", (profile) => {
  const policy = getPolicy(profile);

  it("migrates via request and response files", async () => {
    const { vaultA, exporter, vaultB, importer, authB } = setup(policy);
    const requestPath = await importer.writeRequestFile(dir);
    const request = JSON.parse(await readFile(requestPath, "utf8")) as { mode: string; importer: string };
    expect(request).toMatchObject({ mode: "indirect", importer: "provider-b.example" });

    const { responsePath, report } = await exporter.exportToFile(requestPath, dir);
    expect(report.exported).toBe(2);
    const imported = await importer.importResponseFile(responsePath);
    expect(imported).toMatchObject({ exporter: "provider-a.example", replaced: [], skipped: [] });
    expect(imported.imported).toHaveLength(2);
    expectMigrated(vaultA, vaultB, authB);
  });
});

describe.each(PROFILE_NAMES)("direct mode under %s (CXP §3.2.2)", (profile) => {
  const policy = getPolicy(profile);
  let service: RunningExporterService;
  let ctx: ReturnType<typeof setup>;
  let tls: LoopbackTls | undefined;
  const client = () => (tls ? { caPem: tls.caPem } : {});

  beforeEach(async () => {
    ctx = setup(policy);
    // GAP-19 (hardened): HTTPS with a pinned test CA.
    tls = isEnabled(policy, "requireTls") ? await createLoopbackTls() : undefined;
    service = await startExporterService(ctx.exporter, tls ? { tls } : {});
  });
  afterEach(async () => {
    await service.close();
  });

  it("migrates over loopback HTTP", async () => {
    expect(service.url).toMatch(/^https?:\/\/127\.0\.0\.1:/);
    const report = await importDirect(ctx.importer, service.url, client());
    expect(report.imported).toHaveLength(2);
    expectMigrated(ctx.vaultA, ctx.vaultB, ctx.authB);
  });

  it("answers with an error over the same transport (GAP-23)", async () => {
    const request = await ctx.importer.createRequest("direct");
    const submit = (body: unknown) => submitDirectRequest(service.url, body, client());
    await expect(submit({ ...request, hpke: [] })).rejects.toThrow(/400/);
    await expect(submit({ ...request, mode: "indirect" })).rejects.toThrow(DirectModeError);
    await expect(submit({ ...request, mode: "self" })).rejects.toThrow(/self/);
    await expect(submit({ ...request, archive: ["zstd"] })).rejects.toThrow(/archive/);
    if (tls === undefined) {
      const raw = await fetch(new URL(DIRECT_EXPORT_PATH, service.url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{not json",
      });
      expect(raw.status).toBe(400);
    }
  });
});

describe("importer handling", () => {
  const policy = getPolicy("spec-minimal");

  it("imports only passkeys from a mixed CXF document (README §5)", async () => {
    const { importer, vaultB } = setup(policy);
    const request = await importer.createRequest("indirect");
    const appendixA = parseCxfHeader(
      JSON.parse(readFileSync(new URL("../fixtures/cxf-appendix-a.json", import.meta.url), "utf8")),
      policy,
    );
    const response = await createExportResponse({ request, header: appendixA, exporter: "exporter.example.com" });
    const report = await importer.importResponse(response);
    expect(report.imported).toEqual(["akKA3Y0jQRuK7sKplB0Y9w"]);
    expect(report.skipped).toHaveLength(14); // 13 items; GitHub Login holds basic-auth + totp
    expect(report.skipped.every((s) => s.reason === "not-a-passkey")).toBe(true);
    expect(vaultB.list()[0]!.rpId).toBe("webauthn.io");
  });

  it("skips a passkey whose key is not P-256", async () => {
    const { importer, vaultB, exporter } = setup(policy);
    const request = await importer.createRequest("indirect");
    const { header } = exporter.buildCxf(request);
    const ed25519 = generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" });
    const credential = header.accounts[0]!.items[0]!.credentials[0]!;
    if (isPasskey(credential)) credential.key = encodeB64url(ed25519);
    const response = await createExportResponse({ request, header: header as Header, exporter: "provider-a.example" });
    const report = await importer.importResponse(response);
    expect(report.skipped).toEqual([{ itemId: header.accounts[0]!.items[0]!.id, reason: "unsupported-key" }]);
    expect(vaultB.size).toBe(1);
  });
});

/** spec-minimal characterisation; hardened counterparts are M7 (GAP-11, GAP-30, GAP-31). */
describe("spec-minimal import properties", () => {
  const policy = getPolicy("spec-minimal");

  it("the same response file imports twice, replacing the credentials (GAP-11, GAP-30; A-03/A-07 precursor)", async () => {
    const { exporter, importer, vaultB } = setup(policy);
    const requestPath = await importer.writeRequestFile(dir);
    const { responsePath } = await exporter.exportToFile(requestPath, dir);
    const first = await importer.importResponseFile(responsePath);
    const second = await importer.importResponseFile(responsePath);
    expect(second.replaced).toEqual(first.imported);
    expect(vaultB.size).toBe(2);
  });

  it("request and response files stay on disk after import (GAP-31)", async () => {
    const { exporter, importer } = setup(policy);
    const requestPath = await importer.writeRequestFile(dir);
    const { responsePath } = await exporter.exportToFile(requestPath, dir);
    await importer.importResponseFile(responsePath);
    expect(existsSync(requestPath) && existsSync(responsePath)).toBe(true);
  });
});
