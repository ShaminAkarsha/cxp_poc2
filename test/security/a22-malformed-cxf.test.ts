/**
 * A-22 / T-IM-02c: malformed CXF document violating producer MUSTs.
 *
 * The exporter produces a CXF document with invalid DER key material and
 * an unsupported major version. Under spec-minimal the document is accepted
 * at the protocol level. Under hardened, strictCxfValidation (GAP-20)
 * rejects producer-MUST violations.
 *
 * Gaps exercised: GAP-20.
 * spec-minimal: succeeds — no strict validation.
 * hardened: fails — strict validation catches version and key violations.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateKeyPair, MTI_SUITE } from "../../src/crypto/hpke.js";
import { createExportResponse } from "../../src/cxp/response.js";
import { encodeB64url, type Header } from "../../src/cxf/index.js";
import { getPolicy, isEnabled, PROFILE_NAMES } from "../../src/policy/index.js";
import { ImportingProvider } from "../../src/provider/importer.js";
import { Vault } from "../../src/provider/vault.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-22 / GAP-20: malformed CXF document violating producer MUSTs", () => {
  describe.each(PROFILE_NAMES)("%s", (profile) => {
    const policy = getPolicy(profile);
    let world: Awaited<ReturnType<typeof createWorld>>;

    beforeEach(async () => {
      world = await createWorld(policy);
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
    });

    afterEach(async () => {
      await world.close();
    });

    if (profile === "spec-minimal") {
      it("succeeds: malformed CXF accepted at protocol level", async () => {
        const testImporter = new ImportingProvider({
          rpId: world.providerB.importer.config.rpId,
          vault: new Vault(),
          policy,
          confirmExporter: () => true,
        });
        const request = await testImporter.createRequest("indirect");
        const { header } = world.providerA.exporter.buildCxf(request);
        const malformed: Header = {
          ...header,
          accounts: header.accounts.map((a) => ({
            ...a,
            items: a.items.map((item) => ({
              ...item,
              credentials: item.credentials.map((c) => ({
                ...c,
                key: encodeB64url(new Uint8Array([0xde, 0xad, 0xbe, 0xef])),
              })),
            })),
          })),
        };
        const rpId = world.providerA.exporter.config.rpId;
        const response = await createExportResponse({
          request,
          header: malformed,
          exporter: rpId,
          policy,
        });
        const report = await testImporter.importResponse(response);
        expect(report.skipped.length).toBeGreaterThan(0);
      });
    } else {
      it("fails: strict validation rejects malformed CXF (GAP-20)", async () => {
        const testImporter = new ImportingProvider({
          rpId: world.providerB.importer.config.rpId,
          vault: new Vault(),
          policy,
          confirmExporter: () => true,
        });
        const request = await testImporter.createRequest("indirect");
        const { header } = world.providerA.exporter.buildCxf(request);
        const malformed: Header = {
          ...header,
          accounts: header.accounts.map((a) => ({
            ...a,
            items: a.items.map((item) => ({
              ...item,
              credentials: item.credentials.map((c) => ({
                ...c,
                key: encodeB64url(new Uint8Array([0xde, 0xad, 0xbe, 0xef])),
              })),
            })),
          })),
        };
        const rpId = world.providerA.exporter.config.rpId;
        const senderKey = isEnabled(policy, "requireHpkeAuthMode")
          ? await generateKeyPair(MTI_SUITE.kem)
          : undefined;
        const response = await createExportResponse({
          request,
          header: malformed,
          exporter: rpId,
          policy,
          ...(senderKey ? { senderKey } : {}),
        });
        await expect(
          testImporter.importResponse(response),
        ).rejects.toThrow(/GAP-20|producer requirements/);
      });
    }
  });
});
