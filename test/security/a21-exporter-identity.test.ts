/**
 * A-21 / T-RS-02: exporter identity mismatch between CXP envelope and CXF header.
 *
 * The CXP response carries `exporter: "adversary.example"` while the
 * encrypted CXF document says `exporterRpId: "provider-a.example"`.
 * GAP-22 (bindExporterIdentity) should reject the mismatch under hardened.
 *
 * Gaps exercised: GAP-22.
 * spec-minimal: succeeds — no identity binding check.
 * hardened: fails — CXF exporterRpId differs from response exporter (GAP-22).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateKeyPair, MTI_SUITE } from "../../src/crypto/hpke.js";
import { createExportResponse } from "../../src/cxp/response.js";
import { getPolicy, isEnabled, PROFILE_NAMES } from "../../src/policy/index.js";
import { ImportingProvider } from "../../src/provider/importer.js";
import { Vault } from "../../src/provider/vault.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-21 / GAP-22: exporter identity mismatch (CXP vs CXF)", () => {
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
      it("succeeds: identity mismatch accepted without binding check", async () => {
        const testImporter = new ImportingProvider({
          rpId: world.providerB.importer.config.rpId,
          vault: new Vault(),
          policy,
          confirmExporter: () => true,
        });
        const request = await testImporter.createRequest("indirect");
        const { header } = world.providerA.exporter.buildCxf(request);
        const response = await createExportResponse({
          request,
          header,
          exporter: "adversary.example",
          policy,
        });
        const report = await testImporter.importResponse(response);
        expect(report.imported).toHaveLength(1);
        expect(report.exporter).toBe("provider-a.example");
      });
    } else {
      it("fails: exporter identity mismatch rejected (GAP-22)", async () => {
        const testImporter = new ImportingProvider({
          rpId: world.providerB.importer.config.rpId,
          vault: new Vault(),
          policy,
          confirmExporter: () => true,
        });
        const request = await testImporter.createRequest("indirect");
        const { header } = world.providerA.exporter.buildCxf(request);
        const senderKey = isEnabled(policy, "requireHpkeAuthMode")
          ? await generateKeyPair(MTI_SUITE.kem)
          : undefined;
        const response = await createExportResponse({
          request,
          header,
          exporter: "adversary.example",
          policy,
          ...(senderKey ? { senderKey } : {}),
        });
        await expect(
          testImporter.importResponse(response),
        ).rejects.toThrow(/exporterRpId.*differs.*GAP-22/);
      });
    }
  });
});
