/**
 * A-16 / T-RS-01a: stale CXF document accepted without freshness check.
 *
 * The exporter produces a CXF document with a timestamp 2 hours in the past.
 * GAP-21 (enforceTimestampFreshness) should reject it under hardened.
 *
 * Gaps exercised: GAP-21.
 * spec-minimal: succeeds — no timestamp freshness check.
 * hardened: fails — CXF document predates the Export Request (GAP-21).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { ExportingProvider } from "../../src/provider/exporter.js";
import { ImportingProvider } from "../../src/provider/importer.js";
import { Vault } from "../../src/provider/vault.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-16 / GAP-21: stale CXF document accepted without freshness check", () => {
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
      it("succeeds: stale document (2h old) accepted without freshness check", async () => {
        const staleExporter = new ExportingProvider({
          rpId: world.providerA.exporter.config.rpId,
          displayName: "Provider A",
          vault: world.providerA.vault,
          policy,
          account: world.providerA.exporter.config.account,
          now: () => Math.floor(Date.now() / 1000) - 7200,
          approveExport: () => true,
        });
        const testImporter = new ImportingProvider({
          rpId: world.providerB.importer.config.rpId,
          vault: new Vault(),
          policy,
          confirmExporter: () => true,
        });
        const request = await testImporter.createRequest("indirect");
        const { response } = await staleExporter.respond(request, "file");
        const report = await testImporter.importResponse(response);
        expect(report.imported).toHaveLength(1);
      });
    } else {
      it("fails: stale timestamp rejected by freshness check (GAP-21)", async () => {
        const staleExporter = new ExportingProvider({
          rpId: world.providerA.exporter.config.rpId,
          displayName: "Provider A",
          vault: world.providerA.vault,
          policy,
          account: world.providerA.exporter.config.account,
          now: () => Math.floor(Date.now() / 1000) - 7200,
          approveExport: () => true,
        });
        const testImporter = new ImportingProvider({
          rpId: world.providerB.importer.config.rpId,
          vault: new Vault(),
          policy,
          confirmExporter: () => true,
        });
        const request = await testImporter.createRequest("indirect");
        const { response } = await staleExporter.respond(request, "file");
        await expect(
          testImporter.importResponse(response),
        ).rejects.toThrow(/predates.*Export Request.*GAP-21/);
      });
    }
  });
});
