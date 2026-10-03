import type { Policy } from "../../policy/index.js";
import { ExportingProvider } from "../../provider/exporter.js";
import { ImportingProvider } from "../../provider/importer.js";
import { Vault } from "../../provider/vault.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a20: Scenario = {
  ...catalogEntry("A-20"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const staleNow = () => Math.floor(Date.now() / 1000) - 7200;
      const staleExporter = new ExportingProvider({
        rpId: world.providerA.exporter.config.rpId,
        displayName: "Provider A",
        vault: world.providerA.vault,
        policy,
        account: world.providerA.exporter.config.account,
        now: staleNow,
        approveExport: () => true,
      });
      const testImporter = new ImportingProvider({
        rpId: world.providerB.importer.config.rpId,
        vault: new Vault(),
        policy,
        confirmExporter: () => true,
      });
      const request = await testImporter.createRequest("indirect");
      try {
        const { response } = await staleExporter.respond(request, "file");
        await testImporter.importResponse(response);
        return { id: "A-20", profile: policy.profile, outcome: "succeeded", evidence: "stale CXF document (timestamp 2h old) accepted without freshness check" };
      } catch (err) {
        return { id: "A-20", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
