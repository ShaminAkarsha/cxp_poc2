import { MTI_SUITE } from "../../crypto/hpke.js";
import type { Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a04: Scenario = {
  ...catalogEntry("A-04"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const request = await world.providerB.importer.createRequest("indirect");
      const tampered = { ...request, hpke: request.hpke.filter((e) => e.kem !== MTI_SUITE.kem) };
      if (tampered.hpke.length === 0) {
        return { id: "A-04", profile: policy.profile, outcome: "rejected", evidence: "only the MTI suite was offered; nothing to downgrade" };
      }
      try {
        const { response } = await world.providerA.exporter.respond(tampered, "file");
        const report = await world.providerB.importer.importResponse(response);
        return { id: "A-04", profile: policy.profile, outcome: "succeeded", evidence: `forced non-MTI suite (KEM ${response.hpke.kem}), imported ${report.imported.length} credential(s)` };
      } catch (err) {
        return { id: "A-04", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
