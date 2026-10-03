import type { Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import { createMaliciousPasskey, forgeResponse } from "../forge-response.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a07: Scenario = {
  ...catalogEntry("A-07"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const request = await world.providerB.importer.createRequest("indirect");
      const malicious = createMaliciousPasskey("localhost", "mallory");
      const forged = await forgeResponse(request, [malicious]);

      try {
        const report = await world.providerB.importer.importResponse(forged);
        return { id: "A-07", profile: policy.profile, outcome: "succeeded", evidence: `injected ${report.imported.length} credential(s)` };
      } catch (err) {
        return { id: "A-07", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
