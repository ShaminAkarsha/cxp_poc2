import type { Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a05: Scenario = {
  ...catalogEntry("A-05"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const request = await world.providerB.importer.createRequest("indirect", { version: 1 });
      const { response } = await world.providerA.exporter.respond(request, "file");
      try {
        const report = await world.providerB.importer.importResponse(response);
        return { id: "A-05", profile: policy.profile, outcome: "succeeded", evidence: `version ${response.version} accepted for request version ${request.version}, imported ${report.imported.length} credential(s)` };
      } catch (err) {
        return { id: "A-05", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
