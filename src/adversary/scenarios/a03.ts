import type { Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a03: Scenario = {
  ...catalogEntry("A-03"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const request = await world.providerB.importer.createRequest("indirect");
      const { response } = await world.providerA.exporter.respond(request, "file");
      await world.providerB.importer.importResponse(response);

      try {
        const replay = await world.providerB.importer.importResponse(response);
        return { id: "A-03", profile: policy.profile, outcome: "succeeded", evidence: `replay imported ${replay.imported.length} credential(s), replaced ${replay.replaced.length}` };
      } catch (err) {
        return { id: "A-03", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
