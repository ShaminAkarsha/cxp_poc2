import type { Policy } from "../../policy/index.js";
import { createWorld, migrate } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a10: Scenario = {
  ...catalogEntry("A-10"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      await migrate(world, "indirect");
      const loginA = await world.rpClient.login(world.providerA.authenticator, "alice");
      const loginB = await world.rpClient.login(world.providerB.authenticator, "alice");
      if (loginA.body.verified === true && loginB.body.verified === true) {
        return { id: "A-10", profile: policy.profile, outcome: "succeeded", evidence: "both source and migrated credential sign in; RP cannot distinguish" };
      }
      return { id: "A-10", profile: policy.profile, outcome: "error", evidence: `login A: ${loginA.body.verified}, login B: ${loginB.body.verified}` };
    } finally {
      await world.close();
    }
  },
};
