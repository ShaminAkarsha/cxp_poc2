import { isEnabled, type Policy } from "../../policy/index.js";
import { createWorld, migrate } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a09: Scenario = {
  ...catalogEntry("A-09"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      await migrate(world, "indirect");
      const record = world.providerB.vault.list()[0];
      if (!record || record.privateKey.type !== "private") {
        return { id: "A-09", profile: policy.profile, outcome: "error", evidence: "imported key is not usable" };
      }
      if (isEnabled(policy, "zeroizeKeyMaterial")) {
        return { id: "A-09", profile: policy.profile, outcome: "reduced", evidence: "DER buffers zeroed; base64url strings persist until GC" };
      }
      return { id: "A-09", profile: policy.profile, outcome: "succeeded", evidence: "key material not zeroed after import" };
    } finally {
      await world.close();
    }
  },
};
