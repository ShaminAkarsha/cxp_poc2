import { createExportRequest, openExportResponse } from "../../cxp/index.js";
import { getPolicy, type Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a13: Scenario = {
  ...catalogEntry("A-13"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const requestPolicy = policy.profile === "hardened" ? getPolicy("hardened") : undefined;
      const { request, keyring } = await createExportRequest({
        importer: "adversary.example",
        mode: "indirect",
        ...(requestPolicy ? { policy: requestPolicy } : {}),
      });
      try {
        const { response } = await world.providerA.exporter.respond(request, "file");
        const header = await openExportResponse({ request, response, keyring, policy });
        const count = header.accounts[0]?.items.length ?? 0;
        return { id: "A-13", profile: policy.profile, outcome: "succeeded", evidence: `adversary's request served without consent, ${count} credential(s)` };
      } catch (err) {
        return { id: "A-13", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
