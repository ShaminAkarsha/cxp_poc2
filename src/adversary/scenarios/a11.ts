import type { Passkey } from "../../cxf/index.js";
import type { Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a11: Scenario = {
  ...catalogEntry("A-11"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const req1 = await world.providerB.importer.createRequest("indirect");
      const cxf1 = world.providerA.exporter.buildCxf(req1);
      const req2 = await world.providerB.importer.createRequest("indirect");
      const cxf2 = world.providerA.exporter.buildCxf(req2);
      const pk1 = cxf1.header.accounts[0]?.items[0]?.credentials[0] as Passkey | undefined;
      const pk2 = cxf2.header.accounts[0]?.items[0]?.credentials[0] as Passkey | undefined;
      if (pk1 && pk2 && pk1.key === pk2.key) {
        return { id: "A-11", profile: policy.profile, outcome: "succeeded", evidence: "identical PKCS#8 key material across exports; hmacCredentials would also be copied verbatim (CXF §3.3.12.3)" };
      }
      return { id: "A-11", profile: policy.profile, outcome: "error", evidence: "key material differs across exports" };
    } finally {
      await world.close();
    }
  },
};
