import { generateKeyPair, MTI_SUITE } from "../../crypto/hpke.js";
import { createExportResponse } from "../../cxp/response.js";
import { isEnabled, type Policy } from "../../policy/index.js";
import { ImportingProvider } from "../../provider/importer.js";
import { Vault } from "../../provider/vault.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a17: Scenario = {
  ...catalogEntry("A-17"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const testImporter = new ImportingProvider({
        rpId: world.providerB.importer.config.rpId,
        vault: new Vault(),
        policy,
        confirmExporter: () => true,
      });
      const request = await testImporter.createRequest("indirect");
      const { header } = world.providerA.exporter.buildCxf(request);
      const senderKey = isEnabled(policy, "requireHpkeAuthMode") ? await generateKeyPair(MTI_SUITE.kem) : undefined;
      const response = await createExportResponse({
        request,
        header,
        exporter: "adversary.example",
        policy,
        ...(senderKey ? { senderKey } : {}),
      });
      try {
        await testImporter.importResponse(response);
        return { id: "A-17", profile: policy.profile, outcome: "succeeded", evidence: `CXP exporter="adversary.example" vs CXF exporterRpId="${header.exporterRpId}"; mismatch accepted` };
      } catch (err) {
        return { id: "A-17", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
