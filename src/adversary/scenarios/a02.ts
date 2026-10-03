import { openExportResponse } from "../../cxp/index.js";
import type { Policy } from "../../policy/index.js";
import { startExporterService, submitDirectRequest } from "../../provider/direct.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import { substituteImporterKey } from "../substitute-key.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a02: Scenario = {
  ...catalogEntry("A-02"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      try {
        const service = await startExporterService(world.providerA.exporter);
        try {
          const request = await world.providerB.importer.createRequest("direct");
          const { tampered, adversaryKeyring } = await substituteImporterKey(request);
          const response = await submitDirectRequest(service.url, tampered);
          const header = await openExportResponse({
            request: tampered,
            response,
            keyring: adversaryKeyring,
            policy,
          });
          const count = header.accounts[0]?.items.length ?? 0;
          return { id: "A-02", profile: policy.profile, outcome: "succeeded", evidence: `MITM decrypted ${count} credential(s) via plain HTTP` };
        } finally {
          await service.close();
        }
      } catch (err) {
        return { id: "A-02", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
