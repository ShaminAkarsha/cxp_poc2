import { readZip } from "../../crypto/archive.js";
import { decodeB64url } from "../../cxf/index.js";
import { DOCUMENTS_DIR } from "../../cxp/index.js";
import type { Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import { swapArchiveDocuments } from "../swap-files.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a06: Scenario = {
  ...catalogEntry("A-06"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      await world.rpClient.register(world.providerA.authenticator, "bob", "Bob");
      const request = await world.providerB.importer.createRequest("indirect");
      const { response } = await world.providerA.exporter.respond(request, "file");

      const files = readZip(decodeB64url(response.payload));
      const docPaths = [...files.keys()].filter((p) => p.startsWith(DOCUMENTS_DIR)).sort();
      const [pathA, pathB] = docPaths;
      if (pathA === undefined || pathB === undefined) {
        return { id: "A-06", profile: policy.profile, outcome: "error", evidence: "fewer than 2 documents in archive" };
      }
      const tampered = swapArchiveDocuments(response, pathA, pathB);

      try {
        const report = await world.providerB.importer.importResponse(tampered);
        return { id: "A-06", profile: policy.profile, outcome: "succeeded", evidence: `swapped archive imported ${report.imported.length} credential(s)` };
      } catch (err) {
        return { id: "A-06", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
