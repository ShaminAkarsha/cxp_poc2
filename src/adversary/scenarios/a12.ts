import { readZip } from "../../crypto/archive.js";
import { decodeB64url } from "../../cxf/index.js";
import { DOCUMENTS_DIR } from "../../cxp/index.js";
import { isEnabled, type Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a12: Scenario = {
  ...catalogEntry("A-12"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      await world.rpClient.register(world.providerA.authenticator, "bob", "Bob");
      const request = await world.providerB.importer.createRequest("indirect");
      const { response } = await world.providerA.exporter.respond(request, "file");
      const zip = readZip(decodeB64url(response.payload));
      const docPaths = [...zip.keys()].filter((p) => p.startsWith(DOCUMENTS_DIR));
      const records = world.providerA.vault.list();
      const leaky = records.some((r) => docPaths.includes(`${DOCUMENTS_DIR}${r.itemId}.jwe`));
      if (leaky) {
        return { id: "A-12", profile: policy.profile, outcome: "succeeded", evidence: `file names expose Item IDs: ${docPaths.join(", ")}` };
      }
      if (isEnabled(policy, "randomizeFileNames")) {
        return { id: "A-12", profile: policy.profile, outcome: "reduced", evidence: `file names randomized; ${docPaths.length} file sizes still observable` };
      }
      return { id: "A-12", profile: policy.profile, outcome: "error", evidence: "unexpected: names are not Item IDs and randomization is off" };
    } finally {
      await world.close();
    }
  },
};
