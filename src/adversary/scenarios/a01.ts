import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openExportResponse, parseExportRequestJson } from "../../cxp/index.js";
import type { Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import { substituteImporterKey } from "../substitute-key.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a01: Scenario = {
  ...catalogEntry("A-01"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    const workDir = await mkdtemp(join(tmpdir(), "a01-"));
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const requestPath = await world.providerB.importer.writeRequestFile(workDir);
      const originalRequest = parseExportRequestJson(await readFile(requestPath, "utf8"));
      const { tampered, adversaryKeyring } = await substituteImporterKey(originalRequest);
      await writeFile(requestPath, JSON.stringify(tampered));

      try {
        const { response } = await world.providerA.exporter.exportToFile(requestPath, workDir);
        const header = await openExportResponse({
          request: tampered,
          response,
          keyring: adversaryKeyring,
          policy,
        });
        const count = header.accounts[0]?.items.length ?? 0;
        return { id: "A-01", profile: policy.profile, outcome: "succeeded", evidence: `adversary decrypted ${count} credential(s)` };
      } catch (err) {
        return { id: "A-01", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
      await rm(workDir, { recursive: true, force: true });
    }
  },
};
