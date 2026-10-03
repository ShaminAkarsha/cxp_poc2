import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeB64url } from "../../cxf/b64url.js";
import { parseExportRequestJson } from "../../cxp/index.js";
import type { Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a14: Scenario = {
  ...catalogEntry("A-14"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    const workDir = await mkdtemp(join(tmpdir(), "a14-"));
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");

      // Build the base CXF and inject a password credential to simulate a vault
      // with mixed types. The PoC vault only stores passkeys; a real-world vault
      // would hold passwords, TOTP seeds, etc.
      const probeReq = await world.providerB.importer.createRequest("indirect");
      const { header } = world.providerA.exporter.buildCxf(probeReq);
      const account = header.accounts[0]!;
      const passwordItem = {
        id: encodeB64url(new Uint8Array(randomBytes(16))),
        creationAt: Math.floor(Date.now() / 1000),
        title: "example.com",
        subtitle: "alice@example.com",
        credentials: [{ type: "password", url: "https://example.com", username: "alice" }],
      };
      const mixedItems = [...account.items, passwordItem];
      const withFilter = mixedItems.filter((i) =>
        i.credentials.some((c: { type: string }) => c.type === "passkey"),
      ).length;
      const withoutFilter = mixedItems.length;

      // File-based attack: write request with credentialTypes: ["passkey"],
      // then strip the field so the exporter serves all types.
      const requestPath = await world.providerB.importer.writeRequestFile(workDir, {
        credentialTypes: ["passkey"],
      });
      const original = parseExportRequestJson(await readFile(requestPath, "utf8"));
      const { credentialTypes: _, ...rest } = original as Record<string, unknown>;
      void _;
      await writeFile(requestPath, JSON.stringify(rest));

      try {
        const { report } = await world.providerA.exporter.exportToFile(requestPath, workDir);
        return {
          id: "A-14",
          profile: policy.profile,
          outcome: "succeeded",
          evidence: `scope tampering undetected; passkey-only=${withFilter}, all-types=${withoutFilter}; exporter served ${report.exported} credential(s)`,
        };
      } catch (err) {
        return {
          id: "A-14",
          profile: policy.profile,
          outcome: "rejected",
          evidence: `${err instanceof Error ? err.message : String(err)}`,
        };
      }
    } finally {
      await world.close();
      await rm(workDir, { recursive: true, force: true });
    }
  },
};
