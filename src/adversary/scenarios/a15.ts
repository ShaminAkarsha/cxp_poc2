import { generateKeyPairSync, randomBytes } from "node:crypto";
import type { Policy } from "../../policy/index.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a15: Scenario = {
  ...catalogEntry("A-15"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const keyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      world.providerA.vault.add({
        itemId: `non-zero-counter-${randomBytes(8).toString("hex")}`,
        credentialId: randomBytes(32),
        rpId: "localhost",
        userHandle: randomBytes(32),
        username: "bob",
        userDisplayName: "Bob (non-zero counter)",
        privateKey: keyPair.privateKey,
        signCount: 42,
        backupEligible: true,
        backupState: true,
        createdAt: Math.floor(Date.now() / 1000),
      });
      const before = world.providerA.vault.size;
      const request = await world.providerB.importer.createRequest("indirect");
      const { header, report } = world.providerA.exporter.buildCxf(request);
      const exported = header.accounts[0]?.items.length ?? 0;
      if (report.excludedNonZeroCounter.length > 0 && exported < before) {
        return { id: "A-15", profile: policy.profile, outcome: "succeeded", evidence: `${report.excludedNonZeroCounter.length} passkey(s) silently excluded (signCount != 0); owner not notified (GAP-33 not implemented)` };
      }
      return { id: "A-15", profile: policy.profile, outcome: "error", evidence: `expected exclusion: exported=${exported}, vault=${before}, excluded=${report.excludedNonZeroCounter.length}` };
    } finally {
      await world.close();
    }
  },
};
