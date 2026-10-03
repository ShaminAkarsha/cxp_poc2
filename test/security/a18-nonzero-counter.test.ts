/**
 * A-18 / T-EX-04: silent exclusion of a passkey with a non-zero counter.
 *
 * CXF §3.3.12 mandates that passkeys with signCount != 0 are excluded from
 * export. The user is not warned (GAP-36: exporter does not notify the owner
 * of excluded credentials). GAP-36 is not implemented; hardened classified
 * as NOT MITIGATED.
 *
 * Both profiles: succeeds — exclusion is spec-mandated; silence is not.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-18 / GAP-36: silent exclusion of passkey with non-zero signature counter", () => {
  describe.each(PROFILE_NAMES)("%s", (profile) => {
    const policy = getPolicy(profile);
    let world: Awaited<ReturnType<typeof createWorld>>;

    beforeEach(async () => {
      world = await createWorld(policy);
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
    });

    afterEach(async () => {
      await world.close();
    });

    it("succeeds: passkey with signCount=42 silently excluded from export", async () => {
      const keyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      world.providerA.vault.add({
        itemId: `non-zero-${randomBytes(8).toString("hex")}`,
        credentialId: randomBytes(32),
        rpId: "localhost",
        userHandle: randomBytes(32),
        username: "bob",
        userDisplayName: "Bob",
        privateKey: keyPair.privateKey,
        signCount: 42,
        backupEligible: true,
        backupState: true,
        createdAt: Math.floor(Date.now() / 1000),
      });
      expect(world.providerA.vault.size).toBe(2);
      const request = await world.providerB.importer.createRequest("indirect");
      const { header, report } = world.providerA.exporter.buildCxf(request);
      expect(report.excludedNonZeroCounter).toHaveLength(1);
      expect(header.accounts[0]!.items).toHaveLength(1);
    });
  });
});
