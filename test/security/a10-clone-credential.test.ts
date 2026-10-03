/**
 * A-10: clone use of source and migrated credential goes undetected by the RP.
 *
 * After migration, both the source and the migrated credential can sign
 * in at the same RP. Because CXF §3.3.12 (MUST) copies the private key
 * exactly (GAP-17) and the source credential is not destroyed (GAP-15),
 * the RP cannot distinguish the two.
 *
 * Gaps exercised: GAP-15, GAP-17.
 * Both profiles: succeeds — CXF mandates identical key material, and
 *   credential destruction is out of CXP scope.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld, migrate } from "../../src/scenario/world.js";

describe("A-10 / GAP-15, GAP-17: clone credential undetected by RP", () => {
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

    it("succeeds: both source and migrated credential sign in (GAP-15, GAP-17)", async () => {
      await migrate(world, "indirect");
      const loginA = await world.rpClient.login(world.providerA.authenticator, "alice");
      const loginB = await world.rpClient.login(world.providerB.authenticator, "alice");
      expect(loginA.body.verified).toBe(true);
      expect(loginB.body.verified).toBe(true);
    });
  });
});
