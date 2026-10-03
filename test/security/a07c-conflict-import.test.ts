/**
 * 4e — A-07c: exercise rejectConflictingImport directly and record whether
 * the existing credential is kept.
 *
 * spec-minimal: replacement wins (GAP-30 open).
 * hardened: existing credential is kept, second import is skipped.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld, migrate } from "../../src/scenario/world.js";

describe("A-07c / GAP-30: rejectConflictingImport — duplicate credential handling", () => {
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

    if (profile === "spec-minimal") {
      it("replacement wins: second import overwrites existing credential", async () => {
        const first = await migrate(world, "indirect");
        expect(first.imported).toHaveLength(1);
        expect(first.replaced).toHaveLength(0);
        const loginAfterFirst = await world.rpClient.login(world.providerB.authenticator, "alice");
        expect(loginAfterFirst.body.verified).toBe(true);
        const second = await migrate(world, "indirect");
        expect(second.imported).toHaveLength(1);
        expect(second.replaced).toHaveLength(1);
        expect(world.providerB.vault.size).toBe(1);
        const loginAfterSecond = await world.rpClient.login(world.providerB.authenticator, "alice");
        expect(loginAfterSecond.body.verified).toBe(true);
      });
    } else {
      it("existing credential kept: second import skipped as conflict", async () => {
        const first = await migrate(world, "indirect");
        expect(first.imported).toHaveLength(1);
        const second = await migrate(world, "indirect");
        expect(second.skipped.filter((s) => s.reason === "conflict")).toHaveLength(1);
        expect(second.imported).toHaveLength(0);
        expect(world.providerB.vault.size).toBe(1);
        const login = await world.rpClient.login(world.providerB.authenticator, "alice");
        expect(login.body.verified).toBe(true);
      });
    }
  });
});
