/**
 * 4a — Positive control: a legitimate migration under hardened completes and
 * the credential authenticates at the demo RP.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getPolicy } from "../../src/policy/index.js";
import { createWorld, migrate } from "../../src/scenario/world.js";

describe("Positive control: legitimate hardened migration", () => {
  let world: Awaited<ReturnType<typeof createWorld>>;

  beforeEach(async () => {
    world = await createWorld(getPolicy("hardened"));
    await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
  });

  afterEach(async () => {
    await world.close();
  });

  it("migration completes and migrated credential authenticates at the RP", async () => {
    const report = await migrate(world, "indirect");
    expect(report.imported).toHaveLength(1);
    expect(report.skipped).toHaveLength(0);
    const login = await world.rpClient.login(world.providerB.authenticator, "alice");
    expect(login.body.verified).toBe(true);
  });
});
