/**
 * M5 exit criterion: Provider A -> B migration; the migrated passkey
 * authenticates at the RP; counter = 0 verified.
 */
import { parseAuthenticatorData } from "@simplewebauthn/server/helpers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decodeB64url } from "../../src/cxf/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld, migrate, type MigrationMode, type World } from "../../src/scenario/world.js";

const MODES: MigrationMode[] = ["indirect", "direct"];
const CASES = PROFILE_NAMES.flatMap((profile) => MODES.map((mode) => [profile, mode] as const));

describe.each(CASES)("end-to-end migration under %s, %s mode", (profile, mode) => {
  let world: World;

  beforeEach(async () => {
    world = await createWorld(getPolicy(profile));
    // Baseline: Alice registers at the RP with Provider A.
    const reg = await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
    expect(reg.body.verified).toBe(true);
  });

  afterEach(async () => {
    await world.close();
  });

  it("the migrated passkey signs in at the RP from Provider B", async () => {
    const report = await migrate(world, mode);
    expect(report.imported).toHaveLength(1);

    const byUsername = await world.rpClient.login(world.providerB.authenticator, "alice");
    expect(byUsername.body).toMatchObject({ verified: true, username: "alice" });
    const discoverable = await world.rpClient.login(world.providerB.authenticator);
    expect(discoverable.body).toMatchObject({ verified: true, username: "alice" });

    // Same credential the RP registered; the RP was never asked to register Provider B.
    const registered = world.rp.rp.getUser("alice")!.credentials;
    expect(registered).toHaveLength(1);
    expect(byUsername.body.credentialId).toBe(registered[0]!.id);
    expect(world.rp.rp.events.filter((e) => e.kind === "registered")).toHaveLength(1);
  });

  it("counter = 0 at Provider B, in every assertion, and at the RP (CXF §3.3.12 MUST)", async () => {
    await migrate(world, mode);
    expect(world.providerB.vault.list().map((r) => r.signCount)).toEqual([0]);
    for (let i = 0; i < 3; i++) {
      const options = await world.rpClient.loginOptions("alice");
      const assertion = world.providerB.authenticator.get(options, world.rpClient.origin);
      const authData = parseAuthenticatorData(decodeB64url(assertion.response.authenticatorData));
      expect(authData.counter).toBe(0);
      expect((await world.rpClient.submitAssertion(assertion)).body).toMatchObject({ verified: true, counter: 0 });
    }
    expect(world.rp.rp.getUser("alice")!.credentials[0]!.counter).toBe(0);
  });

  it("Provider A's copy still signs in after migration (GAP-15; A-10 precondition)", async () => {
    await migrate(world, mode);
    expect((await world.rpClient.login(world.providerA.authenticator, "alice")).body.verified).toBe(true);
    expect((await world.rpClient.login(world.providerB.authenticator, "alice")).body.verified).toBe(true);
    expect((await world.rpClient.login(world.providerA.authenticator, "alice")).body.verified).toBe(true);
  });
});

/**
 * What the RP can observe about the two copies. Evidence for A-10 (GAP-17,
 * GAP-25): the assertions differ only in the (randomised) ECDSA signature.
 */
describe("RP view of source vs migrated assertions", () => {
  let world: World;
  beforeEach(async () => {
    world = await createWorld(getPolicy("spec-minimal"));
    await world.rpClient.register(world.providerA.authenticator, "alice");
    await migrate(world, "indirect");
  });
  afterEach(async () => {
    await world.close();
  });

  it("authenticator data is byte-identical; nothing distinguishes the two providers", async () => {
    const options = await world.rpClient.loginOptions("alice");
    const fromA = world.providerA.authenticator.get(options, world.rpClient.origin);
    const fromB = world.providerB.authenticator.get(options, world.rpClient.origin);

    expect(fromB.id).toBe(fromA.id);
    expect(fromB.response.userHandle).toBe(fromA.response.userHandle);
    expect(fromB.response.clientDataJSON).toBe(fromA.response.clientDataJSON);
    expect(fromB.response.authenticatorData).toBe(fromA.response.authenticatorData); // flags, counter 0, rpIdHash
    const flags = parseAuthenticatorData(decodeB64url(fromB.response.authenticatorData)).flags;
    expect(flags).toMatchObject({ up: true, uv: true, be: true, bs: true });

    // Either one is accepted for the same challenge (only the first submitted, as challenges are single-use).
    expect((await world.rpClient.submitAssertion(fromB)).body.verified).toBe(true);
  });
});
