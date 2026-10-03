/**
 * A-11: PRF seed reuse across two importers.
 *
 * CXF §3.3.12.3 (MUST) exports hmacCredentials verbatim. When the same
 * credential is exported to two importers, both receive identical PRF seeds.
 *
 * Gaps exercised: GAP-16.
 * Both profiles: succeeds — the spec mandates identical export of all
 *   credential material; there is no conformant mitigation.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Passkey } from "../../src/cxf/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-11 / GAP-16: PRF seed reuse across importers", () => {
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

    it("succeeds: two exports produce identical credential key material (GAP-16)", async () => {
      const req1 = await world.providerB.importer.createRequest("indirect");
      const cxf1 = world.providerA.exporter.buildCxf(req1);
      const req2 = await world.providerB.importer.createRequest("indirect");
      const cxf2 = world.providerA.exporter.buildCxf(req2);
      const pk1 = cxf1.header.accounts[0]!.items[0]!.credentials[0] as Passkey;
      const pk2 = cxf2.header.accounts[0]!.items[0]!.credentials[0] as Passkey;
      expect(pk1.key).toBe(pk2.key);
    });
  });
});
