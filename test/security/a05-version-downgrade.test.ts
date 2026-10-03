/**
 * A-05: protocol version downgrade.
 *
 * The request specifies a higher CXP version than the response's, which
 * an adversary could use to force a downgrade to a weaker protocol revision.
 *
 * Gaps exercised: GAP-04, GAP-24.
 * spec-minimal: succeeds — no version check; the importer accepts version 0
 *   when the request asked for version 1.
 * hardened: fails — rejectVersionDowngrade detects version 0 < 1 (GAP-04).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-05 / GAP-04, GAP-24: protocol version downgrade", () => {
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
      it("succeeds: response version 0 accepted for request version 1 (GAP-04)", async () => {
        const request = await world.providerB.importer.createRequest("indirect", { version: 1 });
        expect(request.version).toBe(1);
        const { response } = await world.providerA.exporter.respond(request, "file");
        expect(response.version).toBe(0);
        const report = await world.providerB.importer.importResponse(response);
        expect(report.imported).toHaveLength(1);
      });
    } else {
      it("fails: version downgrade detected (GAP-04)", async () => {
        const request = await world.providerB.importer.createRequest("indirect", { version: 1 });
        const { response } = await world.providerA.exporter.respond(request, "file");
        await expect(
          world.providerB.importer.importResponse(response),
        ).rejects.toThrow(/version.*below.*GAP-04/);
      });
    }
  });
});
