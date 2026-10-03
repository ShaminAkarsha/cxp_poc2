/**
 * A-03 / T-ER-03: replay of a captured ExportResponse to the importer.
 *
 * The adversary captures a legitimate Export Response (including a response
 * file left on disk, GAP-31) and replays it to the importer.
 *
 * Gaps exercised: GAP-01, GAP-11, GAP-31.
 * spec-minimal: succeeds — the importer key is reusable (GAP-11), there is
 *   no request binding (GAP-01), and the response file stays on disk (GAP-31),
 *   so a second import replaces the credentials.
 * hardened: fails — the importer key is destroyed after the first import
 *   (GAP-11 singleUseImporterKey).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-03 / GAP-01, GAP-11, GAP-31: replay of a captured ExportResponse", () => {
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
      it("succeeds: the same response imports twice (GAP-01, GAP-11)", async () => {
        // First import (legitimate)
        const request = await world.providerB.importer.createRequest("indirect");
        const { response } = await world.providerA.exporter.respond(request, "file");
        const first = await world.providerB.importer.importResponse(response);
        expect(first.imported).toHaveLength(1);

        // Replay: re-submit the captured response // GAP-11
        const replay = await world.providerB.importer.importResponse(response);
        expect(replay.imported).toHaveLength(1);
        // GAP-30: the replayed credential replaces the existing one
        expect(replay.replaced).toHaveLength(1);
      });
    } else {
      it("fails: importer key destroyed after first import (GAP-11)", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        const { response } = await world.providerA.exporter.respond(request, "file");
        const first = await world.providerB.importer.importResponse(response);
        expect(first.imported).toHaveLength(1);

        // Replay: the pending request was cleared after the first import
        await expect(
          world.providerB.importer.importResponse(response),
        ).rejects.toThrow(/no pending Export Request/);
      });
    }
  });
});
