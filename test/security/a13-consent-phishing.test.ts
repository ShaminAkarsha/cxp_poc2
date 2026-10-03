/**
 * A-13: consent phishing — victim approves an attacker-crafted Export Request.
 *
 * The adversary crafts a complete Export Request carrying their own HPKE
 * key and presents it to the exporter, hoping the credential owner
 * approves it without verifying the importer's identity.
 *
 * Gaps exercised: GAP-05, GAP-06, GAP-29.
 * spec-minimal: succeeds — no consent or fingerprint check (GAP-29).
 * hardened: fails — consent screen shows a fingerprint that does not match
 *   any legitimate importer's display (GAP-05/06/29).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createExportRequest, openExportResponse } from "../../src/cxp/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-13 / GAP-05, GAP-06, GAP-29: consent phishing", () => {
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
      it("succeeds: adversary's request is served without consent (GAP-29)", async () => {
        const { request, keyring } = await createExportRequest({
          importer: "adversary.example",
          mode: "indirect",
        });
        const { response } = await world.providerA.exporter.respond(request, "file");
        const header = await openExportResponse({ request, response, keyring, policy });
        expect(header.accounts[0]!.items.length).toBeGreaterThan(0);
      });
    } else {
      it("fails: fingerprint mismatch prevents export (GAP-05, GAP-06, GAP-29)", async () => {
        const { request } = await createExportRequest({
          importer: "adversary.example",
          mode: "indirect",
          policy: getPolicy("hardened"),
        });
        await expect(
          world.providerA.exporter.respond(request, "file"),
        ).rejects.toThrow(/not approved|GAP-29/);
      });
    }
  });
});
