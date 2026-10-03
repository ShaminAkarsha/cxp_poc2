/**
 * A-02: active MITM on a direct channel, relaying a substituted importer key.
 *
 * The adversary intercepts the importer's Export Request on the direct
 * (HTTP/HTTPS) transport, substitutes the HPKE public key, forwards the
 * tampered request to the exporter, and decrypts the response.
 *
 * Gaps exercised: GAP-05, GAP-19.
 * spec-minimal: succeeds — plain HTTP channel, no SAS confirmation.
 * hardened: fails — TLS prevents interception (GAP-19).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { substituteImporterKey } from "../../src/adversary/substitute-key.js";
import { openExportResponse } from "../../src/cxp/index.js";
import { startExporterService, submitDirectRequest } from "../../src/provider/direct.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-02 / GAP-05, GAP-19: MITM on direct channel with substituted importer key", () => {
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
      it("succeeds: adversary intercepts and substitutes key on plain HTTP (GAP-05, GAP-19)", async () => {
        const service = await startExporterService(world.providerA.exporter);
        try {
          const request = await world.providerB.importer.createRequest("direct");
          const { tampered, adversaryKeyring } = await substituteImporterKey(request);
          const response = await submitDirectRequest(service.url, tampered);
          const header = await openExportResponse({
            request: tampered,
            response,
            keyring: adversaryKeyring,
            policy,
          });
          expect(header.accounts[0]!.items.length).toBeGreaterThan(0);
        } finally {
          await service.close();
        }
      });
    } else {
      it("fails: exporter refuses to serve without TLS (GAP-19)", async () => {
        await expect(
          startExporterService(world.providerA.exporter),
        ).rejects.toThrow(/TLS material.*required.*GAP-19/);
      });
    }
  });
});
