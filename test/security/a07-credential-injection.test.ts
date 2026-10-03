/**
 * A-07 / T-ER-07: credential injection by an unauthenticated exporter.
 *
 * An adversary who intercepts the importer's Export Request forges a
 * base-mode response injecting their own credentials. In the replacement
 * variant the injected credential has the same credentialId as an existing
 * one, silently replacing it.
 *
 * Gaps exercised: GAP-14, GAP-30.
 * spec-minimal: succeeds — HPKE base mode has no exporter authentication
 *   (GAP-14), and an imported credential silently replaces a conflicting
 *   one (GAP-30).
 * hardened: fails — the importer requires auth mode (GAP-14), and the
 *   adversary's base-mode response does not correspond to any request entry.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMaliciousPasskey, forgeResponse } from "../../src/adversary/forge-response.js";
import { encodeB64url } from "../../src/cxf/index.js";
import { CxpNegotiationError } from "../../src/cxp/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld, migrate } from "../../src/scenario/world.js";

describe("A-07 / GAP-14, GAP-30: credential injection by an unauthenticated exporter", () => {
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
      it("succeeds: adversary injects new credentials via a forged response (GAP-14)", async () => {
        // Provider B creates a request; adversary intercepts it
        const request = await world.providerB.importer.createRequest("indirect");

        // Adversary forges a base-mode response with a malicious credential
        const malicious = createMaliciousPasskey("localhost", "mallory");
        const forged = await forgeResponse(request, [malicious]);

        // Provider B imports the forged response — base mode, no exporter auth
        const report = await world.providerB.importer.importResponse(forged);
        expect(report.imported).toHaveLength(1);
        expect(world.providerB.vault.size).toBe(1);
      });

      it("succeeds: adversary replaces an existing credential (GAP-30)", async () => {
        // Legitimate migration first
        await migrate(world, "indirect");
        expect(world.providerB.vault.size).toBe(1);
        const originalRecord = world.providerB.vault.list()[0]!;

        // Provider B can sign in after the legitimate migration
        const loginBefore = await world.rpClient.login(world.providerB.authenticator, "alice");
        expect(loginBefore.body.verified).toBe(true);

        // Adversary forges a credential with the same credentialId
        const replacement = createMaliciousPasskey("localhost", "alice", {
          credentialId: encodeB64url(originalRecord.credentialId),
          userHandle: encodeB64url(originalRecord.userHandle),
        });
        const request = await world.providerB.importer.createRequest("indirect");
        const forged = await forgeResponse(request, [replacement]);
        const report = await world.providerB.importer.importResponse(forged);

        // The credential was silently replaced
        expect(report.replaced).toHaveLength(1);
        expect(world.providerB.vault.size).toBe(1);

        // Provider B can NO LONGER sign in: the RP has Alice's original public
        // key but Provider B now holds the adversary's private key
        const loginAfter = await world.rpClient.login(world.providerB.authenticator, "alice");
        expect(loginAfter.body.verified).toBe(false);
      });
    } else {
      it("fails: base-mode response does not correspond to auth-mode request (GAP-14)", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        const malicious = createMaliciousPasskey("localhost", "mallory");
        const forged = await forgeResponse(request, [malicious]);

        // The importer rejects: base mode ≠ auth mode in the request
        await expect(
          world.providerB.importer.importResponse(forged),
        ).rejects.toThrow(CxpNegotiationError);
      });
    }
  });
});
