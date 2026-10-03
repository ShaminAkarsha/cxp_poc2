/**
 * A-04: HPKE suite / archive negotiation tampering.
 *
 * The adversary tampers with the Export Request to force the exporter to
 * select a non-preferred (potentially weaker) HPKE suite.
 *
 * Gaps exercised: GAP-02, GAP-03.
 * spec-minimal: succeeds — the importer offers MTI and P-256; the adversary
 *   removes the MTI entry, forcing the exporter to select P-256.
 * hardened: fails — the importer offers only the MTI suite (GAP-02), so
 *   there is nothing to downgrade; a non-MTI response is rejected.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AEAD, KDF, KEM, MTI_SUITE, generateKeyPair, publicKeyToJwk } from "../../src/crypto/hpke.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-04 / GAP-02, GAP-03: HPKE suite negotiation tampering", () => {
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
      it("succeeds: adversary forces P-256 by removing the MTI entry (GAP-02, GAP-03)", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        expect(request.hpke.length).toBeGreaterThan(1);
        const tampered = { ...request, hpke: request.hpke.filter((e) => e.kem !== MTI_SUITE.kem) };
        expect(tampered.hpke.length).toBeGreaterThan(0);
        const { response } = await world.providerA.exporter.respond(tampered, "file");
        expect(response.hpke.kem).toBe(KEM.P256_HKDF_SHA256);
        const report = await world.providerB.importer.importResponse(response);
        expect(report.imported).toHaveLength(1);
      });
    } else {
      it("fails: only the mandatory suite is offered, adversary cannot downgrade (GAP-02)", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        expect(request.hpke).toHaveLength(1);
        expect(request.hpke[0]!.kem).toBe(MTI_SUITE.kem);
        const kp = await generateKeyPair(KEM.P256_HKDF_SHA256);
        const jwk = await publicKeyToJwk(KEM.P256_HKDF_SHA256, kp.publicKey);
        const tampered = {
          ...request,
          hpke: [{ mode: request.hpke[0]!.mode, kem: KEM.P256_HKDF_SHA256, kdf: KDF.HKDF_SHA256, aead: AEAD.AES_128_GCM, key: { kty: jwk.kty ?? "", ...jwk } }],
        };
        await expect(
          world.providerA.exporter.respond(tampered, "file"),
        ).rejects.toThrow(/no mutually supported HPKE parameters/);
      });
    }
  });
});
