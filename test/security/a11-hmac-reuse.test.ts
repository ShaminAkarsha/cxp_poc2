/**
 * A-11 / GAP-16: PRF seed reuse across two importers.
 *
 * CXF §3.3.12.3 exports hmacCredentials (CTAP 2.1 CredRandom) verbatim.
 * StoredPasskey does not preserve fido2Extensions through import, so we
 * compare the decrypted CXF payloads received by each importer instead
 * of reading stored hmacCredentials from the vault.
 */
import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateKeyPair, MTI_SUITE } from "../../src/crypto/hpke.js";
import { encodeB64url, type Passkey } from "../../src/cxf/index.js";
import {
  createExportRequest,
  type CreateExportRequestOptions,
} from "../../src/cxp/request.js";
import { createExportResponse, openExportResponse } from "../../src/cxp/response.js";
import { isEnabled, getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-11 / GAP-16: hmacCredentials reuse across importers (decrypted CXF comparison)", () => {
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

    it("succeeds: two importers receive byte-identical hmacCredentials in decrypted CXF", async () => {
      const hmacSeed = encodeB64url(new Uint8Array(randomBytes(32)));

      // Build a CXF header enriched with hmacCredentials
      const probeReq = await world.providerB.importer.createRequest("indirect");
      const { header } = world.providerA.exporter.buildCxf(probeReq);
      const pk = header.accounts[0]!.items[0]!.credentials[0] as Passkey;
      const enriched: Passkey = {
        ...pk,
        fido2Extensions: {
          hmacCredentials: {
            algorithm: "HMAC-SHA-256",
            credWithUV: hmacSeed,
            credWithoutUV: hmacSeed,
          },
        },
      };
      const headerWithHmac = {
        ...header,
        accounts: header.accounts.map((a) => ({
          ...a,
          items: a.items.map((item) => ({
            ...item,
            credentials: [enriched],
          })),
        })),
      };

      const rpId = world.providerA.exporter.config.rpId;
      const senderKey = isEnabled(policy, "requireHpkeAuthMode")
        ? await generateKeyPair(MTI_SUITE.kem)
        : undefined;

      const reqOpts: Omit<CreateExportRequestOptions, "importer"> = {
        mode: "indirect",
        policy,
      };

      // Importer 1: create request, build response, open and decrypt
      const { request: req1, keyring: keyring1 } = await createExportRequest({
        ...reqOpts,
        importer: "importer-1.example",
      });
      const resp1 = await createExportResponse({
        request: req1,
        header: headerWithHmac,
        exporter: rpId,
        policy,
        ...(senderKey ? { senderKey } : {}),
      });

      // Importer 2: same procedure
      const { request: req2, keyring: keyring2 } = await createExportRequest({
        ...reqOpts,
        importer: "importer-2.example",
      });
      const resp2 = await createExportResponse({
        request: req2,
        header: headerWithHmac,
        exporter: rpId,
        policy,
        ...(senderKey ? { senderKey } : {}),
      });

      // Decrypt both responses
      const decrypted1 = await openExportResponse({
        request: req1,
        response: resp1,
        keyring: keyring1,
        policy,
        confirmExporter: () => true,
      });
      const decrypted2 = await openExportResponse({
        request: req2,
        response: resp2,
        keyring: keyring2,
        policy,
        confirmExporter: () => true,
      });

      // Compare hmacCredentials from the decrypted CXF payloads
      const cred1 = decrypted1.accounts[0]!.items[0]!.credentials[0] as Passkey;
      const cred2 = decrypted2.accounts[0]!.items[0]!.credentials[0] as Passkey;

      expect(cred1.fido2Extensions?.hmacCredentials).toBeDefined();
      expect(cred2.fido2Extensions?.hmacCredentials).toBeDefined();
      expect(cred1.fido2Extensions!.hmacCredentials!.credWithUV).toBe(
        cred2.fido2Extensions!.hmacCredentials!.credWithUV,
      );
      expect(cred1.fido2Extensions!.hmacCredentials!.credWithoutUV).toBe(
        cred2.fido2Extensions!.hmacCredentials!.credWithoutUV,
      );
      expect(cred1.key).toBe(cred2.key);
    });
  });
});
