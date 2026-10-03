/**
 * 4d — A-07b: forged response in HPKE auth mode using the adversary's own
 * sender key pair. Expected: rejected under hardened because the sender
 * key does not match the confirmed exporter key.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateKeyPair, MTI_SUITE, publicKeyToJwk } from "../../src/crypto/hpke.js";
import { createExportResponse, SENDER_KEY_MEMBER } from "../../src/cxp/response.js";
import { encodeB64url } from "../../src/cxf/index.js";
import { createMaliciousPasskey } from "../../src/adversary/forge-response.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";
import type { Account, Header, Item } from "../../src/cxf/index.js";
import { randomBytes } from "node:crypto";

describe("A-07b: forged auth-mode response with adversary sender key", () => {
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
      it("succeeds: base-mode forged response accepted (no auth required)", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        const malicious = createMaliciousPasskey("localhost", "mallory");
        const items: Item[] = [{
          id: encodeB64url(new Uint8Array(randomBytes(16))),
          creationAt: Math.floor(Date.now() / 1000),
          title: "localhost",
          subtitle: "mallory",
          credentials: [malicious],
        }];
        const account: Account = {
          id: encodeB64url(new Uint8Array(randomBytes(16))),
          username: "adversary",
          email: "adversary@example.test",
          collections: [],
          items,
        };
        const header: Header = {
          version: { major: 1, minor: 0 },
          exporterRpId: "adversary.example",
          exporterDisplayName: "Adversary",
          timestamp: Math.floor(Date.now() / 1000),
          accounts: [account],
        };
        const response = await createExportResponse({
          request,
          header,
          exporter: "adversary.example",
          policy,
        });
        const report = await world.providerB.importer.importResponse(response);
        expect(report.imported).toHaveLength(1);
      });
    } else {
      it("rejected: adversary sender key fingerprint does not match confirmed exporter key", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        const malicious = createMaliciousPasskey("localhost", "mallory");
        const items: Item[] = [{
          id: encodeB64url(new Uint8Array(randomBytes(16))),
          creationAt: Math.floor(Date.now() / 1000),
          title: "localhost",
          subtitle: "mallory",
          credentials: [malicious],
        }];
        const account: Account = {
          id: encodeB64url(new Uint8Array(randomBytes(16))),
          username: "adversary",
          email: "adversary@example.test",
          collections: [],
          items,
        };
        const header: Header = {
          version: { major: 1, minor: 0 },
          exporterRpId: "adversary.example",
          exporterDisplayName: "Adversary",
          timestamp: Math.floor(Date.now() / 1000),
          accounts: [account],
        };
        const adversaryKey = await generateKeyPair(MTI_SUITE.kem);
        const response = await createExportResponse({
          request,
          header,
          exporter: "adversary.example",
          policy,
          senderKey: adversaryKey,
        });
        await expect(
          world.providerB.importer.importResponse(response),
        ).rejects.toThrow(/not confirmed|GAP-05/);
      });
    }
  });
});
