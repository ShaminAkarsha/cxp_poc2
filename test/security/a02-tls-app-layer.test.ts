/**
 * 4c — A-02 with TLS configured on the hardened exporter and the relay
 * substituting the importer key at the application layer. Expected:
 * rejected by key-fingerprint mismatch, not by missing TLS.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { substituteImporterKey } from "../../src/adversary/substitute-key.js";
import { createLoopbackTls } from "../../src/crypto/test-ca.js";
import { openExportResponse } from "../../src/cxp/index.js";
import { getPolicy } from "../../src/policy/index.js";
import { startExporterService, submitDirectRequest } from "../../src/provider/direct.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-02 TLS variant: app-layer key substitution with TLS present", () => {
  const policy = getPolicy("hardened");
  let world: Awaited<ReturnType<typeof createWorld>>;

  beforeEach(async () => {
    world = await createWorld(policy);
    await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
  });

  afterEach(async () => {
    await world.close();
  });

  it("rejected by fingerprint mismatch, not by missing TLS", async () => {
    const tls = await createLoopbackTls();
    const service = await startExporterService(world.providerA.exporter, { tls });
    try {
      const request = await world.providerB.importer.createRequest("direct");
      const { tampered } = await substituteImporterKey(request);
      await expect(
        submitDirectRequest(service.url, tampered, { caPem: tls.caPem }),
      ).rejects.toThrow(/not approved|GAP-29/);
    } finally {
      await service.close();
    }
  });
});
