/**
 * 4b — Ablation for A-01 and A-13: hardened with requireExportConsent ON but
 * requireSasConfirmation and confirmRequestFileKey OFF, simulated owner
 * approves. Expected: attack succeeds (shows key confirmation is the
 * mitigating control, not consent alone).
 */
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { substituteImporterKey } from "../../src/adversary/substitute-key.js";
import { createExportRequest, openExportResponse, parseExportRequestJson } from "../../src/cxp/index.js";
import { getPolicy, type Policy } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

function ablationPolicy(): Policy {
  const hardened = getPolicy("hardened");
  return {
    profile: "hardened",
    flags: {
      ...hardened.flags,
      requireSasConfirmation: false,
      confirmRequestFileKey: false,
    },
  };
}

describe("Ablation: consent without key confirmation", () => {
  const policy = ablationPolicy();
  let world: Awaited<ReturnType<typeof createWorld>>;
  let workDir: string;

  beforeEach(async () => {
    world = await createWorld(policy);
    await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
    workDir = await mkdtemp(join(tmpdir(), "ablation-"));
  });

  afterEach(async () => {
    await world.close();
    await rm(workDir, { recursive: true, force: true });
  });

  it("A-01 ablation: key substitution succeeds when fingerprint confirmation is off", async () => {
    const requestPath = await world.providerB.importer.writeRequestFile(workDir);
    const originalRequest = parseExportRequestJson(await readFile(requestPath, "utf8"));
    const { tampered, adversaryKeyring } = await substituteImporterKey(originalRequest);
    await writeFile(requestPath, JSON.stringify(tampered));
    const { response } = await world.providerA.exporter.exportToFile(requestPath, workDir);
    const header = await openExportResponse({
      request: tampered,
      response,
      keyring: adversaryKeyring,
      policy,
    });
    expect(header.accounts[0]!.items.length).toBeGreaterThan(0);
  });

  it("A-13 ablation: consent phishing succeeds when fingerprint confirmation is off", async () => {
    const { request, keyring } = await createExportRequest({
      importer: "adversary.example",
      mode: "indirect",
      policy,
    });
    const { response } = await world.providerA.exporter.respond(request, "file");
    const header = await openExportResponse({ request, response, keyring, policy });
    expect(header.accounts[0]!.items.length).toBeGreaterThan(0);
  });
});
