/**
 * A-01 / T-ER-01: importer key substitution in request file.
 *
 * The adversary replaces the importer's HPKE public key in an indirect Export
 * Request file with their own. The exporter then encrypts the credentials to
 * the adversary's key instead of the legitimate importer's.
 *
 * Gaps exercised: GAP-05, GAP-06.
 * spec-minimal: succeeds — no fingerprint confirmation, exporter encrypts to
 *   the adversary's key (GAP-05 unauthenticated, GAP-06 no file integrity).
 * hardened: fails — the simulated user sees a fingerprint mismatch and
 *   rejects the export (GAP-05 SAS confirmation, GAP-06 confirmed key).
 */
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { substituteImporterKey } from "../../src/adversary/substitute-key.js";
import { openExportResponse, parseExportRequestJson } from "../../src/cxp/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-01 / GAP-05, GAP-06: importer key substitution in indirect request file", () => {
  describe.each(PROFILE_NAMES)("%s", (profile) => {
    const policy = getPolicy(profile);
    let world: Awaited<ReturnType<typeof createWorld>>;
    let workDir: string;

    beforeEach(async () => {
      world = await createWorld(policy);
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      workDir = await mkdtemp(join(tmpdir(), "a01-"));
    });

    afterEach(async () => {
      await world.close();
      await rm(workDir, { recursive: true, force: true });
    });

    if (profile === "spec-minimal") {
      it("succeeds: exporter encrypts to the adversary's substituted key", async () => {
        // Provider B writes the request file
        const requestPath = await world.providerB.importer.writeRequestFile(workDir);

        // Adversary reads, substitutes the importer key, writes back // GAP-05, GAP-06
        const originalRequest = parseExportRequestJson(await readFile(requestPath, "utf8"));
        const { tampered, adversaryKeyring } = await substituteImporterKey(originalRequest);
        await writeFile(requestPath, JSON.stringify(tampered));

        // Provider A exports to the tampered request (no consent under spec-minimal)
        const { response } = await world.providerA.exporter.exportToFile(requestPath, workDir);

        // The adversary decrypts the response with their own keys
        const header = await openExportResponse({
          request: tampered,
          response,
          keyring: adversaryKeyring,
          policy,
        });
        expect(header.accounts[0]!.items.length).toBeGreaterThan(0);
        expect(header.accounts[0]!.items[0]!.credentials[0]!.type).toBe("passkey");
      });
    } else {
      it("fails: fingerprint mismatch prevents export (GAP-05, GAP-06)", async () => {
        const requestPath = await world.providerB.importer.writeRequestFile(workDir);
        const originalRequest = parseExportRequestJson(await readFile(requestPath, "utf8"));
        const { tampered } = await substituteImporterKey(originalRequest);
        await writeFile(requestPath, JSON.stringify(tampered));

        // Provider A rejects: the simulated user sees a fingerprint mismatch
        await expect(
          world.providerA.exporter.exportToFile(requestPath, workDir),
        ).rejects.toThrow(/not approved|GAP-29/);
      });
    }
  });
});
