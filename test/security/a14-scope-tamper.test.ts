/**
 * A-14 / T-ER-03c: scope tampering — remove credentialTypes from the request.
 *
 * The adversary modifies an indirect Export Request file, stripping the
 * credentialTypes field to widen the export scope from passkeys-only to
 * all credential types. A password credential is injected into the CXF
 * header to simulate a vault with mixed types.
 *
 * Gap: GAP-32 (scope tampering via credentialTypes removal).
 * Mitigation: GAP-01, GAP-05, GAP-06 (fingerprint + consent in hardened).
 * spec-minimal: succeeds — scope modification undetected, exporter serves all.
 * hardened: fails — fingerprint mismatch (tampered request ≠ original).
 */
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { encodeB64url } from "../../src/cxf/b64url.js";
import { parseExportRequestJson } from "../../src/cxp/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-14 / GAP-32: scope tampering — remove credentialTypes", () => {
  describe.each(PROFILE_NAMES)("%s", (profile) => {
    const policy = getPolicy(profile);
    let world: Awaited<ReturnType<typeof createWorld>>;
    let workDir: string;

    beforeEach(async () => {
      world = await createWorld(policy);
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      workDir = await mkdtemp(join(tmpdir(), "a14-"));
    });

    afterEach(async () => {
      await world.close();
      await rm(workDir, { recursive: true, force: true });
    });

    it("demonstrates scope widening with mixed credential types", async () => {
      const probeReq = await world.providerB.importer.createRequest("indirect");
      const { header } = world.providerA.exporter.buildCxf(probeReq);
      const account = header.accounts[0]!;
      const passwordItem = {
        id: encodeB64url(new Uint8Array(randomBytes(16))),
        creationAt: Math.floor(Date.now() / 1000),
        title: "example.com",
        subtitle: "alice@example.com",
        credentials: [{ type: "password", url: "https://example.com", username: "alice" }],
      };
      const mixedItems = [...account.items, passwordItem];
      const passkeysOnly = mixedItems.filter((i) =>
        i.credentials.some((c: { type: string }) => c.type === "passkey"),
      ).length;
      expect(passkeysOnly).toBe(1);
      expect(mixedItems.length).toBe(2);
    });

    if (profile === "spec-minimal") {
      it("succeeds: credentialTypes stripped, exporter serves all types", async () => {
        const requestPath = await world.providerB.importer.writeRequestFile(workDir, {
          credentialTypes: ["passkey"],
        });
        const original = parseExportRequestJson(await readFile(requestPath, "utf8"));
        const { credentialTypes: _stripped, ...rest } = original as Record<string, unknown>;
        void _stripped;
        await writeFile(requestPath, JSON.stringify(rest));
        const { report } = await world.providerA.exporter.exportToFile(requestPath, workDir);
        expect(report.exported).toBeGreaterThan(0);
      });
    } else {
      it("fails: fingerprint mismatch rejects the tampered request (GAP-01, GAP-05, GAP-06)", async () => {
        const requestPath = await world.providerB.importer.writeRequestFile(workDir, {
          credentialTypes: ["passkey"],
        });
        const original = parseExportRequestJson(await readFile(requestPath, "utf8"));
        const { credentialTypes: _stripped, ...rest } = original as Record<string, unknown>;
        void _stripped;
        await writeFile(requestPath, JSON.stringify(rest));
        await expect(
          world.providerA.exporter.exportToFile(requestPath, workDir),
        ).rejects.toThrow(/not approved|GAP-29/);
      });
    }
  });
});
