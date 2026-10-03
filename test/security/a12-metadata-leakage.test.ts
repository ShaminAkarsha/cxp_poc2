/**
 * A-12: metadata observable to a passive observer of the Export Response.
 *
 * In spec-minimal, archive file names are the CXF Item IDs (GAP-08),
 * which may be guessable or linkable. In hardened, file names are random
 * (GAP-08), but per-file sizes remain observable (GAP-18).
 *
 * Gaps exercised: GAP-08, GAP-18.
 * spec-minimal: succeeds — file names expose Item IDs.
 * hardened: reduced — names are random, but sizes still leak the number
 *   and approximate size of credentials.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readZip } from "../../src/crypto/archive.js";
import { decodeB64url } from "../../src/cxf/index.js";
import { DOCUMENTS_DIR } from "../../src/cxp/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-12 / GAP-08, GAP-18: metadata leakage from Export Response", () => {
  describe.each(PROFILE_NAMES)("%s", (profile) => {
    const policy = getPolicy(profile);
    let world: Awaited<ReturnType<typeof createWorld>>;

    beforeEach(async () => {
      world = await createWorld(policy);
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      await world.rpClient.register(world.providerA.authenticator, "bob", "Bob");
    });

    afterEach(async () => {
      await world.close();
    });

    if (profile === "spec-minimal") {
      it("succeeds: archive file names reveal Item IDs (GAP-08, GAP-18)", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        const { response } = await world.providerA.exporter.respond(request, "file");
        const zip = readZip(decodeB64url(response.payload));
        const docPaths = [...zip.keys()].filter((p) => p.startsWith(DOCUMENTS_DIR));
        const records = world.providerA.vault.list();
        for (const record of records) {
          expect(docPaths).toContainEqual(`${DOCUMENTS_DIR}${record.itemId}.jwe`);
        }
      });
    } else {
      it("reduced: file names are random but sizes still observable (GAP-08, GAP-18)", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        const { response } = await world.providerA.exporter.respond(request, "file");
        const zip = readZip(decodeB64url(response.payload));
        const docPaths = [...zip.keys()].filter((p) => p.startsWith(DOCUMENTS_DIR));
        const records = world.providerA.vault.list();
        for (const record of records) {
          expect(docPaths).not.toContainEqual(`${DOCUMENTS_DIR}${record.itemId}.jwe`);
        }
        expect(docPaths).toHaveLength(records.length);
      });
    }
  });
});
