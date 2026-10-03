/**
 * A-06 / T-ER-06: swapping or reordering files inside the archive.
 *
 * The adversary swaps two encrypted document files within the response
 * archive. Under spec-minimal the swap is undetected because all documents
 * share one key and carry no per-file binding.
 *
 * Gaps exercised: GAP-07, GAP-09.
 * spec-minimal: succeeds — the swap goes undetected (GAP-07 shared key,
 *   GAP-09 no AAD binding).
 * hardened: fails — the manifest hash mismatch (GAP-10) or the per-file
 *   AAD path binding (GAP-09) detects the swap.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { swapArchiveDocuments } from "../../src/adversary/swap-files.js";
import { readZip } from "../../src/crypto/archive.js";
import { decodeB64url } from "../../src/cxf/index.js";
import { DOCUMENTS_DIR } from "../../src/cxp/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld } from "../../src/scenario/world.js";

describe("A-06 / GAP-07, GAP-09: swapping files inside the archive", () => {
  describe.each(PROFILE_NAMES)("%s", (profile) => {
    const policy = getPolicy(profile);
    let world: Awaited<ReturnType<typeof createWorld>>;

    beforeEach(async () => {
      world = await createWorld(policy);
      // Two passkeys so there are two documents to swap
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      await world.rpClient.register(world.providerA.authenticator, "bob", "Bob");
    });

    afterEach(async () => {
      await world.close();
    });

    if (profile === "spec-minimal") {
      it("succeeds: swapped documents are imported without detection (GAP-07, GAP-09)", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        const { response } = await world.providerA.exporter.respond(request, "file");

        // Find the two document paths in the archive
        const files = readZip(decodeB64url(response.payload));
        const docPaths = [...files.keys()].filter((p) => p.startsWith(DOCUMENTS_DIR)).sort();
        expect(docPaths).toHaveLength(2);

        // Swap the two documents // GAP-07, GAP-09
        const tampered = swapArchiveDocuments(response, docPaths[0]!, docPaths[1]!);

        // The importer accepts the tampered archive
        const report = await world.providerB.importer.importResponse(tampered);
        expect(report.imported).toHaveLength(2);
      });
    } else {
      it("fails: manifest or AAD binding detects the swap (GAP-09, GAP-10)", async () => {
        const request = await world.providerB.importer.createRequest("indirect");
        const { response } = await world.providerA.exporter.respond(request, "file");

        const files = readZip(decodeB64url(response.payload));
        const docPaths = [...files.keys()].filter((p) => p.startsWith(DOCUMENTS_DIR)).sort();
        expect(docPaths).toHaveLength(2);

        const tampered = swapArchiveDocuments(response, docPaths[0]!, docPaths[1]!);

        // The importer detects the tampering
        await expect(
          world.providerB.importer.importResponse(tampered),
        ).rejects.toThrow(/manifest|bound to another path/);
      });
    }
  });
});
