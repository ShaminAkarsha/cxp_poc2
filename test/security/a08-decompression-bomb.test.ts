/**
 * A-08: decompression bomb via deflate or largeBlob.
 *
 * An adversary crafts a zip archive with entries that declare enormous
 * decompressed sizes, causing excessive memory allocation on the importer.
 *
 * Gaps exercised: GAP-12.
 * spec-minimal: succeeds — no decompression limits.
 * hardened: fails — enforceDecompressionLimits rejects oversized entries.
 */
import { describe, expect, it } from "vitest";
import { createZip, DEFAULT_ARCHIVE_LIMITS, readZip } from "../../src/crypto/archive.js";
import { getPolicy, isEnabled, PROFILE_NAMES } from "../../src/policy/index.js";

describe("A-08 / GAP-12: decompression bomb", () => {
  const bombData = new Uint8Array(2 << 20); // 2 MiB > maxEntryBytes (1 MiB)
  const bomb = createZip(new Map([["bomb.bin", bombData]]));

  describe.each(PROFILE_NAMES)("%s", (profile) => {
    const policy = getPolicy(profile);

    if (profile === "spec-minimal") {
      it("succeeds: oversized entry is accepted without limits (GAP-12)", () => {
        expect(isEnabled(policy, "enforceDecompressionLimits")).toBe(false);
        const files = readZip(bomb);
        expect(files.get("bomb.bin")!.length).toBe(2 << 20);
      });
    } else {
      it("fails: decompression limits reject oversized entry (GAP-12)", () => {
        expect(isEnabled(policy, "enforceDecompressionLimits")).toBe(true);
        expect(() => readZip(bomb, DEFAULT_ARCHIVE_LIMITS)).toThrow(/declared size.*exceeds/);
      });
    }
  });
});
