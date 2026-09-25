/**
 * Zip archive for the CXP credential payload (CXP §3.4 "MUST follow the zip
 * archive format"; layout undefined — GAP-10). Entries are DEFLATE-compressed
 * (CXP §3.5.3 `deflate`; what is compressed is unspecified — GAP-27).
 *
 * fflate's unzipSync allocates each entry's output from the size the entry
 * *declares* (and truncates anything beyond it). Without limits, memory use
 * is therefore whatever the archive claims (GAP-12, spec-minimal). With
 * limits, declared sizes are checked before anything is inflated, which
 * bounds memory; a truncated entry then fails its JWE authentication.
 */
import { unzipSync, zipSync, type Zippable } from "fflate";

export class ArchiveError extends Error {
  override name = "ArchiveError";
}

/** DEFLATE level for entries (zip compression method 8). */
const DEFLATE_LEVEL = 6;

/** GAP-12 (hardened): decompression limits. */
export interface ArchiveLimits {
  readonly maxEntries: number;
  readonly maxEntryBytes: number;
  readonly maxTotalBytes: number;
}

/**
 * Generous for a credential export (a CXF Item is a few KiB) while bounding
 * memory. OWASP File Upload Cheat Sheet: limit decompressed size and file count.
 */
export const DEFAULT_ARCHIVE_LIMITS: ArchiveLimits = {
  maxEntries: 10_000,
  maxEntryBytes: 1 << 20, // 1 MiB per document
  maxTotalBytes: 64 << 20, // 64 MiB in total
};

const STORED = 0;
const DEFLATED = 8;

export function createZip(files: ReadonlyMap<string, Uint8Array>): Uint8Array {
  const zippable: Zippable = {};
  for (const [path, data] of files) zippable[path] = [data, { level: DEFLATE_LEVEL }];
  return zipSync(zippable);
}

export function readZip(data: Uint8Array, limits?: ArchiveLimits): Map<string, Uint8Array> {
  let entries = 0;
  let total = 0;
  const filter = limits
    ? (file: { name: string; originalSize: number; compression: number }) => {
        entries += 1;
        total += file.originalSize;
        if (entries > limits.maxEntries) throw new ArchiveError(`more than ${limits.maxEntries} entries`);
        if (file.compression !== STORED && file.compression !== DEFLATED) {
          throw new ArchiveError(`${file.name}: unsupported compression method ${file.compression}`);
        }
        if (file.originalSize > limits.maxEntryBytes) {
          throw new ArchiveError(`${file.name}: declared size ${file.originalSize} exceeds ${limits.maxEntryBytes}`);
        }
        if (total > limits.maxTotalBytes) throw new ArchiveError(`declared total exceeds ${limits.maxTotalBytes}`);
        return true;
      }
    : undefined;
  try {
    return new Map(Object.entries(unzipSync(data, filter ? { filter } : {})));
  } catch (err) {
    if (err instanceof ArchiveError) throw err;
    throw new ArchiveError(`invalid zip archive: ${err instanceof Error ? err.message : String(err)}`);
  }
}
