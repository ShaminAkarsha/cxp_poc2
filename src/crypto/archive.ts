/**
 * Zip archive for the CXP credential payload (CXP §3.4 "MUST follow the zip
 * archive format"; layout undefined — GAP-10). Entries are DEFLATE-compressed
 * (CXP §3.5.3 `deflate`; what is compressed is unspecified — GAP-27).
 *
 * Inflation has no size limit here; decompression limits are GAP-12 (M7).
 */
import { unzipSync, zipSync, type Zippable } from "fflate";

export class ArchiveError extends Error {
  override name = "ArchiveError";
}

/** DEFLATE level for entries (zip compression method 8). */
const DEFLATE_LEVEL = 6;

export function createZip(files: ReadonlyMap<string, Uint8Array>): Uint8Array {
  const zippable: Zippable = {};
  for (const [path, data] of files) zippable[path] = [data, { level: DEFLATE_LEVEL }];
  return zipSync(zippable);
}

export function readZip(data: Uint8Array): Map<string, Uint8Array> {
  try {
    return new Map(Object.entries(unzipSync(data)));
  } catch (err) {
    throw new ArchiveError(`invalid zip archive: ${err instanceof Error ? err.message : String(err)}`);
  }
}
