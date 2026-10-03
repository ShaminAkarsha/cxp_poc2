/**
 * A-06 / GAP-07, GAP-09: swap two document files inside a response archive.
 * Under spec-minimal (no per-file AAD, shared key), the swap is undetected.
 */
import { createZip, readZip } from "../crypto/archive.js";
import { decodeB64url, encodeB64url } from "../cxf/b64url.js";
import type { ExportResponse } from "../cxp/schema.js";

export function swapArchiveDocuments(
  response: ExportResponse,
  pathA: string,
  pathB: string,
): ExportResponse {
  const files = readZip(decodeB64url(response.payload));
  const a = files.get(pathA);
  const b = files.get(pathB);
  if (!a || !b) throw new Error(`cannot swap: missing ${pathA} or ${pathB}`);
  files.set(pathA, b);
  files.set(pathB, a);
  return { ...response, payload: encodeB64url(createZip(files)) };
}
