/**
 * CXP message schemas (CXP WD 2024-10-03 §3.2, §3.3, §3.5).
 *
 * Objects are loose: CXP does not say whether unknown members are ignored,
 * so both profiles ignore and keep them, as CXF §3.1.1 does (GAP-26).
 */
import { z } from "zod";
import { B64url } from "../cxf/schema.js";

/** CDDL `uint .size 2`. */
const Uint16 = z.int().min(0).max(0xffff);

/** CXP §3.2 (MUST) version corresponds to a published CXP level; none exists — GAP-24. */
export const CXP_VERSION = 0;

/** CXP §3.2.2. */
export const RESPONSE_MODES = ["direct", "indirect", "self"] as const;
export type ResponseMode = (typeof RESPONSE_MODES)[number];

/** CXP §3.5.3. */
export const ARCHIVE_DEFLATE = "deflate";

/** RFC 7517 JWK; members are checked when the key is used (src/crypto/hpke.ts). */
export const JwkSchema = z.looseObject({ kty: z.string() });

/**
 * CXP §3.5.1. `mode` is `HPKEMode / tstr`. `key` is required by the CDDL but
 * "only present" without a pre-shared key per the prose — GAP-26.
 */
export const HpkeParametersSchema = z.looseObject({
  mode: z.string(),
  kem: Uint16,
  kdf: Uint16,
  aead: Uint16,
  key: JwkSchema.optional(),
});

/** CXP §3.2. */
export const ExportRequestSchema = z.looseObject({
  version: Uint16,
  hpke: z.array(HpkeParametersSchema).min(1), // [ + HpkeParameters ]
  archive: z.array(z.string()).min(1), // [ + ArchiveAlgorithm / tstr ]
  mode: z.string(),
  importer: z.string(),
  // CDDL says [ + ... ] but the prose gives an empty list a meaning — GAP-26.
  credentialTypes: z.array(z.string()).optional(),
  knownExtensions: z.array(z.string()).optional(),
});

/** CXP §3.3. */
export const ExportResponseSchema = z.looseObject({
  version: Uint16,
  hpke: HpkeParametersSchema,
  archive: z.string(),
  exporter: z.string(),
  payload: B64url,
});

export type Jwk = z.infer<typeof JwkSchema>;
export type HpkeParameters = z.infer<typeof HpkeParametersSchema>;
export type ExportRequest = z.infer<typeof ExportRequestSchema>;
export type ExportResponse = z.infer<typeof ExportResponseSchema>;

export class CxpError extends Error {
  override name = "CxpError";
}

export class CxpValidationError extends CxpError {
  override name = "CxpValidationError";
}

export class CxpNegotiationError extends CxpError {
  override name = "CxpNegotiationError";
}

export class CxpPayloadError extends CxpError {
  override name = "CxpPayloadError";
}

function parseWith<T>(schema: z.ZodType<T>, input: unknown, what: string): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `$.${i.path.join(".")}: ${i.message}`).join("; ");
    throw new CxpValidationError(`Malformed ${what}: ${issues}`);
  }
  return result.data;
}

function parseJson(json: string, what: string): unknown {
  try {
    return JSON.parse(json);
  } catch (err) {
    throw new CxpValidationError(`${what} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
}

export const parseExportRequest = (input: unknown) => parseWith(ExportRequestSchema, input, "ExportRequest");
export const parseExportResponse = (input: unknown) => parseWith(ExportResponseSchema, input, "ExportResponse");

/** CXP §3.2.1 (SHALL): the Export Request file is a JSON-encoded document. */
export const parseExportRequestJson = (json: string) => parseExportRequest(parseJson(json, "Export Request"));
export const serializeExportRequest = (request: ExportRequest) => JSON.stringify(request);

/** CXP §3.3 (SHALL): a response that cannot be received directly is stored as a JSON document. */
export const parseExportResponseJson = (json: string) => parseExportResponse(parseJson(json, "Export Response"));
export const serializeExportResponse = (response: ExportResponse) => JSON.stringify(response);
