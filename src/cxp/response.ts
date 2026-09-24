/**
 * Export Response (CXP §3.3): built by the exporter from a request and a CXF
 * document; opened by the importer with its keyring.
 */
import { jwkToPublicKey, jwkToPublicKeyBytes, publicKeyBytesToJwk } from "../crypto/hpke.js";
import { decodeB64url, encodeB64url, type Header } from "../cxf/index.js";
import type { Policy } from "../policy/index.js";
import {
  correspondingEntry,
  DEFAULT_EXPORTER_CAPABILITIES,
  selectArchive,
  selectHpkeParameters,
  type ExporterCapabilities,
} from "./negotiate.js";
import { openPayload, sealPayload } from "./payload.js";
import type { ImporterKeyring } from "./request.js";
import {
  CXP_VERSION,
  CxpNegotiationError,
  CxpValidationError,
  parseExportResponse,
  type ExportRequest,
  type ExportResponse,
} from "./schema.js";

export interface CreateExportResponseOptions {
  readonly request: ExportRequest;
  /** CXF document to export (already filtered by the exporter). */
  readonly header: Header;
  /** CXP §3.3 `exporter`: the exporter's RP ID (self-asserted — GAP-05). */
  readonly exporter: string;
  readonly capabilities?: ExporterCapabilities;
}

export async function createExportResponse(options: CreateExportResponseOptions): Promise<ExportResponse> {
  const capabilities = options.capabilities ?? DEFAULT_EXPORTER_CAPABILITIES;
  const selected = selectHpkeParameters(options.request.hpke, capabilities);
  if (selected?.key === undefined) throw new CxpNegotiationError("no mutually supported HPKE parameters");
  const archive = selectArchive(options.request.archive, capabilities);
  if (archive === undefined) throw new CxpNegotiationError("no mutually supported archive algorithm");

  const suite = { kem: selected.kem, kdf: selected.kdf, aead: selected.aead };
  const recipientPublicKey = await jwkToPublicKey(selected.kem, selected.key);
  const sealed = await sealPayload({ header: options.header, suite, recipientPublicKey });

  return {
    version: CXP_VERSION,
    // CXP §3.3 (MUST) corresponds to a request entry (GAP-28); `key` is the
    // exporter's key the importer needs, here the HPKE `enc` (GAP-07).
    hpke: { mode: selected.mode, ...suite, key: jwkFor(selected.kem, sealed.enc) },
    archive, // CXP §3.3 (MUST) corresponds to an entry in the request `archive`
    exporter: options.exporter,
    payload: encodeB64url(sealed.archive),
  };
}

function jwkFor(kem: number, enc: Uint8Array): { kty: string } {
  const jwk = publicKeyBytesToJwk(kem, enc);
  return { ...jwk, kty: jwk.kty ?? "" };
}

export interface OpenExportResponseOptions {
  readonly request: ExportRequest;
  readonly response: unknown;
  readonly keyring: ImporterKeyring;
  readonly policy: Policy;
  /** Archive algorithms the importer can unpack. */
  readonly supportedArchives?: readonly string[];
}

/**
 * Importer: validate and decrypt an Export Response.
 *
 * Checked in both profiles: the response is well formed; its `hpke`
 * corresponds to a request entry (GAP-28; otherwise the importer has no key);
 * its `archive` is one the importer listed and can unpack (GAP-03, spec-minimal
 * column). Not checked: version (GAP-04), exporter identity (GAP-05/22),
 * freshness or replay (GAP-11/21) — spec-minimal, hardened in M7.
 */
export async function openExportResponse(options: OpenExportResponseOptions): Promise<Header> {
  const response = parseExportResponse(options.response);

  const entry = correspondingEntry(options.request.hpke, response.hpke);
  if (entry === undefined) throw new CxpNegotiationError("response hpke does not correspond to any request entry");
  const recipientKey = options.keyring.get(entry.kem);
  if (recipientKey === undefined) throw new CxpNegotiationError(`no importer key for KEM ${entry.kem}`);

  if (!options.request.archive.includes(response.archive)) {
    throw new CxpNegotiationError(`archive ${response.archive} was not offered`);
  }
  if (!(options.supportedArchives ?? DEFAULT_EXPORTER_CAPABILITIES.archives).includes(response.archive)) {
    throw new CxpNegotiationError(`archive ${response.archive} is not supported`);
  }

  if (response.hpke.key === undefined) throw new CxpValidationError("response hpke.key (enc) is missing");
  let enc: Uint8Array;
  try {
    enc = jwkToPublicKeyBytes(entry.kem, response.hpke.key);
  } catch (err) {
    throw new CxpValidationError(`response hpke.key is invalid: ${err instanceof Error ? err.message : String(err)}`);
  }

  return openPayload({
    archive: decodeB64url(response.payload),
    suite: { kem: entry.kem, kdf: entry.kdf, aead: entry.aead },
    recipientKey,
    enc,
    policy: options.policy,
  });
}
