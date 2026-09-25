/**
 * Export Response (CXP §3.3): built by the exporter from a request and a CXF
 * document; opened by the importer with its keyring.
 */
import {
  jwkToPublicKey,
  jwkToPublicKeyBytes,
  MTI_SUITE,
  publicKeyBytesToJwk,
  publicKeyToJwk,
} from "../crypto/hpke.js";
import { decodeB64url, encodeB64url, isCanonicalB64url, type Header } from "../cxf/index.js";
import { getPolicy, isEnabled, type Policy } from "../policy/index.js";
import { CHALLENGE_BYTES, hpkeInfo, keyFingerprint, requestDigest } from "./binding.js";
import {
  capabilitiesFor,
  correspondingEntry,
  DEFAULT_EXPORTER_CAPABILITIES,
  selectArchive,
  selectHpkeParameters,
  type ExporterCapabilities,
} from "./negotiate.js";
import { openPayload, sealPayload, type PayloadBinding } from "./payload.js";
import type { ImporterKeyring } from "./request.js";
import {
  CXP_VERSION,
  CxpError,
  CxpNegotiationError,
  CxpValidationError,
  parseExportResponse,
  type ExportRequest,
  type ExportResponse,
} from "./schema.js";

/** GAP-14 (hardened): response `hpke` member carrying the exporter's static public key (pkS). */
export const SENDER_KEY_MEMBER = "senderKey";

/** GAP-21 (hardened): tolerated clock skew, seconds. */
export const CLOCK_SKEW_SECONDS = 300;

/** GAP-12 (hardened): largest accepted `payload` (base64url characters, ~48 MiB decoded). */
export const MAX_PAYLOAD_CHARS = 64 << 20;

export class CxpRejectedError extends CxpError {
  override name = "CxpRejectedError";
}

function bindingFor(policy: Policy, request: ExportRequest): PayloadBinding {
  return { policy, info: hpkeInfo(policy, request), requestDigest: requestDigest(request) };
}

export interface CreateExportResponseOptions {
  readonly request: ExportRequest;
  /** CXF document to export (already filtered by the exporter). */
  readonly header: Header;
  /** CXP §3.3 `exporter`: the exporter's RP ID (self-asserted — GAP-05). */
  readonly exporter: string;
  /** Defaults to spec-minimal. */
  readonly policy?: Policy;
  readonly capabilities?: ExporterCapabilities;
  /** Exporter's static HPKE key pair, needed for `auth` mode (GAP-14). */
  readonly senderKey?: CryptoKeyPair;
}

export async function createExportResponse(options: CreateExportResponseOptions): Promise<ExportResponse> {
  const policy = options.policy ?? getPolicy("spec-minimal");
  const { request } = options;

  // GAP-01 (hardened): only answer requests that carry a fresh challenge.
  if (isEnabled(policy, "bindRequestChallenge")) {
    const challenge = request.challenge;
    if (typeof challenge !== "string" || !isCanonicalB64url(challenge) || decodeB64url(challenge).length !== CHALLENGE_BYTES) {
      throw new CxpRejectedError("request has no valid challenge (GAP-01)");
    }
  }

  const capabilities = options.capabilities ?? (options.policy ? capabilitiesFor(policy) : DEFAULT_EXPORTER_CAPABILITIES);
  const selected = selectHpkeParameters(request.hpke, capabilities);
  if (selected?.key === undefined) throw new CxpNegotiationError("no mutually supported HPKE parameters");
  const archive = selectArchive(request.archive, capabilities);
  if (archive === undefined) throw new CxpNegotiationError("no mutually supported archive algorithm");

  const auth = selected.mode === "auth";
  if (auth && options.senderKey === undefined) throw new CxpNegotiationError("auth mode needs the exporter's static key");

  const suite = { kem: selected.kem, kdf: selected.kdf, aead: selected.aead };
  const recipientPublicKey = await jwkToPublicKey(selected.kem, selected.key);
  const sealed = await sealPayload({
    header: options.header,
    suite,
    recipientPublicKey,
    binding: bindingFor(policy, request),
    ...(auth && options.senderKey ? { senderKey: options.senderKey } : {}),
  });

  const senderJwk = auth && options.senderKey ? jwk(await publicKeyToJwk(selected.kem, options.senderKey.publicKey)) : undefined;
  return {
    version: CXP_VERSION,
    // CXP §3.3 (MUST) corresponds to a request entry (GAP-28); `key` is the
    // exporter's key the importer needs, here the HPKE `enc` (GAP-07).
    hpke: {
      mode: selected.mode,
      ...suite,
      key: jwk(publicKeyBytesToJwk(selected.kem, sealed.enc)),
      ...(senderJwk ? { [SENDER_KEY_MEMBER]: senderJwk } : {}),
    },
    archive, // CXP §3.3 (MUST) corresponds to an entry in the request `archive`
    exporter: options.exporter,
    payload: encodeB64url(sealed.archive),
  };
}

function jwk(value: JsonWebKey): { kty: string } {
  return { ...value, kty: value.kty ?? "" };
}

/** Shown to the user before trusting the exporter's static key (GAP-05, GAP-14). */
export interface ExporterConfirmation {
  readonly exporter: string;
  readonly fingerprint: string;
}

export interface OpenExportResponseOptions {
  readonly request: ExportRequest;
  readonly response: unknown;
  readonly keyring: ImporterKeyring;
  readonly policy: Policy;
  /** Archive algorithms the importer can unpack. */
  readonly supportedArchives?: readonly string[];
  /** UNIX seconds when the request was created (GAP-21). */
  readonly requestCreatedAt?: number;
  readonly now?: () => number;
  /** The user compares the exporter's fingerprint with the one the exporter displays (GAP-05, GAP-14). */
  readonly confirmExporter?: (confirmation: ExporterConfirmation) => Promise<boolean> | boolean;
}

/**
 * Importer: validate and decrypt an Export Response.
 *
 * Both profiles: well formed; `hpke` corresponds to a request entry (GAP-28);
 * `archive` was offered and is supported (GAP-03, spec-minimal column).
 * Hardened adds GAP-01/02/03/04/05/12/14/21/22 checks, each marked below.
 */
export async function openExportResponse(options: OpenExportResponseOptions): Promise<Header> {
  const { policy, request } = options;
  const on = (flag: Parameters<typeof isEnabled>[1]) => isEnabled(policy, flag);
  const response = parseExportResponse(options.response);

  // GAP-12 (hardened): bound the payload before decoding it.
  if (on("enforceDecompressionLimits") && response.payload.length > MAX_PAYLOAD_CHARS) {
    throw new CxpRejectedError("payload exceeds the size limit (GAP-12)");
  }

  const entry = correspondingEntry(request.hpke, response.hpke);
  if (entry === undefined) throw new CxpNegotiationError("response hpke does not correspond to any request entry");
  const recipientKey = options.keyring.get(entry.kem);
  if (recipientKey === undefined) throw new CxpNegotiationError(`no importer key for KEM ${entry.kem}`);

  const supported = options.supportedArchives ?? DEFAULT_EXPORTER_CAPABILITIES.archives;
  if (!request.archive.includes(response.archive)) throw new CxpNegotiationError(`archive ${response.archive} was not offered`);
  if (!supported.includes(response.archive)) throw new CxpNegotiationError(`archive ${response.archive} is not supported`);

  // GAP-02 (hardened): only the mandatory-to-implement suite.
  if (on("enforceMandatorySuite") && (entry.kem !== MTI_SUITE.kem || entry.kdf !== MTI_SUITE.kdf || entry.aead !== MTI_SUITE.aead)) {
    throw new CxpRejectedError("response suite is not the mandatory-to-implement suite (GAP-02)");
  }
  // GAP-03 (hardened): the exporter must have taken the importer's first choices.
  if (on("verifyNegotiatedSelection")) {
    if (request.hpke[0] !== entry) throw new CxpRejectedError("exporter did not select the first HPKE entry (GAP-03)");
    if (request.archive.find((a) => supported.includes(a)) !== response.archive) {
      throw new CxpRejectedError("exporter did not select the first supported archive (GAP-03)");
    }
  }
  // GAP-04 (hardened): no version downgrade.
  if (on("rejectVersionDowngrade") && response.version < request.version) {
    throw new CxpRejectedError(`response version ${response.version} is below requested ${request.version} (GAP-04)`);
  }

  // GAP-14: in auth mode the exporter's static key authenticates the payload.
  if (on("requireHpkeAuthMode") && entry.mode !== "auth") throw new CxpRejectedError("response is not in HPKE auth mode (GAP-14)");
  let senderPublicKey: CryptoKey | undefined;
  if (entry.mode === "auth") {
    const senderJwk = (response.hpke as Record<string, unknown>)[SENDER_KEY_MEMBER];
    if (typeof senderJwk !== "object" || senderJwk === null) throw new CxpValidationError("auth-mode response has no sender key");
    try {
      senderPublicKey = await jwkToPublicKey(entry.kem, senderJwk as Record<string, unknown>);
    } catch (err) {
      throw new CxpValidationError(`sender key is invalid: ${err instanceof Error ? err.message : String(err)}`);
    }
    // GAP-05 (hardened): the user confirms the exporter key's fingerprint.
    if (on("requireSasConfirmation")) {
      const fingerprint = await keyFingerprint(senderJwk as Record<string, unknown>);
      const confirmed = await options.confirmExporter?.({ exporter: response.exporter, fingerprint });
      if (confirmed !== true) throw new CxpRejectedError("exporter key was not confirmed by the user (GAP-05)");
    }
  }

  if (response.hpke.key === undefined) throw new CxpValidationError("response hpke.key (enc) is missing");
  let enc: Uint8Array;
  try {
    enc = jwkToPublicKeyBytes(entry.kem, response.hpke.key);
  } catch (err) {
    throw new CxpValidationError(`response hpke.key is invalid: ${err instanceof Error ? err.message : String(err)}`);
  }

  const header = await openPayload({
    archive: decodeB64url(response.payload),
    suite: { kem: entry.kem, kdf: entry.kdf, aead: entry.aead },
    recipientKey,
    enc,
    binding: bindingFor(policy, request),
    ...(senderPublicKey ? { senderPublicKey } : {}),
  });

  // GAP-22 (hardened): the exporter named inside the encrypted document must be the one in the response.
  if (on("bindExporterIdentity") && header.exporterRpId !== response.exporter) {
    throw new CxpRejectedError(`CXF exporterRpId ${header.exporterRpId} differs from response exporter ${response.exporter} (GAP-22)`);
  }
  // GAP-21 (hardened): the document must be fresh.
  if (on("enforceTimestampFreshness")) {
    const now = options.now?.() ?? Math.floor(Date.now() / 1000);
    if (header.timestamp > now + CLOCK_SKEW_SECONDS) throw new CxpRejectedError("CXF timestamp is in the future (GAP-21)");
    if (options.requestCreatedAt !== undefined && header.timestamp < options.requestCreatedAt - CLOCK_SKEW_SECONDS) {
      throw new CxpRejectedError("CXF document predates the Export Request (GAP-21)");
    }
  }
  return header;
}
