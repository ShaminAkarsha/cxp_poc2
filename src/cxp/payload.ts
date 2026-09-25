/**
 * Credential payload (CXP §3.4): a zip whose files are each a JWE, laid out as
 *
 *   CXP-Export/index.jwe            { header, documents }        (GAP-10)
 *   CXP-Export/documents/<name>.jwe one CXF Item per file        (GAP-08, GAP-10)
 *
 * spec-minimal: one key exported from the HPKE context for every file
 * (GAP-07), no binding beyond the JWE header (GAP-09), names from Item IDs
 * (GAP-08), no manifest (GAP-10), no size limits (GAP-12), no zeroing (GAP-13).
 * hardened closes each of these, selected by the policy flags named below.
 */
import { createHash, randomBytes } from "node:crypto";
import { createZip, DEFAULT_ARCHIVE_LIMITS, readZip } from "../crypto/archive.js";
import { exportSecret, setupRecipient, setupSender, type SuiteIds } from "../crypto/hpke.js";
import { CEK_LENGTH, decryptJwe, encryptJwe, jweEncForAead, type JweEnc } from "../crypto/jwe.js";
import { encodeB64url, normaliseCxfHeader, parseCxfHeader, type Header, type Item } from "../cxf/index.js";
import { isEnabled, type Policy } from "../policy/index.js";
import { CxpPayloadError } from "./schema.js";

export const PAYLOAD_ROOT = "CXP-Export/";
export const INDEX_PATH = `${PAYLOAD_ROOT}index.jwe`;
export const DOCUMENTS_DIR = `${PAYLOAD_ROOT}documents/`;

/** GAP-07 (spec-minimal): RFC 9180 §5.3 exporter context for the single payload key. */
export const PAYLOAD_KEY_CONTEXT = new TextEncoder().encode("CXP payload key");

/** GAP-07 (hardened): per-file exporter context = label || file path. */
const FILE_KEY_LABEL = "CXP file key ";

/** GAP-09 (hardened): JWE protected-header members binding a file to its path and request. */
export const PATH_HEADER = "cxp-path";
export const REQUEST_HEADER = "cxp-req";

/** Plaintext of index.jwe (GAP-10). */
export interface PayloadIndex {
  /** CXF Header with every Account's `items` emptied. */
  readonly header: Header;
  /** Where each Item went; `sha256` of the stored JWE when GAP-10 is closed. */
  readonly documents: readonly { readonly path: string; readonly account: string; readonly sha256?: string }[];
}

export interface PayloadBinding {
  readonly policy: Policy;
  /** RFC 9180 `info` (see binding.ts, GAP-01). */
  readonly info: Uint8Array;
  /** SHA-256 of the canonical request (GAP-09 AAD). */
  readonly requestDigest: Uint8Array;
}

function jweEncFor(suite: SuiteIds): JweEnc {
  const enc = jweEncForAead(suite.aead);
  if (enc === undefined) throw new CxpPayloadError(`AEAD ${suite.aead} has no JWE mapping (GAP-07)`);
  return enc;
}

const encodeJson = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const sha256b64 = (data: Uint8Array) => encodeB64url(new Uint8Array(createHash("sha256").update(data).digest()));

function decodeJson(bytes: Uint8Array, what: string): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (err) {
    throw new CxpPayloadError(`${what} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Document path: Item ID (GAP-08 spec-minimal) or a random 128-bit name (hardened). */
function documentPath(item: Item, policy: Policy): string {
  const name = isEnabled(policy, "randomizeFileNames") ? encodeB64url(new Uint8Array(randomBytes(16))) : item.id;
  return `${DOCUMENTS_DIR}${name}.jwe`;
}

type Context = Parameters<typeof exportSecret>[0];

/** Content-encryption key for a file (GAP-07). */
async function fileKey(context: Context, policy: Policy, path: string, length: number): Promise<Uint8Array> {
  const label = isEnabled(policy, "deriveFileKeysViaExport")
    ? new TextEncoder().encode(FILE_KEY_LABEL + path)
    : PAYLOAD_KEY_CONTEXT;
  return exportSecret(context, label, length);
}

/** Extra protected-header members for a file (GAP-09). */
function fileHeader(binding: PayloadBinding, path: string): Record<string, string> {
  if (!isEnabled(binding.policy, "bindFileAad")) return {};
  return { [PATH_HEADER]: path, [REQUEST_HEADER]: encodeB64url(binding.requestDigest) };
}

export interface SealedPayload {
  /** RFC 9180 `enc`, sent to the importer in ExportResponse.hpke.key. */
  readonly enc: Uint8Array;
  /** Zip archive bytes. */
  readonly archive: Uint8Array;
}

/** Exporter: encrypt a CXF document for the importer's public key. */
export async function sealPayload(params: {
  readonly header: Header;
  readonly suite: SuiteIds;
  readonly recipientPublicKey: CryptoKey;
  readonly binding: PayloadBinding;
  /** Exporter's static key pair: HPKE auth mode (GAP-14). */
  readonly senderKey?: CryptoKeyPair;
}): Promise<SealedPayload> {
  const { binding } = params;
  const enc = jweEncFor(params.suite);
  const context = await setupSender({
    suite: params.suite,
    recipientPublicKey: params.recipientPublicKey,
    info: binding.info,
    ...(params.senderKey ? { senderKey: params.senderKey } : {}),
  });
  const manifest = isEnabled(binding.policy, "authenticateManifest");

  const seal = async (path: string, value: unknown) => {
    const cek = await fileKey(context, binding.policy, path, CEK_LENGTH[enc]);
    const jwe = new TextEncoder().encode(await encryptJwe(encodeJson(value), cek, enc, fileHeader(binding, path)));
    cek.fill(0);
    return jwe;
  };

  const header = normaliseCxfHeader(params.header); // CXF §2.1.2 (MUST) array encoding
  const files = new Map<string, Uint8Array>();
  const documents: { path: string; account: string; sha256?: string }[] = [];
  for (const account of header.accounts) {
    for (const item of account.items) {
      const path = documentPath(item, binding.policy);
      if (files.has(path)) throw new CxpPayloadError(`duplicate document path ${path}`);
      const jwe = await seal(path, item);
      files.set(path, jwe);
      // GAP-10 (hardened): the encrypted index lists each document's digest.
      documents.push({ path, account: account.id, ...(manifest ? { sha256: sha256b64(jwe) } : {}) });
    }
  }
  const index: PayloadIndex = {
    header: { ...header, accounts: header.accounts.map((a) => ({ ...a, items: [] })) },
    documents,
  };
  files.set(INDEX_PATH, await seal(INDEX_PATH, index));

  return { enc: new Uint8Array(context.enc), archive: createZip(files) };
}

/** Importer: decrypt the payload and reassemble the CXF document. */
export async function openPayload(params: {
  readonly archive: Uint8Array;
  readonly suite: SuiteIds;
  readonly recipientKey: CryptoKeyPair;
  readonly enc: Uint8Array;
  readonly binding: PayloadBinding;
  /** Exporter's static public key: HPKE auth mode (GAP-14). */
  readonly senderPublicKey?: CryptoKey;
}): Promise<Header> {
  const { binding } = params;
  const { policy } = binding;
  const jweEnc = jweEncFor(params.suite);
  let context;
  try {
    context = await setupRecipient({
      suite: params.suite,
      recipientKey: params.recipientKey,
      enc: params.enc,
      info: binding.info,
      ...(params.senderPublicKey ? { senderPublicKey: params.senderPublicKey } : {}),
    });
  } catch (err) {
    throw new CxpPayloadError(`HPKE decapsulation failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  // GAP-12 (hardened): check declared sizes before inflating anything.
  const files = readZip(params.archive, isEnabled(policy, "enforceDecompressionLimits") ? DEFAULT_ARCHIVE_LIMITS : undefined);
  const zeroize = isEnabled(policy, "zeroizeKeyMaterial");
  const expectedRequest = encodeB64url(binding.requestDigest);

  const decryptFile = async (path: string) => {
    const data = files.get(path);
    if (data === undefined) return undefined;
    const cek = await fileKey(context, policy, path, CEK_LENGTH[jweEnc]);
    try {
      const { plaintext, protectedHeader } = await decryptJwe(new TextDecoder().decode(data), cek, jweEnc);
      // GAP-09 (hardened): the authenticated header must name this path and this request.
      if (isEnabled(policy, "bindFileAad")) {
        if (protectedHeader[PATH_HEADER] !== path) throw new CxpPayloadError(`${path}: file is bound to another path`);
        if (protectedHeader[REQUEST_HEADER] !== expectedRequest) {
          throw new CxpPayloadError(`${path}: file is bound to another request`);
        }
      }
      const value = decodeJson(plaintext, path);
      if (zeroize) plaintext.fill(0); // GAP-13 (hardened), best effort
      return value;
    } finally {
      if (zeroize) cek.fill(0); // GAP-13 (hardened)
    }
  };

  const indexJson = await decryptFile(INDEX_PATH);
  if (indexJson === undefined) throw new CxpPayloadError(`archive has no ${INDEX_PATH}`);
  const index = indexJson as { header?: unknown; documents?: unknown };
  if (typeof index.header !== "object" || index.header === null || !Array.isArray(index.documents)) {
    throw new CxpPayloadError("index.jwe is not {header, documents}");
  }
  const listed = index.documents as { path?: unknown; account?: unknown; sha256?: unknown }[];

  // GAP-10 (hardened): the archive must hold exactly the listed documents, byte for byte.
  if (isEnabled(policy, "authenticateManifest")) {
    const paths = new Set<string>();
    for (const entry of listed) {
      if (typeof entry.path !== "string" || typeof entry.sha256 !== "string") {
        throw new CxpPayloadError("manifest entry without path or sha256");
      }
      if (paths.has(entry.path)) throw new CxpPayloadError(`manifest lists ${entry.path} twice`);
      paths.add(entry.path);
      const data = files.get(entry.path);
      if (data === undefined) throw new CxpPayloadError(`manifest lists missing document ${entry.path}`);
      if (sha256b64(data) !== entry.sha256) throw new CxpPayloadError(`${entry.path} does not match the manifest`);
    }
    for (const name of files.keys()) {
      if (name !== INDEX_PATH && !paths.has(name)) throw new CxpPayloadError(`unlisted file ${name} in archive`);
    }
  }

  // Reassemble: raw JSON first, validated as a whole by parseCxfHeader below.
  const header = structuredClone(index.header) as { accounts?: { id?: unknown; items?: unknown[] }[] };
  const accounts = new Map((header.accounts ?? []).map((a) => [a.id, a]));
  for (const entry of listed) {
    if (typeof entry.path !== "string") continue;
    // GAP-10 (spec-minimal): a listed document that is missing is skipped, and
    // so is one whose account is not in the index; unlisted files are ignored.
    const account = accounts.get(entry.account);
    const item = await decryptFile(entry.path);
    if (account === undefined || item === undefined) continue;
    (account.items ??= []).push(item);
  }
  return parseCxfHeader(header, policy);
}
