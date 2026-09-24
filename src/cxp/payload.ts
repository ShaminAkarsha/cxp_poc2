/**
 * Credential payload (CXP §3.4): a zip whose files are each a JWE, laid out as
 *
 *   CXP-Export/index.jwe            { header, documents }        (GAP-10)
 *   CXP-Export/documents/<id>.jwe   one CXF Item per file        (GAP-08, GAP-10)
 *
 * All files are encrypted under one key exported from the HPKE context
 * (GAP-07). `info` is empty (GAP-01), files carry no AAD beyond the JWE
 * protected header (GAP-09), and names come from CXF Item IDs (GAP-08).
 * These are the spec-minimal choices; the hardened variants arrive in M7.
 */
import { exportSecret, setupRecipient, setupSender, type SuiteIds } from "../crypto/hpke.js";
import { CEK_LENGTH, decryptJwe, encryptJwe, jweEncForAead, type JweEnc } from "../crypto/jwe.js";
import { createZip, readZip } from "../crypto/archive.js";
import { normaliseCxfHeader, parseCxfHeader, type Header, type Item } from "../cxf/index.js";
import type { Policy } from "../policy/index.js";
import { CxpPayloadError } from "./schema.js";

export const PAYLOAD_ROOT = "CXP-Export/";
export const INDEX_PATH = `${PAYLOAD_ROOT}index.jwe`;
export const DOCUMENTS_DIR = `${PAYLOAD_ROOT}documents/`;

/** GAP-07: RFC 9180 §5.3 exporter context for the single payload key. */
export const PAYLOAD_KEY_CONTEXT = new TextEncoder().encode("CXP payload key");

/** Plaintext of index.jwe (GAP-10). */
export interface PayloadIndex {
  /** CXF Header with every Account's `items` emptied. */
  readonly header: Header;
  /** Where each Item went. */
  readonly documents: readonly { readonly path: string; readonly account: string }[];
}

function jweEncFor(suite: SuiteIds): JweEnc {
  const enc = jweEncForAead(suite.aead);
  if (enc === undefined) throw new CxpPayloadError(`AEAD ${suite.aead} has no JWE mapping (GAP-07)`);
  return enc;
}

const encodeJson = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

function decodeJson(bytes: Uint8Array, what: string): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (err) {
    throw new CxpPayloadError(`${what} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** GAP-08 (spec-minimal): a document's file name is its CXF Item ID. */
export function documentPath(item: Item): string {
  return `${DOCUMENTS_DIR}${item.id}.jwe`;
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
}): Promise<SealedPayload> {
  const enc = jweEncFor(params.suite);
  const context = await setupSender({ suite: params.suite, recipientPublicKey: params.recipientPublicKey });
  const cek = await exportSecret(context, PAYLOAD_KEY_CONTEXT, CEK_LENGTH[enc]);

  const header = normaliseCxfHeader(params.header); // CXF §2.1.2 (MUST) array encoding
  const files = new Map<string, Uint8Array>();
  const documents: { path: string; account: string }[] = [];
  for (const account of header.accounts) {
    for (const item of account.items) {
      const path = documentPath(item);
      if (files.has(path)) throw new CxpPayloadError(`duplicate document path ${path}`);
      files.set(path, new TextEncoder().encode(await encryptJwe(encodeJson(item), cek, enc)));
      documents.push({ path, account: account.id });
    }
  }
  const index: PayloadIndex = {
    header: { ...header, accounts: header.accounts.map((a) => ({ ...a, items: [] })) },
    documents,
  };
  files.set(INDEX_PATH, new TextEncoder().encode(await encryptJwe(encodeJson(index), cek, enc)));

  return { enc: new Uint8Array(context.enc), archive: createZip(files) };
}

/** Importer: decrypt the payload and reassemble the CXF document. */
export async function openPayload(params: {
  readonly archive: Uint8Array;
  readonly suite: SuiteIds;
  readonly recipientKey: CryptoKeyPair;
  readonly enc: Uint8Array;
  readonly policy: Policy;
}): Promise<Header> {
  const jweEnc = jweEncFor(params.suite);
  let context;
  try {
    context = await setupRecipient({ suite: params.suite, recipientKey: params.recipientKey, enc: params.enc });
  } catch (err) {
    throw new CxpPayloadError(`HPKE decapsulation failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  const cek = await exportSecret(context, PAYLOAD_KEY_CONTEXT, CEK_LENGTH[jweEnc]);
  const files = readZip(params.archive);

  const decryptFile = async (path: string) => {
    const data = files.get(path);
    if (data === undefined) return undefined;
    const { plaintext } = await decryptJwe(new TextDecoder().decode(data), cek, jweEnc);
    return decodeJson(plaintext, path);
  };

  const indexJson = await decryptFile(INDEX_PATH);
  if (indexJson === undefined) throw new CxpPayloadError(`archive has no ${INDEX_PATH}`);
  const index = indexJson as { header?: unknown; documents?: unknown };
  if (typeof index.header !== "object" || index.header === null || !Array.isArray(index.documents)) {
    throw new CxpPayloadError("index.jwe is not {header, documents}");
  }

  // Reassemble: raw JSON first, validated as a whole by parseCxfHeader below.
  const header = structuredClone(index.header) as { accounts?: { id?: unknown; items?: unknown[] }[] };
  const accounts = new Map((header.accounts ?? []).map((a) => [a.id, a]));
  for (const entry of index.documents as { path?: unknown; account?: unknown }[]) {
    if (typeof entry.path !== "string") continue;
    // GAP-10 (spec-minimal): a listed document that is missing is skipped, and
    // so is one whose account is not in the index; unlisted files are ignored.
    const account = accounts.get(entry.account);
    const item = await decryptFile(entry.path);
    if (account === undefined || item === undefined) continue;
    (account.items ??= []).push(item);
  }
  return parseCxfHeader(header, params.policy);
}
