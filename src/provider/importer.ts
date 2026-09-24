/**
 * Importing provider (CXP §2.1 "Importer"): starts the exchange with an
 * Export Request, opens the Export Response and stores the passkeys.
 *
 * spec-minimal behaviour; hardened flags arrive in M7. Notably: the importer
 * key is kept after import, so a response can be imported again (GAP-11); an
 * imported credential replaces an existing one (GAP-30); and a response is
 * matched to the latest pending request, because nothing binds the two (GAP-01).
 */
import { createPrivateKey, type KeyObject } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  createExportRequest,
  openExportResponse,
  parseExportResponseJson,
  serializeExportRequest,
  type CreateExportRequestOptions,
  type ExportRequest,
  type ImporterKeyring,
  type ResponseMode,
} from "../cxp/index.js";
import { decodeB64url, isPasskey, type Header, type Passkey } from "../cxf/index.js";
import type { Policy } from "../policy/index.js";
import type { StoredPasskey, Vault } from "./vault.js";

export interface ImportingProviderConfig {
  /** CXP §3.2 `importer` (self-asserted — GAP-05). */
  readonly rpId: string;
  readonly vault: Vault;
  readonly policy: Policy;
  readonly now?: () => number;
}

export type SkipReason = "not-a-passkey" | "unsupported-key" | "invalid-field";

export interface ImportReport {
  readonly exporter: string;
  readonly imported: readonly string[]; // Item IDs
  /** GAP-30 (spec-minimal): existing credentials that were overwritten. */
  readonly replaced: readonly string[];
  readonly skipped: readonly { readonly itemId: string; readonly reason: SkipReason; readonly type?: string }[];
}

/** CXP §3.2.1: the request file name is not specified (GAP-31). */
export const REQUEST_FILE_NAME = "cxp-export-request.json";

interface PendingRequest {
  readonly request: ExportRequest;
  readonly keyring: ImporterKeyring;
}

export class ImportingProvider {
  readonly config: ImportingProviderConfig;
  #pending: PendingRequest | undefined;

  constructor(config: ImportingProviderConfig) {
    this.config = config;
  }

  get pendingRequest(): ExportRequest | undefined {
    return this.#pending?.request;
  }

  /** CXP §2 step 1: the importer initiates with an Export Request. */
  async createRequest(
    mode: ResponseMode,
    options: Omit<CreateExportRequestOptions, "importer" | "mode"> = {},
  ): Promise<ExportRequest> {
    const { request, keyring } = await createExportRequest({ ...options, importer: this.config.rpId, mode });
    this.#pending = { request, keyring };
    return request;
  }

  /**
   * `indirect`: store the request as a JSON document for the credential owner
   * to hand to the exporter (CXP §3.2.1 SHALL). GAP-31: default permissions.
   */
  async writeRequestFile(dir: string, options: Omit<CreateExportRequestOptions, "importer" | "mode"> = {}): Promise<string> {
    const request = await this.createRequest("indirect", options);
    await mkdir(dir, { recursive: true });
    const path = join(dir, REQUEST_FILE_NAME);
    await writeFile(path, serializeExportRequest(request));
    return path;
  }

  /** Open an Export Response for the pending request and store its passkeys. */
  async importResponse(response: unknown): Promise<ImportReport> {
    const pending = this.#pending;
    if (pending === undefined) throw new Error("no pending Export Request");
    const header = await openExportResponse({
      request: pending.request,
      response,
      keyring: pending.keyring,
      policy: this.config.policy,
    });
    // GAP-11 (spec-minimal): the pending request and its keys stay usable.
    return this.#store(header);
  }

  /** `indirect`: read the response file the exporter wrote (CXP §3.3 JSON document). */
  async importResponseFile(path: string): Promise<ImportReport> {
    return this.importResponse(parseExportResponseJson(await readFile(path, "utf8")));
  }

  #store(header: Header): ImportReport {
    const imported: string[] = [];
    const replaced: string[] = [];
    const skipped: { itemId: string; reason: SkipReason; type?: string }[] = [];

    for (const account of header.accounts) {
      for (const item of account.items) {
        for (const credential of item.credentials) {
          // Only passkeys are in scope (README §5); CXF §3.3 lets importers store
          // other types "as a best effort", which this PoC does not.
          if (!isPasskey(credential)) {
            skipped.push({ itemId: item.id, reason: "not-a-passkey", type: credential.type });
            continue;
          }
          const record = this.#toRecord(item.id, credential);
          if (typeof record === "string") {
            skipped.push({ itemId: item.id, reason: record });
            continue;
          }
          // GAP-30 (spec-minimal): an existing credential with the same ID is replaced.
          if (this.config.vault.get(record.credentialId)) replaced.push(item.id);
          this.config.vault.add(record);
          imported.push(item.id);
        }
      }
    }
    return { exporter: header.exporterRpId, imported, replaced, skipped };
  }

  #toRecord(itemId: string, passkey: Passkey): StoredPasskey | SkipReason {
    let privateKey: KeyObject;
    try {
      privateKey = createPrivateKey({ key: Buffer.from(passkey.key, "base64url"), format: "der", type: "pkcs8" });
    } catch {
      return "invalid-field";
    }
    // The software authenticator signs ES256 only (M2).
    if (privateKey.asymmetricKeyType !== "ec" || privateKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      return "unsupported-key";
    }
    return {
      itemId,
      credentialId: decodeB64url(passkey.credentialId),
      rpId: passkey.rpId,
      userHandle: decodeB64url(passkey.userHandle),
      username: passkey.username,
      userDisplayName: passkey.userDisplayName,
      privateKey,
      signCount: 0, // CXF §3.3.12 (MUST) zero, and never incremented
      backupEligible: true, // GAP-25: CXF carries no BE/BS
      backupState: true,
      createdAt: this.config.now?.() ?? Math.floor(Date.now() / 1000),
    };
  }
}
