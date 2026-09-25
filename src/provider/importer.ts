/**
 * Importing provider (CXP §2.1 "Importer"): starts the exchange with an
 * Export Request, opens the Export Response and stores the passkeys.
 *
 * spec-minimal: the importer key is kept after import, so a response can be
 * imported again (GAP-11); an imported credential replaces an existing one
 * (GAP-30); files keep default permissions and stay on disk (GAP-31).
 * A response is matched to the latest pending request (GAP-01; in hardened
 * the HPKE `info` binding makes any other request's response undecryptable).
 */
import { createPrivateKey, type KeyObject } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { inflateRawSync } from "node:zlib";
import { join } from "node:path";
import {
  createExportRequest,
  openExportResponse,
  parseExportResponseJson,
  serializeExportRequest,
  type CreateExportRequestOptions,
  type ExportRequest,
  type ImporterKeyring,
  type ExporterConfirmation,
  type ResponseMode,
} from "../cxp/index.js";
import { requestFingerprint } from "../cxp/binding.js";
import { decodeB64url, isPasskey, type Header, type Passkey } from "../cxf/index.js";
import { isEnabled, type Policy } from "../policy/index.js";
import type { StoredPasskey, Vault } from "./vault.js";

export interface ImportingProviderConfig {
  /** CXP §3.2 `importer` (self-asserted — GAP-05). */
  readonly rpId: string;
  readonly vault: Vault;
  readonly policy: Policy;
  readonly now?: () => number;
  /** The user confirms the exporter key's fingerprint (hardened: GAP-05, GAP-14). */
  readonly confirmExporter?: (confirmation: ExporterConfirmation) => Promise<boolean> | boolean;
}

export type SkipReason = "not-a-passkey" | "unsupported-key" | "invalid-field" | "conflict" | "invalid-large-blob";

/** GAP-12 (hardened): largest accepted inflated largeBlob. */
export const MAX_LARGE_BLOB_BYTES = 64 << 10;

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
  readonly createdAt: number;
  /** Where the request file was written (indirect mode). */
  requestPath?: string;
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

  /** Displayed to the user, who compares it with the exporter's prompt (hardened: GAP-05/06). */
  get requestFingerprint(): string | undefined {
    return this.#pending && requestFingerprint(this.#pending.request);
  }

  #on(flag: Parameters<typeof isEnabled>[1]): boolean {
    return isEnabled(this.config.policy, flag);
  }

  #now(): number {
    return this.config.now?.() ?? Math.floor(Date.now() / 1000);
  }

  /** CXP §2 step 1: the importer initiates with an Export Request. */
  async createRequest(
    mode: ResponseMode,
    options: Omit<CreateExportRequestOptions, "importer" | "mode"> = {},
  ): Promise<ExportRequest> {
    const { request, keyring } = await createExportRequest({
      ...options,
      importer: this.config.rpId,
      mode,
      policy: this.config.policy,
    });
    this.#pending = { request, keyring, createdAt: this.#now() };
    return request;
  }

  /**
   * `indirect`: store the request as a JSON document for the credential owner
   * to hand to the exporter (CXP §3.2.1 SHALL). GAP-31: default permissions
   * in spec-minimal, 0600 in hardened.
   */
  async writeRequestFile(dir: string, options: Omit<CreateExportRequestOptions, "importer" | "mode"> = {}): Promise<string> {
    const request = await this.createRequest("indirect", options);
    await mkdir(dir, { recursive: true });
    const path = join(dir, REQUEST_FILE_NAME);
    await writeFile(path, serializeExportRequest(request), this.#on("secureExportFiles") ? { mode: 0o600 } : {});
    if (this.#pending) this.#pending.requestPath = path;
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
      requestCreatedAt: pending.createdAt,
      now: () => this.#now(),
      ...(this.config.confirmExporter ? { confirmExporter: this.config.confirmExporter } : {}),
    });
    const report = this.#store(header);
    // GAP-11: spec-minimal keeps the request and its keys usable; hardened
    // discards them after the first successful import, so a response opens once.
    if (this.#on("singleUseImporterKey")) this.#pending = undefined;
    return report;
  }

  /** `indirect`: read the response file the exporter wrote (CXP §3.3 JSON document). */
  async importResponseFile(path: string): Promise<ImportReport> {
    const requestPath = this.#pending?.requestPath;
    const report = await this.importResponse(parseExportResponseJson(await readFile(path, "utf8")));
    // GAP-31 (hardened): remove both files once imported (best effort: storage
    // remanence and backups are outside the application's control).
    if (this.#on("secureExportFiles")) {
      await rm(path, { force: true });
      if (requestPath !== undefined) await rm(requestPath, { force: true });
    }
    return report;
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
          if (this.config.vault.get(record.credentialId)) {
            // GAP-30: hardened never silently replaces an existing credential.
            if (this.#on("rejectConflictingImport")) {
              skipped.push({ itemId: item.id, reason: "conflict" });
              continue;
            }
            replaced.push(item.id); // spec-minimal: last import wins
          }
          this.config.vault.add(record);
          imported.push(item.id);
        }
      }
    }
    return { exporter: header.exporterRpId, imported, replaced, skipped };
  }

  #toRecord(itemId: string, passkey: Passkey): StoredPasskey | SkipReason {
    // GAP-12 (hardened): the largeBlob inflates within a bound and to its claimed size.
    const largeBlob = passkey.fido2Extensions?.largeBlob;
    if (largeBlob !== undefined && this.#on("enforceDecompressionLimits")) {
      try {
        const inflated = inflateRawSync(Buffer.from(largeBlob.data, "base64url"), { maxOutputLength: MAX_LARGE_BLOB_BYTES });
        if (inflated.length !== largeBlob.uncompressedSize) return "invalid-large-blob";
      } catch {
        return "invalid-large-blob";
      }
    }
    let privateKey: KeyObject;
    const der = Buffer.from(passkey.key, "base64url");
    try {
      privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    } catch {
      return "invalid-field";
    } finally {
      // GAP-13 (hardened), best effort: the base64url string in the parsed
      // JSON is immutable and stays until garbage collection.
      if (this.#on("zeroizeKeyMaterial")) der.fill(0);
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
      createdAt: this.#now(),
    };
  }
}
