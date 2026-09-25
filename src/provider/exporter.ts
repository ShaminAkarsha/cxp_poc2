/**
 * Exporting provider (CXP §2.1 "Exporter"): turns its vault into a CXF
 * document scoped by the Export Request, and answers with an Export Response.
 *
 * spec-minimal: answers any well-formed request (GAP-29: supplying the request
 * is the approval). hardened: asks the user first (GAP-05/06/29), signs with a
 * static HPKE key in auth mode (GAP-14), and writes private files (GAP-31).
 */
import { randomBytes } from "node:crypto";
import { generateKeyPair, MTI_SUITE, publicKeyToJwk } from "../crypto/hpke.js";
import { keyFingerprint, requestFingerprint } from "../cxp/binding.js";
import { capabilitiesFor, selectArchive, selectHpkeParameters } from "../cxp/negotiate.js";
import { CxpRejectedError } from "../cxp/response.js";
import { CxpNegotiationError } from "../cxp/schema.js";
import { isEnabled } from "../policy/index.js";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  createExportResponse,
  parseExportRequest,
  parseExportRequestJson,
  serializeExportResponse,
  type ExportRequest,
  type ExportResponse,
} from "../cxp/index.js";
import { encodeB64url, type Account, type Header, type Item, type Passkey } from "../cxf/index.js";
import type { Policy } from "../policy/index.js";
import type { StoredPasskey, Vault } from "./vault.js";

export interface ExportingProviderConfig {
  /** CXF §3.1 exporterRpId and CXP §3.3 `exporter`. */
  readonly rpId: string;
  readonly displayName: string;
  readonly vault: Vault;
  readonly policy: Policy;
  /** The credential owner's account at this provider (CXF §3.2.1). */
  readonly account: { readonly username: string; readonly email: string; readonly fullName?: string };
  /** UNIX seconds; injectable for tests. */
  readonly now?: () => number;
  /**
   * The credential owner's decision on an export (hardened: GAP-05/06/29).
   * Stands for a confirmation screen after user verification.
   */
  readonly approveExport?: (prompt: ExportConsentPrompt) => Promise<boolean> | boolean;
}

/** What the user is shown before an export (GAP-29 hardened column). */
export interface ExportConsentPrompt {
  /** Claimed by the request; not authenticated (GAP-05). */
  readonly importer: string;
  /** Fingerprint of the received request, to compare with the importer's display (GAP-05/06). */
  readonly requestFingerprint?: string;
  readonly credentialTypes: readonly string[] | "all";
  readonly itemCount: number;
  readonly channel: ExportChannel;
}

export type ExportChannel = "direct" | "file";

export interface ExportReport {
  readonly exported: number;
  /** CXF §3.3.12: excluded because of a non-zero signature counter (user SHOULD be told). */
  readonly excludedNonZeroCounter: readonly string[];
  /** Filtered out by the request's credentialTypes (CXP §3.2). */
  readonly excludedByType: number;
}

/** CXP §3.2.2 / §3.3 indirect mode: the file name is not specified (GAP-31). */
export const RESPONSE_FILE_PREFIX = "cxp-export-response-";

export class ExportingProvider {
  readonly config: ExportingProviderConfig;
  /** CXF §1.3: a machine-generated Account ID, stable across exports. */
  readonly accountId = encodeB64url(new Uint8Array(randomBytes(16)));
  /** Static HPKE key for auth mode (GAP-14), created on first use. */
  #staticKey: Promise<CryptoKeyPair> | undefined;

  constructor(config: ExportingProviderConfig) {
    this.config = config;
  }

  #now(): number {
    return this.config.now?.() ?? Math.floor(Date.now() / 1000);
  }

  /** CXF §3.3.12: one vault record as a CXF Passkey. */
  static toCxfPasskey(record: StoredPasskey): Passkey {
    return {
      type: "passkey",
      credentialId: encodeB64url(record.credentialId), // MUST equal rawId
      rpId: record.rpId, // MUST equal the registration RP ID
      username: record.username,
      userDisplayName: record.userDisplayName,
      userHandle: encodeB64url(record.userHandle), // MUST equal user.id
      // MUST be PKCS#8 DER and give the registration public key.
      key: encodeB64url(record.privateKey.export({ format: "der", type: "pkcs8" })),
    };
  }

  /**
   * Build the CXF document the request asks for (CXP §3.2 credentialTypes /
   * knownExtensions semantics, CXF §3.3.12 counter rule).
   */
  buildCxf(request: ExportRequest): { header: Header; report: ExportReport } {
    const excludedNonZeroCounter: string[] = [];
    const items: Item[] = [];
    for (const record of this.config.vault.list()) {
      // CXF §3.3.12 (MUST) passkeys using a non-zero signature counter are excluded.
      if (record.signCount !== 0) {
        excludedNonZeroCounter.push(record.itemId);
        continue;
      }
      items.push({
        id: record.itemId,
        creationAt: record.createdAt,
        title: record.rpId,
        subtitle: record.username,
        credentials: [ExportingProvider.toCxfPasskey(record)],
      });
    }

    // CXP §3.2 credentialTypes: absent = all types; empty = the Account only,
    // without any Collection (MUST); otherwise listed types, unknown values
    // ignored (MUST).
    const types = request.credentialTypes;
    let scoped = items;
    if (types !== undefined) {
      scoped = items
        .map((item) => ({ ...item, credentials: item.credentials.filter((c) => types.includes(c.type)) }))
        .filter((item) => item.credentials.length > 0);
    }

    const account: Account = {
      id: this.accountId,
      username: this.config.account.username,
      email: this.config.account.email,
      ...(this.config.account.fullName !== undefined ? { fullName: this.config.account.fullName } : {}),
      collections: [], // this provider has no collections; see the empty-list rule above
      items: types?.length === 0 ? [] : scoped,
    };

    const header: Header = {
      version: { major: 1, minor: 0 }, // CXF §3.1 (MUST) a published CXF level
      exporterRpId: this.config.rpId,
      exporterDisplayName: this.config.displayName,
      timestamp: this.#now(),
      accounts: [stripExtensions(account, request.knownExtensions)],
    };
    return {
      header,
      report: { exported: account.items.length, excludedNonZeroCounter, excludedByType: items.length - scoped.length },
    };
  }

  #on(flag: Parameters<typeof isEnabled>[1]): boolean {
    return isEnabled(this.config.policy, flag);
  }

  #senderKey(): Promise<CryptoKeyPair> {
    this.#staticKey ??= generateKeyPair(MTI_SUITE.kem);
    return this.#staticKey;
  }

  /**
   * GAP-14 (hardened): fingerprint of this exporter's static key, which the
   * exporter displays so the user can confirm it at the importer.
   */
  async keyFingerprint(): Promise<string> {
    const jwk = await publicKeyToJwk(MTI_SUITE.kem, (await this.#senderKey()).publicKey);
    return keyFingerprint(jwk as Record<string, unknown>);
  }

  /**
   * Hardened: ask the user before exporting. GAP-29 always prompts; GAP-05
   * (direct) and GAP-06 (file) add the request fingerprint to the prompt.
   */
  async #obtainConsent(request: ExportRequest, report: ExportReport, channel: ExportChannel): Promise<void> {
    const showFingerprint = channel === "direct" ? this.#on("requireSasConfirmation") : this.#on("confirmRequestFileKey");
    if (!this.#on("requireExportConsent") && !showFingerprint) return; // GAP-29 (spec-minimal)
    const prompt: ExportConsentPrompt = {
      importer: request.importer,
      ...(showFingerprint ? { requestFingerprint: requestFingerprint(request) } : {}),
      credentialTypes: request.credentialTypes ?? "all",
      itemCount: report.exported,
      channel,
    };
    if ((await this.config.approveExport?.(prompt)) !== true) {
      throw new CxpRejectedError("export was not approved by the credential owner (GAP-29)");
    }
  }

  /** Answer an Export Request (any source). */
  async respond(
    input: unknown,
    channel: ExportChannel = "direct",
  ): Promise<{ response: ExportResponse; report: ExportReport }> {
    const request = parseExportRequest(input);
    // Fail fast: never ask the user about an export that cannot be served.
    const capabilities = capabilitiesFor(this.config.policy);
    if (selectHpkeParameters(request.hpke, capabilities) === undefined) {
      throw new CxpNegotiationError("no mutually supported HPKE parameters");
    }
    if (selectArchive(request.archive, capabilities) === undefined) {
      throw new CxpNegotiationError("no mutually supported archive algorithm");
    }
    const { header, report } = this.buildCxf(request);
    await this.#obtainConsent(request, report, channel);
    const response = await createExportResponse({
      request,
      header,
      exporter: this.config.rpId,
      policy: this.config.policy,
      ...(this.#on("requireHpkeAuthMode") ? { senderKey: await this.#senderKey() } : {}),
    });
    return { response, report };
  }

  /**
   * `indirect` mode: read the request file the credential owner supplied
   * (CXP §3.2.1) and write the response to the filesystem (CXP §3.2.2 MUST).
   * GAP-31: spec-minimal uses default permissions; hardened writes 0600.
   */
  async exportToFile(
    requestPath: string,
    outDir: string,
  ): Promise<{ responsePath: string; response: ExportResponse; report: ExportReport }> {
    const request = parseExportRequestJson(await readFile(requestPath, "utf8"));
    const { response, report } = await this.respond(request, "file");
    await mkdir(outDir, { recursive: true });
    const responsePath = join(outDir, `${RESPONSE_FILE_PREFIX}${this.#now()}.json`);
    // GAP-31 (hardened): owner-only permissions.
    await writeFile(responsePath, serializeExportResponse(response), this.#on("secureExportFiles") ? { mode: 0o600 } : {});
    return { responsePath, response, report };
  }
}

/**
 * CXP §3.2 knownExtensions: absent = whatever the exporter includes; empty =
 * MUST NOT include any; otherwise only listed names (unknown values ignored).
 */
function stripExtensions(account: Account, known: readonly string[] | undefined): Account {
  if (known === undefined) return account;
  const keep = <T extends { extensions?: { name: string }[] | undefined }>(entity: T): T => {
    const extensions = entity.extensions?.filter((e) => known.includes(e.name));
    const { extensions: _dropped, ...rest } = entity;
    void _dropped;
    return (extensions && extensions.length > 0 ? { ...rest, extensions } : rest) as T;
  };
  return keep({ ...account, items: account.items.map(keep), collections: account.collections.map(keep) });
}
