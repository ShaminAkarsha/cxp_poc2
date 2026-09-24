/**
 * Importer side: build an Export Request (CXP §3.2) and keep the matching
 * private keys. The importer starts the flow (CXP §2 step 1).
 */
import { AEAD, generateKeyPair, KDF, KEM, MTI_SUITE, publicKeyToJwk, type SuiteIds } from "../crypto/hpke.js";
import { ARCHIVE_DEFLATE, CXP_VERSION, type ExportRequest, type HpkeParameters, type ResponseMode } from "./schema.js";

/** Importer HPKE preference order: the MTI suite, then P-256 for interoperability. */
export const DEFAULT_IMPORTER_SUITES: readonly SuiteIds[] = [
  MTI_SUITE,
  { kem: KEM.P256_HKDF_SHA256, kdf: KDF.HKDF_SHA256, aead: AEAD.AES_128_GCM },
];

/** Private keys for the request's `hpke` entries: one key pair per KEM. */
export class ImporterKeyring {
  readonly #byKem = new Map<number, CryptoKeyPair>();

  set(kem: number, keyPair: CryptoKeyPair): void {
    this.#byKem.set(kem, keyPair);
  }

  get(kem: number): CryptoKeyPair | undefined {
    return this.#byKem.get(kem);
  }

  get kems(): number[] {
    return [...this.#byKem.keys()];
  }
}

export interface CreateExportRequestOptions {
  /** CXP §3.2 `importer`: the importer's RP ID (self-asserted — GAP-05). */
  readonly importer: string;
  readonly mode: ResponseMode;
  readonly suites?: readonly SuiteIds[];
  readonly archive?: readonly string[];
  readonly credentialTypes?: readonly string[];
  readonly knownExtensions?: readonly string[];
  readonly version?: number;
}

export async function createExportRequest(
  options: CreateExportRequestOptions,
): Promise<{ request: ExportRequest; keyring: ImporterKeyring }> {
  const keyring = new ImporterKeyring();
  const hpke: HpkeParameters[] = [];
  for (const suite of options.suites ?? DEFAULT_IMPORTER_SUITES) {
    let keyPair = keyring.get(suite.kem);
    if (keyPair === undefined) {
      keyPair = await generateKeyPair(suite.kem);
      keyring.set(suite.kem, keyPair);
    }
    // CXP §3.2 (MUST) parameters carry the public key they need; §3.5.1 `key` as a JWK.
    const key = await publicKeyToJwk(suite.kem, keyPair.publicKey);
    hpke.push({ mode: "base", ...suite, key: { kty: key.kty ?? "", ...key } });
  }

  const request: ExportRequest = {
    version: options.version ?? CXP_VERSION,
    hpke,
    archive: [...(options.archive ?? [ARCHIVE_DEFLATE])],
    mode: options.mode,
    importer: options.importer,
    ...(options.credentialTypes ? { credentialTypes: [...options.credentialTypes] } : {}),
    ...(options.knownExtensions ? { knownExtensions: [...options.knownExtensions] } : {}),
  };
  return { request, keyring };
}
