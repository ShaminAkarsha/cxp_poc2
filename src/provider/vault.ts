/**
 * In-memory credential vault of a provider.
 *
 * Each record holds exactly the data a CXF Passkey (CXF §3.3.12) needs, so the
 * exporter (M4) can map it field-for-field:
 *   credentialId = PublicKeyCredential.rawId at registration (MUST)
 *   rpId         = RP ID the authenticator used at registration (MUST)
 *   userHandle   = PublicKeyCredentialUserEntity.id (MUST)
 *   username / userDisplayName = user.name / user.displayName (SHOULD)
 *   privateKey   = serialisable as PKCS#8 DER (MUST)
 */
import type { KeyObject } from "node:crypto";
import { encodeB64url } from "../cxf/b64url.js";

export interface StoredPasskey {
  readonly credentialId: Uint8Array;
  readonly rpId: string;
  readonly userHandle: Uint8Array;
  readonly username: string;
  readonly userDisplayName: string;
  readonly privateKey: KeyObject;
  /**
   * Always 0. CXF §3.3.12 (MUST): passkeys with a non-zero signature counter
   * are excluded from export, so an exportable passkey never counts (GAP-17).
   */
  readonly signCount: number;
  /** WebAuthn L3 §6.1.3 backup flags; see GAP-25. */
  readonly backupEligible: boolean;
  readonly backupState: boolean;
  /** UNIX seconds. */
  readonly createdAt: number;
}

export class Vault {
  readonly #records = new Map<string, StoredPasskey>();

  add(record: StoredPasskey): void {
    this.#records.set(encodeB64url(record.credentialId), record);
  }

  get(credentialId: Uint8Array): StoredPasskey | undefined {
    return this.#records.get(encodeB64url(credentialId));
  }

  remove(credentialId: Uint8Array): boolean {
    return this.#records.delete(encodeB64url(credentialId));
  }

  findByRpId(rpId: string): StoredPasskey[] {
    return this.list().filter((r) => r.rpId === rpId);
  }

  list(): StoredPasskey[] {
    return [...this.#records.values()];
  }

  get size(): number {
    return this.#records.size;
  }
}
