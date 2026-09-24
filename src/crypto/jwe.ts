/**
 * JWE packaging of payload files (CXP §3.4: "All files are stored as JSON Web
 * Encryption files"). CXP does not define how HPKE maps onto JWE — GAP-07.
 *
 * Each file is a compact JWE (RFC 7516 §7.1) with `alg: "dir"` (RFC 7518 §4.5):
 * the content-encryption key is supplied directly, having been derived from
 * the HPKE context by secret export.
 */
import { CompactEncrypt, compactDecrypt, type CompactJWEHeaderParameters } from "jose";
import { AEAD } from "./hpke.js";

export type JweEnc = "A128GCM" | "A256GCM";

export const CEK_LENGTH: Readonly<Record<JweEnc, number>> = { A128GCM: 16, A256GCM: 32 };

/**
 * GAP-07: JWE `enc` for the selected HPKE AEAD. ChaCha20-Poly1305 has no
 * registered JOSE `enc`, so it is unsupported; the export-only AEAD carries
 * no cipher of its own, so AES-256-GCM is used.
 */
export function jweEncForAead(aead: number): JweEnc | undefined {
  switch (aead) {
    case AEAD.AES_128_GCM:
      return "A128GCM";
    case AEAD.AES_256_GCM:
    case AEAD.EXPORT_ONLY:
      return "A256GCM";
    default:
      return undefined;
  }
}

export class JweError extends Error {
  override name = "JweError";
}

export async function encryptJwe(
  plaintext: Uint8Array,
  cek: Uint8Array,
  enc: JweEnc,
  extraHeader: Record<string, unknown> = {},
): Promise<string> {
  if (cek.length !== CEK_LENGTH[enc]) throw new JweError(`${enc} needs a ${CEK_LENGTH[enc]}-byte key`);
  return new CompactEncrypt(plaintext).setProtectedHeader({ ...extraHeader, alg: "dir", enc }).encrypt(cek);
}

export async function decryptJwe(
  jwe: string,
  cek: Uint8Array,
  enc: JweEnc,
): Promise<{ plaintext: Uint8Array; protectedHeader: CompactJWEHeaderParameters }> {
  try {
    const { plaintext, protectedHeader } = await compactDecrypt(jwe, cek, {
      keyManagementAlgorithms: ["dir"],
      contentEncryptionAlgorithms: [enc],
    });
    return { plaintext, protectedHeader };
  } catch (err) {
    throw new JweError(`JWE decryption failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}
