/**
 * HPKE (RFC 9180) wrapper over @hpke/core, plus conversion between HPKE
 * serialised public keys and the JWKs CXP carries (CXP §3.5.1 `key: JWK`).
 *
 * Supported: KEM DHKEM(X25519, HKDF-SHA256) 0x0020 and DHKEM(P-256,
 * HKDF-SHA256) 0x0010; KDF HKDF-SHA256 0x0001; AEAD AES-128-GCM 0x0001,
 * AES-256-GCM 0x0002, export-only 0xFFFF. Modes `base` and `auth`
 * (README §5; `psk`/`auth-psk` are out of scope).
 */
import {
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  DhkemX25519HkdfSha256,
  ExportOnly,
  HkdfSha256,
  type RecipientContext,
  type SenderContext,
} from "@hpke/core";
import { decodeB64url, encodeB64url, isCanonicalB64url } from "../cxf/b64url.js";

export const KEM = { P256_HKDF_SHA256: 0x0010, X25519_HKDF_SHA256: 0x0020 } as const;
export const KDF = { HKDF_SHA256: 0x0001 } as const;
export const AEAD = { AES_128_GCM: 0x0001, AES_256_GCM: 0x0002, CHACHA20_POLY1305: 0x0003, EXPORT_ONLY: 0xffff } as const;

/** CXP §3.5.2 HPKEMode names, and their RFC 9180 §5 mode values. */
export const HPKE_MODES = { base: 0x00, psk: 0x01, auth: 0x02, "auth-psk": 0x03 } as const;
export type HpkeModeName = keyof typeof HPKE_MODES;

export interface SuiteIds {
  readonly kem: number;
  readonly kdf: number;
  readonly aead: number;
}

/** The README's hardened mandatory-to-implement suite (GAP-02). */
export const MTI_SUITE: SuiteIds = { kem: KEM.X25519_HKDF_SHA256, kdf: KDF.HKDF_SHA256, aead: AEAD.AES_256_GCM };

export class HpkeParameterError extends Error {
  override name = "HpkeParameterError";
}

function makeKem(kem: number) {
  switch (kem) {
    case KEM.X25519_HKDF_SHA256:
      return new DhkemX25519HkdfSha256();
    case KEM.P256_HKDF_SHA256:
      return new DhkemP256HkdfSha256();
    default:
      return undefined;
  }
}

function makeAead(aead: number) {
  switch (aead) {
    case AEAD.AES_128_GCM:
      return new Aes128Gcm();
    case AEAD.AES_256_GCM:
      return new Aes256Gcm();
    case AEAD.EXPORT_ONLY:
      return new ExportOnly();
    default:
      return undefined;
  }
}

export function isSupportedSuite(ids: SuiteIds): boolean {
  return makeKem(ids.kem) !== undefined && ids.kdf === KDF.HKDF_SHA256 && makeAead(ids.aead) !== undefined;
}

export function createCipherSuite(ids: SuiteIds): CipherSuite {
  const kem = makeKem(ids.kem);
  const aead = makeAead(ids.aead);
  if (kem === undefined || aead === undefined || ids.kdf !== KDF.HKDF_SHA256) {
    throw new HpkeParameterError(`unsupported HPKE suite kem=${ids.kem} kdf=${ids.kdf} aead=${ids.aead}`);
  }
  return new CipherSuite({ kem, kdf: new HkdfSha256(), aead });
}

function requireKem(kem: number) {
  const k = makeKem(kem);
  if (k === undefined) throw new HpkeParameterError(`unsupported KEM ${kem}`);
  return k;
}

export function generateKeyPair(kem: number): Promise<CryptoKeyPair> {
  return requireKem(kem).generateKeyPair();
}

export function deriveKeyPair(kem: number, ikm: Uint8Array): Promise<CryptoKeyPair> {
  return requireKem(kem).deriveKeyPair(ikm);
}

export async function serializePublicKey(kem: number, key: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await requireKem(kem).serializePublicKey(key));
}

export function deserializePublicKey(kem: number, bytes: Uint8Array): Promise<CryptoKey> {
  return requireKem(kem).deserializePublicKey(bytes);
}

/**
 * Serialised KEM public key (RFC 9180 §7.1.1 SerializePublicKey), which is
 * also the format of `enc`, as a JWK: OKP for X25519 (RFC 8037 §2), EC for
 * P-256 (RFC 7518 §6.2.1, from the uncompressed point).
 */
export function publicKeyBytesToJwk(kem: number, bytes: Uint8Array): JsonWebKey {
  switch (kem) {
    case KEM.X25519_HKDF_SHA256:
      if (bytes.length !== 32) throw new HpkeParameterError("X25519 public key must be 32 bytes");
      return { kty: "OKP", crv: "X25519", x: encodeB64url(bytes) };
    case KEM.P256_HKDF_SHA256:
      if (bytes.length !== 65 || bytes[0] !== 0x04) throw new HpkeParameterError("P-256 key must be an uncompressed point");
      return { kty: "EC", crv: "P-256", x: encodeB64url(bytes.slice(1, 33)), y: encodeB64url(bytes.slice(33)) };
    default:
      throw new HpkeParameterError(`unsupported KEM ${kem}`);
  }
}

/** Inverse of publicKeyBytesToJwk. Rejects JWKs that do not match the KEM. */
export function jwkToPublicKeyBytes(kem: number, jwk: Record<string, unknown>): Uint8Array<ArrayBuffer> {
  const coord = (name: "x" | "y", length: number) => {
    const value = jwk[name];
    if (typeof value !== "string" || !isCanonicalB64url(value)) throw new HpkeParameterError(`JWK ${name} is not base64url`);
    const bytes = decodeB64url(value);
    if (bytes.length !== length) throw new HpkeParameterError(`JWK ${name} must be ${length} bytes`);
    return bytes;
  };
  switch (kem) {
    case KEM.X25519_HKDF_SHA256:
      if (jwk.kty !== "OKP" || jwk.crv !== "X25519") throw new HpkeParameterError("expected an OKP X25519 JWK");
      return coord("x", 32);
    case KEM.P256_HKDF_SHA256: {
      if (jwk.kty !== "EC" || jwk.crv !== "P-256") throw new HpkeParameterError("expected an EC P-256 JWK");
      const out = new Uint8Array(65);
      out[0] = 0x04;
      out.set(coord("x", 32), 1);
      out.set(coord("y", 32), 33);
      return out;
    }
    default:
      throw new HpkeParameterError(`unsupported KEM ${kem}`);
  }
}

export async function publicKeyToJwk(kem: number, key: CryptoKey): Promise<JsonWebKey> {
  return publicKeyBytesToJwk(kem, await serializePublicKey(kem, key));
}

export function jwkToPublicKey(kem: number, jwk: Record<string, unknown>): Promise<CryptoKey> {
  return deserializePublicKey(kem, jwkToPublicKeyBytes(kem, jwk));
}

export interface SenderParams {
  readonly suite: SuiteIds;
  readonly recipientPublicKey: CryptoKey;
  /** RFC 9180 §5.1 `info`. Empty unless a binding is configured (GAP-01). */
  readonly info?: Uint8Array;
  /** Present ⇒ `auth` mode (RFC 9180 §5.1.3). */
  readonly senderKey?: CryptoKeyPair;
  /** Test-only deterministic ephemeral key input (RFC 9180 test vectors `ikmE`). */
  readonly ikmE?: Uint8Array;
}

export interface RecipientParams {
  readonly suite: SuiteIds;
  readonly recipientKey: CryptoKeyPair;
  readonly enc: Uint8Array;
  readonly info?: Uint8Array;
  /** Present ⇒ `auth` mode. */
  readonly senderPublicKey?: CryptoKey;
}

/** RFC 9180 §5.1.1 SetupBaseS / §5.1.3 SetupAuthS. */
export function setupSender(params: SenderParams): Promise<SenderContext> {
  return createCipherSuite(params.suite).createSenderContext({
    recipientPublicKey: params.recipientPublicKey,
    info: params.info ?? new Uint8Array(0),
    ...(params.senderKey ? { senderKey: params.senderKey } : {}),
    ...(params.ikmE ? { ekm: params.ikmE } : {}),
  });
}

/** RFC 9180 §5.1.1 SetupBaseR / §5.1.3 SetupAuthR. */
export function setupRecipient(params: RecipientParams): Promise<RecipientContext> {
  return createCipherSuite(params.suite).createRecipientContext({
    recipientKey: params.recipientKey,
    enc: params.enc,
    info: params.info ?? new Uint8Array(0),
    ...(params.senderPublicKey ? { senderPublicKey: params.senderPublicKey } : {}),
  });
}

/** RFC 9180 §5.3 secret export. */
export async function exportSecret(
  context: SenderContext | RecipientContext,
  exporterContext: Uint8Array,
  length: number,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await context.export(exporterContext, length));
}
