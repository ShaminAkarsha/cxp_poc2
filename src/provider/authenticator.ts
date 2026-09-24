/**
 * Software WebAuthn authenticator (README §4: "Why a software authenticator").
 *
 * It plays two WebAuthn roles in one object:
 *   - the client (browser): builds clientDataJSON and checks the RP ID
 *     against the origin (WebAuthn L3 §5.1.3 / §5.1.4);
 *   - the authenticator: generates ES256 (P-256) credentials, returns `none`
 *     attestation (§8.7) and signs assertions (§6.3.3).
 *
 * Credentials are always discoverable and user verification is simulated as
 * performed. Behaviour is identical in both profiles: this is a WebAuthn
 * fixture, not part of CXP.
 */
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { decodeB64url, encodeB64url } from "../cxf/b64url.js";
import { concatBytes, encodeCbor, type CborValue } from "./cbor.js";
import type { StoredPasskey, Vault } from "./vault.js";

/** COSE algorithm ES256 (RFC 9053 §2.1). */
export const COSE_ALG_ES256 = -7;

/** WebAuthn L3 §6.1 authenticator data flags. */
export const AUTH_DATA_FLAGS = {
  UP: 0x01,
  UV: 0x04,
  BE: 0x08,
  BS: 0x10,
  AT: 0x40,
  ED: 0x80,
} as const;

/** Number of random bytes in a new credential ID. */
const CREDENTIAL_ID_BYTES = 16;

/** The signature counter this authenticator reports: always zero (see StoredPasskey.signCount). */
const SIGN_COUNT = 0;

/** DOMException-style error names used by WebAuthn clients. */
export type WebAuthnErrorName = "SecurityError" | "NotSupportedError" | "InvalidStateError" | "NotAllowedError";

export class WebAuthnClientError extends Error {
  override name = "WebAuthnClientError";
  constructor(
    readonly code: WebAuthnErrorName,
    message: string,
  ) {
    super(`${code}: ${message}`);
  }
}

export interface SoftwareAuthenticatorOptions {
  /** 16-byte AAGUID; defaults to all zeros, as for `none` attestation. */
  readonly aaguid?: Uint8Array;
  /** Picks among several matching credentials in get(); defaults to the first. */
  readonly selectCredential?: (candidates: readonly StoredPasskey[]) => StoredPasskey;
  /** Clock in UNIX seconds, injectable for tests. */
  readonly now?: () => number;
}

const sha256 = (data: Uint8Array | string) => new Uint8Array(createHash("sha256").update(data).digest());

function uint32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

/** COSE_Key for an EC2 P-256 public key (RFC 9052 §7, RFC 9053 §7.1.1), CTAP2 canonical key order. */
export function coseKeyFromPublicKey(publicKey: KeyObject): Uint8Array {
  const jwk = publicKey.export({ format: "jwk" });
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || jwk.x === undefined || jwk.y === undefined) {
    throw new Error("expected a P-256 public key");
  }
  return encodeCbor(
    new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, COSE_ALG_ES256], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, decodeB64url(jwk.x)],
      [-3, decodeB64url(jwk.y)],
    ]),
  );
}

/**
 * WebAuthn L3 §5.1.3 step 8 / §5.1.4.1 step 7 (simplified): the origin must be
 * a secure context and the RP ID must equal its host or be a parent domain.
 * The public-suffix check is omitted; the PoC uses loopback hosts only.
 */
function assertRpIdValidForOrigin(rpId: string, origin: string): void {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new WebAuthnClientError("SecurityError", `invalid origin ${origin}`);
  }
  const host = url.hostname;
  const secure = url.protocol === "https:" || host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  if (!secure) throw new WebAuthnClientError("SecurityError", `origin ${origin} is not a secure context`);
  if (host !== rpId && !host.endsWith(`.${rpId}`)) {
    throw new WebAuthnClientError("SecurityError", `RP ID ${rpId} is not valid for origin ${origin}`);
  }
}

export class SoftwareAuthenticator {
  readonly #vault: Vault;
  readonly #aaguid: Uint8Array;
  readonly #select: (candidates: readonly StoredPasskey[]) => StoredPasskey;
  readonly #now: () => number;

  constructor(vault: Vault, options: SoftwareAuthenticatorOptions = {}) {
    this.#vault = vault;
    this.#aaguid = options.aaguid ?? new Uint8Array(16);
    if (this.#aaguid.length !== 16) throw new Error("AAGUID must be 16 bytes");
    this.#select =
      options.selectCredential ??
      ((candidates) => {
        const [first] = candidates;
        if (first === undefined) throw new WebAuthnClientError("NotAllowedError", "no candidate credential");
        return first;
      });
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  get vault(): Vault {
    return this.#vault;
  }

  /** navigator.credentials.create() — WebAuthn L3 §5.1.3 and authenticatorMakeCredential §6.3.2. */
  create(options: PublicKeyCredentialCreationOptionsJSON, origin: string): RegistrationResponseJSON {
    const rpId = options.rp.id ?? new URL(origin).hostname;
    assertRpIdValidForOrigin(rpId, origin);

    if (!options.pubKeyCredParams.some((p) => p.type === "public-key" && p.alg === COSE_ALG_ES256)) {
      throw new WebAuthnClientError("NotSupportedError", "RP does not accept ES256");
    }
    for (const excluded of options.excludeCredentials ?? []) {
      const existing = this.#vault.get(decodeB64url(excluded.id));
      if (existing?.rpId === rpId) {
        throw new WebAuthnClientError("InvalidStateError", "a listed credential already exists on this authenticator");
      }
    }

    const clientDataJSON = JSON.stringify({
      type: "webauthn.create",
      challenge: options.challenge,
      origin,
      crossOrigin: false,
    });

    const userHandle = decodeB64url(options.user.id);
    // §6.3.2 step 7: a new discoverable credential replaces one for the same RP and user.
    for (const old of this.#vault.findByRpId(rpId)) {
      if (Buffer.from(old.userHandle).equals(userHandle)) this.#vault.remove(old.credentialId);
    }

    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const credentialId = new Uint8Array(randomBytes(CREDENTIAL_ID_BYTES));
    const record: StoredPasskey = {
      credentialId,
      rpId,
      userHandle,
      username: options.user.name,
      userDisplayName: options.user.displayName,
      privateKey,
      signCount: SIGN_COUNT,
      backupEligible: true, // GAP-25
      backupState: true, // GAP-25
      createdAt: this.#now(),
    };
    this.#vault.add(record);

    const coseKey = coseKeyFromPublicKey(publicKey);
    const credIdLength = Uint8Array.of(credentialId.length >> 8, credentialId.length & 0xff);
    const authData = concatBytes(
      sha256(rpId),
      Uint8Array.of(this.#flags(record) | AUTH_DATA_FLAGS.AT),
      uint32(record.signCount),
      this.#aaguid,
      credIdLength,
      credentialId,
      coseKey,
    );
    // §8.7 none attestation; attestation object keys in CTAP2 canonical order.
    const attestationObject = encodeCbor(
      new Map<string, CborValue>([
        ["fmt", "none"],
        ["attStmt", new Map<string, CborValue>()],
        ["authData", authData],
      ]),
    );

    const id = encodeB64url(credentialId);
    return {
      id,
      rawId: id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: encodeB64url(new TextEncoder().encode(clientDataJSON)),
        attestationObject: encodeB64url(attestationObject),
        authenticatorData: encodeB64url(authData),
        transports: ["internal"],
        publicKeyAlgorithm: COSE_ALG_ES256,
        publicKey: encodeB64url(new Uint8Array(publicKey.export({ format: "der", type: "spki" }))),
      },
    };
  }

  /** navigator.credentials.get() — WebAuthn L3 §5.1.4 and authenticatorGetAssertion §6.3.3. */
  get(options: PublicKeyCredentialRequestOptionsJSON, origin: string): AuthenticationResponseJSON {
    const rpId = options.rpId ?? new URL(origin).hostname;
    assertRpIdValidForOrigin(rpId, origin);

    let candidates = this.#vault.findByRpId(rpId);
    const allow = options.allowCredentials ?? [];
    if (allow.length > 0) {
      const allowed = new Set(allow.map((c) => c.id));
      candidates = candidates.filter((c) => allowed.has(encodeB64url(c.credentialId)));
    }
    if (candidates.length === 0) {
      throw new WebAuthnClientError("NotAllowedError", `no credential for RP ${rpId}`);
    }
    const credential = this.#select(candidates);

    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin, crossOrigin: false }),
    );
    const authData = concatBytes(sha256(rpId), Uint8Array.of(this.#flags(credential)), uint32(credential.signCount));
    // §6.3.3 step 11: sign authenticatorData || SHA-256(clientDataJSON); ES256 signatures are DER.
    const signature = sign("sha256", concatBytes(authData, sha256(clientDataJSON)), credential.privateKey);

    const id = encodeB64url(credential.credentialId);
    return {
      id,
      rawId: id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: encodeB64url(clientDataJSON),
        authenticatorData: encodeB64url(authData),
        signature: encodeB64url(new Uint8Array(signature)),
        userHandle: encodeB64url(credential.userHandle),
      },
    };
  }

  #flags(record: StoredPasskey): number {
    let flags = AUTH_DATA_FLAGS.UP | AUTH_DATA_FLAGS.UV;
    if (record.backupEligible) flags |= AUTH_DATA_FLAGS.BE;
    if (record.backupState) flags |= AUTH_DATA_FLAGS.BS;
    return flags;
  }
}

/** Public key of a stored passkey, e.g. to compare with what an RP registered. */
export function publicKeyOf(record: StoredPasskey): KeyObject {
  return createPublicKey(record.privateKey);
}
