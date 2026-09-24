/**
 * Demo relying party (README §4). A conventional WebAuthn RP built on
 * @simplewebauthn/server with in-memory state. It is the *victim* the
 * migrated passkey must still work against, so it behaves identically in
 * both profiles and adds no CXP-specific checks.
 */
import { randomBytes } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { encodeB64url } from "../cxf/b64url.js";

export interface RelyingPartyConfig {
  readonly rpId: string;
  readonly rpName: string;
  /** Exact origin the RP accepts in clientDataJSON, e.g. http://localhost:3000. */
  readonly origin: string;
}

export interface RpCredential {
  readonly id: string; // base64url credential ID
  readonly publicKey: Uint8Array<ArrayBuffer>; // COSE key
  counter: number;
  readonly backedUp: boolean;
  readonly deviceType: "singleDevice" | "multiDevice";
  readonly registeredAt: number;
  lastUsedAt?: number;
}

export interface RpUser {
  readonly username: string;
  readonly displayName: string;
  readonly userHandle: Uint8Array<ArrayBuffer>;
  readonly credentials: RpCredential[];
}

export type RpEvent =
  | { kind: "registered"; username: string; credentialId: string }
  | { kind: "authenticated"; username: string; credentialId: string; counter: number }
  | { kind: "rejected"; stage: "registration" | "authentication"; reason: string };

interface PendingRegistration {
  readonly challenge: string;
  readonly userHandle: Uint8Array<ArrayBuffer>;
  readonly displayName: string;
}

export class RelyingPartyError extends Error {
  override name = "RelyingPartyError";
}

export class DemoRelyingParty {
  readonly config: RelyingPartyConfig;
  readonly events: RpEvent[] = [];
  readonly #users = new Map<string, RpUser>();
  readonly #pendingRegistration = new Map<string, PendingRegistration>(); // by username
  readonly #pendingAuthentication = new Set<string>(); // challenges

  constructor(config: RelyingPartyConfig) {
    this.config = config;
  }

  getUser(username: string): RpUser | undefined {
    return this.#users.get(username);
  }

  async registrationOptions(username: string, displayName = username): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const existing = this.#users.get(username);
    const userHandle = existing?.userHandle ?? new Uint8Array(randomBytes(32));
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userName: username,
      userDisplayName: displayName,
      userID: userHandle,
      attestationType: "none",
      supportedAlgorithmIDs: [-7], // ES256
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      excludeCredentials: existing?.credentials.map((c) => ({ id: c.id })) ?? [],
    });
    this.#pendingRegistration.set(username, { challenge: options.challenge, userHandle, displayName });
    return options;
  }

  async verifyRegistration(username: string, response: RegistrationResponseJSON): Promise<RpCredential> {
    const pending = this.#pendingRegistration.get(username);
    this.#pendingRegistration.delete(username); // single use
    if (pending === undefined) return this.#reject("registration", "no pending registration");

    let result;
    try {
      result = await verifyRegistrationResponse({
        response,
        expectedChallenge: pending.challenge,
        expectedOrigin: this.config.origin,
        expectedRPID: this.config.rpId,
        requireUserVerification: true,
      });
    } catch (err) {
      return this.#reject("registration", errorMessage(err));
    }
    if (!result.verified) return this.#reject("registration", "not verified");

    const info = result.registrationInfo;
    const user: RpUser = this.#users.get(username) ?? {
      username,
      displayName: pending.displayName,
      userHandle: pending.userHandle,
      credentials: [],
    };
    const credential: RpCredential = {
      id: info.credential.id,
      publicKey: info.credential.publicKey,
      counter: info.credential.counter,
      backedUp: info.credentialBackedUp,
      deviceType: info.credentialDeviceType,
      registeredAt: Date.now(),
    };
    this.#users.set(username, { ...user, credentials: [...user.credentials, credential] });
    this.events.push({ kind: "registered", username, credentialId: credential.id });
    return credential;
  }

  async authenticationOptions(username?: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const user = username === undefined ? undefined : this.#users.get(username);
    if (username !== undefined && user === undefined) throw new RelyingPartyError(`unknown user ${username}`);
    const options = await generateAuthenticationOptions({
      rpID: this.config.rpId,
      userVerification: "required",
      allowCredentials: user?.credentials.map((c) => ({ id: c.id })) ?? [],
    });
    this.#pendingAuthentication.add(options.challenge);
    return options;
  }

  async verifyAuthentication(
    response: AuthenticationResponseJSON,
  ): Promise<{ username: string; credential: RpCredential }> {
    const owner = this.#findCredential(response.id);
    if (owner === undefined) return this.#reject("authentication", "unknown credential");
    const { user, credential } = owner;

    // WebAuthn L3 §7.2 step 6: the user handle, when returned, must identify the credential's owner.
    const userHandle = response.response.userHandle;
    if (userHandle !== undefined && userHandle !== encodeB64url(user.userHandle)) {
      return this.#reject("authentication", "userHandle does not match credential owner");
    }

    let result;
    try {
      result = await verifyAuthenticationResponse({
        response,
        // Challenges are single-use: consumed on first verification attempt.
        expectedChallenge: (c) => this.#pendingAuthentication.delete(c),
        expectedOrigin: this.config.origin,
        expectedRPID: this.config.rpId,
        credential: { id: credential.id, publicKey: credential.publicKey, counter: credential.counter },
        requireUserVerification: true,
      });
    } catch (err) {
      return this.#reject("authentication", errorMessage(err));
    }
    if (!result.verified) return this.#reject("authentication", "signature not verified");

    // WebAuthn L3 §7.2 step 22: store the new counter. SimpleWebAuthn only
    // compares counters when either value is non-zero (see GAP-17).
    credential.counter = result.authenticationInfo.newCounter;
    credential.lastUsedAt = Date.now();
    this.events.push({
      kind: "authenticated",
      username: user.username,
      credentialId: credential.id,
      counter: credential.counter,
    });
    return { username: user.username, credential };
  }

  #findCredential(id: string): { user: RpUser; credential: RpCredential } | undefined {
    for (const user of this.#users.values()) {
      const credential = user.credentials.find((c) => c.id === id);
      if (credential) return { user, credential };
    }
    return undefined;
  }

  #reject(stage: "registration" | "authentication", reason: string): never {
    this.events.push({ kind: "rejected", stage, reason });
    throw new RelyingPartyError(`${stage} rejected: ${reason}`);
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
