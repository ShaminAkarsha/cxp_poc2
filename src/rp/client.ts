/**
 * Drives a registration or authentication ceremony against the demo RP over
 * HTTP, using a SoftwareAuthenticator in place of a browser.
 */
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server";
import type { SoftwareAuthenticator } from "../provider/authenticator.js";

export interface CeremonyResult {
  readonly ok: boolean;
  readonly status: number;
  readonly body: Record<string, unknown>;
}

export class RpHttpClient {
  constructor(
    /** Where to send HTTP requests (loopback). */
    readonly baseUrl: string,
    /** WebAuthn origin the client reports in clientDataJSON. */
    readonly origin: string,
  ) {}

  async post(path: string, body: unknown): Promise<CeremonyResult> {
    const res = await fetch(new URL(path, this.baseUrl), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { ok: res.ok, status: res.status, body: (await res.json()) as Record<string, unknown> };
  }

  async register(authenticator: SoftwareAuthenticator, username: string, displayName = username): Promise<CeremonyResult> {
    const options = await this.post("/webauthn/register/options", { username, displayName });
    if (!options.ok) return options;
    const response = authenticator.create(options.body as unknown as PublicKeyCredentialCreationOptionsJSON, this.origin);
    return this.post("/webauthn/register/verify", { username, response });
  }

  async loginOptions(username?: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const options = await this.post("/webauthn/login/options", username === undefined ? {} : { username });
    if (!options.ok) throw new Error(`login/options failed: ${JSON.stringify(options.body)}`);
    return options.body as unknown as PublicKeyCredentialRequestOptionsJSON;
  }

  async submitAssertion(response: AuthenticationResponseJSON): Promise<CeremonyResult> {
    return this.post("/webauthn/login/verify", { response });
  }

  /** Full login: fetch options, sign with the authenticator, submit. */
  async login(authenticator: SoftwareAuthenticator, username?: string): Promise<CeremonyResult> {
    const options = await this.loginOptions(username);
    return this.submitAssertion(authenticator.get(options, this.origin));
  }
}
