/**
 * M2 exit criterion: the software authenticator registers and authenticates
 * at the demo RP over loopback HTTP (baseline, no migration).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { encodeB64url } from "../../src/cxf/b64url.js";
import { SoftwareAuthenticator } from "../../src/provider/authenticator.js";
import { Vault } from "../../src/provider/vault.js";
import { RpHttpClient } from "../../src/rp/client.js";
import { LOOPBACK_HOST, startDemoRp, type RunningRp } from "../../src/rp/server.js";

let running: RunningRp;
let client: RpHttpClient;
let provider: SoftwareAuthenticator;

beforeEach(async () => {
  running = await startDemoRp();
  client = new RpHttpClient(running.url, running.rp.config.origin);
  provider = new SoftwareAuthenticator(new Vault());
});

afterEach(async () => {
  await running.close();
});

describe("demo RP baseline (no migration)", () => {
  it("listens on loopback only", () => {
    const address = running.server.address();
    expect(typeof address === "object" && address?.address).toBe(LOOPBACK_HOST);
  });

  it("registers a passkey and records it as a backed-up multi-device credential", async () => {
    const reg = await client.register(provider, "alice", "Alice");
    expect(reg.body).toMatchObject({ verified: true, backedUp: true });
    const stored = running.rp.getUser("alice")!.credentials[0]!;
    expect(stored.deviceType).toBe("multiDevice");
    expect(stored.counter).toBe(0);
    // The RP's user handle is the one the authenticator stored.
    expect(encodeB64url(running.rp.getUser("alice")!.userHandle)).toBe(encodeB64url(provider.vault.list()[0]!.userHandle));
  });

  it("authenticates username-first and discoverably", async () => {
    await client.register(provider, "alice");
    expect((await client.login(provider, "alice")).body).toMatchObject({ verified: true, username: "alice" });
    expect((await client.login(provider)).body).toMatchObject({ verified: true, username: "alice" });
  });

  it("keeps counter 0 at both ends across repeated logins", async () => {
    await client.register(provider, "alice");
    for (let i = 0; i < 3; i++) {
      expect((await client.login(provider, "alice")).body).toMatchObject({ verified: true, counter: 0 });
    }
    expect(running.rp.getUser("alice")!.credentials[0]!.counter).toBe(0);
  });

  it("keeps two users' passkeys separate", async () => {
    const bobProvider = new SoftwareAuthenticator(new Vault());
    await client.register(provider, "alice");
    await client.register(bobProvider, "bob");
    expect((await client.login(bobProvider)).body).toMatchObject({ verified: true, username: "bob" });
    expect((await client.login(provider)).body).toMatchObject({ verified: true, username: "alice" });
  });
});

describe("demo RP rejects invalid ceremonies", () => {
  beforeEach(async () => {
    await client.register(provider, "alice");
  });

  it("replayed assertion (single-use challenge)", async () => {
    const assertion = provider.get(await client.loginOptions("alice"), client.origin);
    expect((await client.submitAssertion(assertion)).ok).toBe(true);
    const replay = await client.submitAssertion(assertion);
    expect(replay.status).toBe(400);
    expect(replay.body.verified).toBe(false);
  });

  it("assertion signed for a different origin", async () => {
    const options = await client.loginOptions("alice");
    const assertion = provider.get(options, "https://sub.localhost");
    const res = await client.submitAssertion(assertion);
    expect(res.status).toBe(400);
    expect(String(res.body.error)).toMatch(/origin/);
  });

  it("tampered signature", async () => {
    const assertion = provider.get(await client.loginOptions("alice"), client.origin);
    const sig = Buffer.from(assertion.response.signature, "base64url");
    sig[sig.length - 1]! ^= 0x01;
    assertion.response.signature = sig.toString("base64url");
    expect((await client.submitAssertion(assertion)).status).toBe(400);
  });

  it("unknown credential", async () => {
    const stranger = new SoftwareAuthenticator(new Vault());
    stranger.create(
      { ...(await (await client.post("/webauthn/register/options", { username: "mallory" })).body), } as never,
      client.origin,
    );
    const assertion = stranger.get(await client.loginOptions(), client.origin);
    const res = await client.submitAssertion(assertion);
    expect(res.status).toBe(400);
    expect(String(res.body.error)).toMatch(/unknown credential/);
  });

  it("userHandle that does not belong to the credential's owner", async () => {
    const assertion = provider.get(await client.loginOptions("alice"), client.origin);
    assertion.response.userHandle = encodeB64url(new Uint8Array(32).fill(9)); // not covered by the signature
    const res = await client.submitAssertion(assertion);
    expect(res.status).toBe(400);
    expect(String(res.body.error)).toMatch(/userHandle/);
  });

  it("registration without a pending challenge", async () => {
    const options = await client.post("/webauthn/register/options", { username: "carol" });
    const response = new SoftwareAuthenticator(new Vault()).create(options.body as never, client.origin);
    expect((await client.post("/webauthn/register/verify", { username: "carol", response })).ok).toBe(true);
    // Same response again: the challenge was consumed.
    expect((await client.post("/webauthn/register/verify", { username: "carol", response })).status).toBe(400);
  });
});
