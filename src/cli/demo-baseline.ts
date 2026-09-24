/**
 * M2 baseline demo: one provider registers a passkey at the demo RP and
 * signs in with it. No migration yet.
 *
 *   pnpm demo:baseline [--profile spec-minimal|hardened]
 */
import { SoftwareAuthenticator } from "../provider/authenticator.js";
import { Vault } from "../provider/vault.js";
import { resolvePolicy } from "../policy/index.js";
import { RpHttpClient } from "../rp/client.js";
import { startDemoRp } from "../rp/server.js";
import { encodeB64url } from "../cxf/b64url.js";

const policy = resolvePolicy();
const running = await startDemoRp();
const client = new RpHttpClient(running.url, running.rp.config.origin);
const providerA = new SoftwareAuthenticator(new Vault());

try {
  console.log(`profile: ${policy.profile} (the RP and authenticator behave the same in both)`);
  console.log(`demo RP listening on ${running.url}  (origin ${running.rp.config.origin}, RP ID localhost)\n`);

  const reg = await client.register(providerA, "alice", "Alice Example");
  console.log("1. register alice with Provider A ->", reg.body);

  const [stored] = providerA.vault.list();
  if (stored) {
    console.log("   Provider A vault now holds (the fields a CXF Passkey will need):");
    console.log({
      credentialId: encodeB64url(stored.credentialId),
      rpId: stored.rpId,
      username: stored.username,
      userDisplayName: stored.userDisplayName,
      userHandle: encodeB64url(stored.userHandle),
      signCount: stored.signCount,
      backupEligible: stored.backupEligible,
    });
  }

  const login1 = await client.login(providerA, "alice");
  console.log("\n2. login as alice (username-first) ->", login1.body);

  const login2 = await client.login(providerA);
  console.log("3. login without username (discoverable passkey) ->", login2.body);

  const options = await client.loginOptions("alice");
  const assertion = providerA.get(options, client.origin);
  const first = await client.submitAssertion(assertion);
  const replay = await client.submitAssertion(assertion);
  console.log("4. submit one assertion twice ->", { first: first.body.verified, replay: replay.body });

  console.log("\nRP event log:");
  for (const event of running.rp.events) console.log("  ", event);
} finally {
  await running.close();
}
