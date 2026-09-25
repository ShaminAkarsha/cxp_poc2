/**
 * M5 demo: register at the RP with Provider A, migrate to Provider B with
 * CXP, then sign in at the RP from Provider B.
 *
 *   pnpm demo:e2e [--mode indirect|direct] [--profile spec-minimal|hardened]
 */
import { resolvePolicy } from "../policy/index.js";
import { createWorld, migrate } from "../scenario/world.js";

const policy = resolvePolicy();
const modeArg = process.argv.find((a) => a.startsWith("--mode="))?.slice(7) ?? process.argv[process.argv.indexOf("--mode") + 1];
const mode = modeArg === "direct" ? "direct" : "indirect";

const world = await createWorld(policy);
try {
  console.log(`profile: ${policy.profile}, mode: ${mode}, RP at ${world.rp.url} (origin ${world.rpClient.origin})\n`);

  const reg = await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
  console.log("1. Alice registers at the RP using Provider A        ->", reg.body.verified ? "registered" : reg.body);
  const before = await world.rpClient.login(world.providerA.authenticator, "alice");
  console.log("2. Alice signs in with Provider A                    ->", before.body);

  const report = await migrate(world, mode);
  console.log(`3. CXP migration A -> B (${mode})                     -> imported ${report.imported.length}, skipped ${report.skipped.length}`);

  const after = await world.rpClient.login(world.providerB.authenticator, "alice");
  console.log("4. Alice signs in with Provider B (migrated passkey) ->", after.body);

  const clone = await world.rpClient.login(world.providerA.authenticator, "alice");
  console.log("5. Provider A's original copy also still signs in   ->", clone.body);

  const stored = world.rp.rp.getUser("alice")?.credentials ?? [];
  console.log(`\nRP view: ${stored.length} registered credential(s): ${stored.map((c) => `${c.id} counter ${c.counter}`).join(", ")}.`);
  console.log("Steps 4 and 5 used the same credential with counter 0 and identical authenticator data,");
  console.log("so the RP cannot tell the two providers apart (GAP-15, GAP-17: see attack A-10).");
} finally {
  await world.close();
}
