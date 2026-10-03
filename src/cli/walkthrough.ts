/**
 * M8 CLI walkthrough.
 *
 *   pnpm walkthrough [--mode indirect|direct] [--profile spec-minimal|hardened]
 *   pnpm walkthrough --compare [--mode ...]     both profiles, one after the other
 */
import { getPolicy, PROFILE_NAMES, resolvePolicy } from "../policy/index.js";
import { runWalkthrough, type WalkthroughResult } from "../scenario/walkthrough.js";

const args = process.argv.slice(2);
const modeArg = args.find((a) => a.startsWith("--mode="))?.slice(7) ?? args[args.indexOf("--mode") + 1];
const mode = modeArg === "direct" ? "direct" : "indirect";
const policies = args.includes("--compare") ? PROFILE_NAMES.map(getPolicy) : [resolvePolicy()];

function print(result: WalkthroughResult): void {
  console.log(`\n${"=".repeat(72)}\n profile: ${result.profile}   mode: ${result.mode}   result: ${result.ok ? "OK" : "FAILED"}\n${"=".repeat(72)}`);
  result.steps.forEach((s, i) => {
    console.log(`\n${i + 1}. ${s.ok ? "✔" : "✘"} ${s.title}${s.gaps.length ? `   [${s.gaps.join(", ")}]` : ""}`);
    for (const fact of s.facts) console.log(`     ${fact}`);
  });
  if (result.prompts.length > 0) {
    console.log("\nWhat the (simulated) user was shown:");
    for (const p of result.prompts) console.log(`   • ${p}`);
  }
}

for (const policy of policies) print(await runWalkthrough(policy, mode));
