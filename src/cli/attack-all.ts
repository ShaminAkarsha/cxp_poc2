/**
 * Run every registered attack scenario under both profiles and write
 * reports/attack-matrix.{json,md}.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { SCENARIOS } from "../adversary/registry.js";
import { meetsExpectation, type ObservedOutcome, type ScenarioResult } from "../adversary/types.js";
import { getPolicy, PROFILE_NAMES } from "../policy/index.js";

interface ResultEntry {
  expected: string;
  observed: ObservedOutcome;
  pass: boolean;
  evidence: string;
}

interface MatrixEntry {
  id: string;
  title: string;
  gaps: string[];
  threats: string[];
  results: Record<string, ResultEntry>;
}

async function main() {
  console.log(`Running ${SCENARIOS.length} scenario(s) under ${PROFILE_NAMES.length} profile(s)…\n`);
  const matrix: MatrixEntry[] = [];

  for (const scenario of SCENARIOS) {
    console.log(`${scenario.id}: ${scenario.title}`);
    const entry: MatrixEntry = {
      id: scenario.id,
      title: scenario.title,
      gaps: [...scenario.gaps],
      threats: [...scenario.threats],
      results: {},
    };

    for (const profile of PROFILE_NAMES) {
      const policy = getPolicy(profile);
      let result: ScenarioResult;
      try {
        result = await scenario.run(policy);
      } catch (err) {
        result = {
          id: scenario.id,
          profile,
          outcome: "error",
          evidence: `unhandled: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
      const expected = scenario.expected[profile];
      const pass = meetsExpectation(expected, result.outcome);
      entry.results[profile] = { expected, observed: result.outcome, pass, evidence: result.evidence };
      const mark = pass ? "✓" : "✗";
      console.log(`  ${mark} ${profile}: expected ${expected}, observed ${result.outcome}`);
    }
    matrix.push(entry);
  }

  await mkdir("reports", { recursive: true });

  await writeFile("reports/attack-matrix.json", JSON.stringify(matrix, null, 2) + "\n");

  const md = [
    "# Attack Matrix",
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    "| ID | Scenario | Gaps | spec-minimal | hardened |",
    "|---|---|---|---|---|",
    ...matrix.map((e) => {
      const fmt = (r?: ResultEntry) => (r ? `${r.pass ? "✓" : "✗"} ${r.observed}` : "—");
      return `| ${e.id} | ${e.title} | ${e.gaps.join(", ")} | ${fmt(e.results["spec-minimal"])} | ${fmt(e.results["hardened"])} |`;
    }),
    "",
    "## Evidence",
    "",
    ...matrix.flatMap((e) => [
      `### ${e.id}: ${e.title}`,
      "",
      ...PROFILE_NAMES.map((p) => {
        const r = e.results[p];
        return r ? `- **${p}**: ${r.observed} — ${r.evidence}` : `- **${p}**: —`;
      }),
      "",
    ]),
  ].join("\n");
  await writeFile("reports/attack-matrix.md", md);

  const total = matrix.length * PROFILE_NAMES.length;
  const passed = matrix.reduce((n, e) => n + Object.values(e.results).filter((r) => r.pass).length, 0);
  console.log(`\n${passed}/${total} assertions match expectations.`);
  console.log("Wrote reports/attack-matrix.json and reports/attack-matrix.md");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
