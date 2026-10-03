/**
 * M8: the walkthrough completes for every profile and mode, and the dashboard
 * serves its page and API on loopback.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startDashboard, type RunningDashboard } from "../../src/dashboard/server.js";
import { getPolicy, POLICY_FLAG_NAMES, PROFILE_NAMES } from "../../src/policy/index.js";
import { runWalkthrough } from "../../src/scenario/walkthrough.js";

const CASES = PROFILE_NAMES.flatMap((p) => (["indirect", "direct"] as const).map((m) => [p, m] as const));

describe.each(CASES)("walkthrough under %s, %s mode", (profile, mode) => {
  it("completes every step", async () => {
    const result = await runWalkthrough(getPolicy(profile), mode);
    expect(result.steps.filter((s) => !s.ok).map((s) => s.facts)).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.steps.at(-2)?.title).toMatch(/Provider B/);
    // Only the hardened profile asks the user anything.
    expect(result.prompts.length > 0).toBe(profile === "hardened");
  });
});

describe("dashboard", () => {
  let dashboard: RunningDashboard;
  beforeAll(async () => {
    dashboard = await startDashboard();
  });
  afterAll(async () => {
    await dashboard.close();
  });

  it("listens on loopback and serves a self-contained page", async () => {
    expect(dashboard.url.startsWith("http://127.0.0.1:")).toBe(true);
    const res = await fetch(dashboard.url);
    const html = await res.text();
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    expect(res.headers.get("content-security-policy")).toMatch(/default-src 'self'/);
    expect(html).toContain("<title>CXP Migration Testbed</title>");
    expect(html).not.toMatch(/https?:\/\/(?!127\.0\.0\.1)/); // no external assets
  });

  it("lists every policy flag with its GAP", async () => {
    const data = (await (await fetch(`${dashboard.url}/api/policy`)).json()) as { flags: { name: string; gap: string }[] };
    expect(data.flags.map((f) => f.name)).toEqual([...POLICY_FLAG_NAMES]);
  });

  it("runs a walkthrough and validates its input", async () => {
    const post = (body: unknown) =>
      fetch(`${dashboard.url}/api/run`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const ok = (await (await post({ profile: "hardened", mode: "indirect" })).json()) as { ok: boolean };
    expect(ok.ok).toBe(true);
    expect((await post({ profile: "lax", mode: "indirect" })).status).toBe(400);
    expect((await post({ profile: "hardened", mode: "carrier-pigeon" })).status).toBe(400);
  });
});
