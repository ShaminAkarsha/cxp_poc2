import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_PROFILE,
  GAPS_WITHOUT_FLAG,
  getPolicy,
  POLICY_FLAG_NAMES,
  POLICY_FLAGS,
  PROFILE_NAMES,
  ProfileSelectionError,
  resolvePolicy,
  resolveProfileName,
} from "../../src/policy/index.js";

const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
const registerGaps = [...readme.matchAll(/^\| (GAP-\d{2}) \|/gm)].map((m) => m[1] ?? "");

describe("policy flag registry (README §3, §6)", () => {
  it("maps each flag to exactly one GAP, and no GAP to two flags", () => {
    const gaps = POLICY_FLAG_NAMES.map((f) => POLICY_FLAGS[f].gap);
    expect(new Set(gaps).size).toBe(gaps.length);
  });

  it("references only GAPs that exist in the README Gap Register", () => {
    expect(registerGaps.length).toBeGreaterThan(0);
    for (const flag of POLICY_FLAG_NAMES) expect(registerGaps).toContain(POLICY_FLAGS[flag].gap);
    for (const gap of Object.keys(GAPS_WITHOUT_FLAG)) expect(registerGaps).toContain(gap);
  });

  it("accounts for every register GAP as either flagged or explicitly flagless", () => {
    const flagged = new Set<string>(POLICY_FLAG_NAMES.map((f) => POLICY_FLAGS[f].gap));
    const flagless = new Set(Object.keys(GAPS_WITHOUT_FLAG));
    for (const gap of registerGaps) {
      expect(flagged.has(gap) || flagless.has(gap), `${gap} has no flag and no reason`).toBe(true);
      expect(flagged.has(gap) && flagless.has(gap), `${gap} is both flagged and flagless`).toBe(false);
    }
  });
});

describe("profiles (README §3)", () => {
  it("spec-minimal enables no mitigation", () => {
    const policy = getPolicy("spec-minimal");
    for (const flag of POLICY_FLAG_NAMES) expect(policy.flags[flag], flag).toBe(false);
  });

  it("hardened closes every flagged gap", () => {
    const policy = getPolicy("hardened");
    for (const flag of POLICY_FLAG_NAMES) expect(policy.flags[flag], flag).toBe(true);
  });

  it("profiles are immutable", () => {
    const policy = getPolicy("spec-minimal");
    expect(Object.isFrozen(policy)).toBe(true);
    expect(Object.isFrozen(policy.flags)).toBe(true);
  });
});

describe("runtime profile selection", () => {
  it("defaults to spec-minimal", () => {
    expect(DEFAULT_PROFILE).toBe("spec-minimal");
    expect(resolveProfileName([], {})).toBe("spec-minimal");
  });

  it.each(PROFILE_NAMES)("accepts --profile %s and --profile=%s", (name) => {
    expect(resolveProfileName(["--profile", name], {})).toBe(name);
    expect(resolveProfileName([`--profile=${name}`], {})).toBe(name);
  });

  it("reads CXP_PROFILE, with the CLI flag taking precedence", () => {
    expect(resolveProfileName([], { CXP_PROFILE: "hardened" })).toBe("hardened");
    expect(resolveProfileName(["--profile", "spec-minimal"], { CXP_PROFILE: "hardened" })).toBe("spec-minimal");
    expect(resolvePolicy([], { CXP_PROFILE: "hardened" }).profile).toBe("hardened");
  });

  it("rejects unknown or missing profile values", () => {
    expect(() => resolveProfileName(["--profile", "lax"], {})).toThrow(ProfileSelectionError);
    expect(() => resolveProfileName(["--profile"], {})).toThrow(ProfileSelectionError);
    expect(() => resolveProfileName([], { CXP_PROFILE: "HARDENED" })).toThrow(ProfileSelectionError);
  });
});
