/**
 * Security scenario contract (README §7). Scenario implementations live in
 * src/adversary/scenarios/ and are registered in registry.ts.
 */
import type { Policy, ProfileName } from "../policy/index.js";

/** What README §7 predicts for a profile. */
export type ExpectedOutcome = "succeeds" | "fails" | "reduced";

/** What was observed when the scenario ran. */
export type ObservedOutcome = "succeeded" | "rejected" | "detected" | "reduced" | "error";

export interface ScenarioResult {
  readonly id: string;
  readonly profile: ProfileName;
  readonly outcome: ObservedOutcome;
  /** One line: the observable fact the outcome is based on. */
  readonly evidence: string;
}

export interface ScenarioDefinition {
  /** "A-01" … as in README §7. */
  readonly id: string;
  readonly title: string;
  /** GAP-xx entries whose spec-minimal choices the scenario relies on. */
  readonly gaps: readonly string[];
  /** T-xx identifiers from the threat model, once assigned (README §6 Threat link). */
  readonly threats: readonly string[];
  readonly expected: Readonly<Record<ProfileName, ExpectedOutcome>>;
  /**
   * False while the hardened mitigations for `gaps` are unimplemented (M7);
   * the hardened assertion is then reported as pending, not as a result.
   */
  readonly hardenedMitigationReady: boolean;
}

export interface Scenario extends ScenarioDefinition {
  run(policy: Policy): Promise<ScenarioResult>;
}

/** Does an observed outcome satisfy the README §7 expectation? */
export function meetsExpectation(expected: ExpectedOutcome, observed: ObservedOutcome): boolean {
  switch (expected) {
    case "succeeds":
      return observed === "succeeded";
    case "fails":
      return observed === "rejected" || observed === "detected";
    case "reduced":
      return observed === "reduced" || observed === "rejected" || observed === "detected";
  }
}
