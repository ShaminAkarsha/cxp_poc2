/**
 * Registered scenario implementations. Add each scenario module here, e.g.
 *
 *   import { a01 } from "./scenarios/a01-request-key-substitution.js";
 *   export const SCENARIOS: readonly Scenario[] = [a01];
 *
 * Each implementation must reuse its catalog entry's metadata
 * (`{ ...catalogEntry("A-01"), run }`) so IDs, GAPs and expectations cannot drift.
 */
import { SCENARIO_CATALOG } from "./catalog.js";
import type { Scenario, ScenarioDefinition } from "./types.js";

export const SCENARIOS: readonly Scenario[] = [];

export function catalogEntry(id: string): ScenarioDefinition {
  const entry = SCENARIO_CATALOG.find((s) => s.id === id);
  if (entry === undefined) throw new Error(`unknown scenario ${id}`);
  return entry;
}
