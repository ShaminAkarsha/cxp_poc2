/**
 * Registered scenario implementations. Each reuses its catalog entry's
 * metadata so IDs, GAPs and expectations cannot drift from the README.
 */
import { SCENARIO_CATALOG } from "./catalog.js";
import { a01 } from "./scenarios/a01.js";
import { a02 } from "./scenarios/a02.js";
import { a03 } from "./scenarios/a03.js";
import { a04 } from "./scenarios/a04.js";
import { a05 } from "./scenarios/a05.js";
import { a06 } from "./scenarios/a06.js";
import { a07 } from "./scenarios/a07.js";
import { a08 } from "./scenarios/a08.js";
import { a09 } from "./scenarios/a09.js";
import { a10 } from "./scenarios/a10.js";
import { a11 } from "./scenarios/a11.js";
import { a12 } from "./scenarios/a12.js";
import { a13 } from "./scenarios/a13.js";
import type { Scenario, ScenarioDefinition } from "./types.js";

export const SCENARIOS: readonly Scenario[] = [a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11, a12, a13];

export function catalogEntry(id: string): ScenarioDefinition {
  const entry = SCENARIO_CATALOG.find((s) => s.id === id);
  if (entry === undefined) throw new Error(`unknown scenario ${id}`);
  return entry;
}
