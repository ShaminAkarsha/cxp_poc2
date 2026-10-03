import { createZip, DEFAULT_ARCHIVE_LIMITS, readZip } from "../../crypto/archive.js";
import { isEnabled, type Policy } from "../../policy/index.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a08: Scenario = {
  ...catalogEntry("A-08"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const bomb = new Uint8Array(2 << 20);
    const zip = createZip(new Map([["bomb.bin", bomb]]));
    const limits = isEnabled(policy, "enforceDecompressionLimits") ? DEFAULT_ARCHIVE_LIMITS : undefined;
    try {
      const files = readZip(zip, limits);
      const inflated = files.get("bomb.bin");
      return { id: "A-08", profile: policy.profile, outcome: "succeeded", evidence: `decompression bomb accepted: ${inflated?.length ?? 0} bytes inflated` };
    } catch (err) {
      return { id: "A-08", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
    }
  },
};
