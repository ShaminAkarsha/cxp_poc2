import { generateKeyPair, MTI_SUITE } from "../../crypto/hpke.js";
import { createExportResponse } from "../../cxp/response.js";
import { encodeB64url, type Header } from "../../cxf/index.js";
import { isEnabled, type Policy } from "../../policy/index.js";
import { ImportingProvider } from "../../provider/importer.js";
import { Vault } from "../../provider/vault.js";
import { createWorld } from "../../scenario/world.js";
import { catalogEntry } from "../registry.js";
import type { Scenario, ScenarioResult } from "../types.js";

export const a22: Scenario = {
  ...catalogEntry("A-22"),
  async run(policy: Policy): Promise<ScenarioResult> {
    const world = await createWorld(policy);
    try {
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
      const testImporter = new ImportingProvider({
        rpId: world.providerB.importer.config.rpId,
        vault: new Vault(),
        policy,
        confirmExporter: () => true,
      });
      const request = await testImporter.createRequest("indirect");
      const { header } = world.providerA.exporter.buildCxf(request);
      const malformed: Header = {
        ...header,
        version: { major: 99, minor: 0 },
        accounts: header.accounts.map((a) => ({
          ...a,
          collections: [],
          items: a.items.map((item) => ({
            ...item,
            credentials: item.credentials.map((c) => ({
              ...c,
              key: encodeB64url(new Uint8Array([0xde, 0xad, 0xbe, 0xef])),
            })),
          })),
        })),
      };
      const rpId = world.providerA.exporter.config.rpId;
      const senderKey = isEnabled(policy, "requireHpkeAuthMode") ? await generateKeyPair(MTI_SUITE.kem) : undefined;
      const response = await createExportResponse({
        request,
        header: malformed,
        exporter: rpId,
        policy,
        ...(senderKey ? { senderKey } : {}),
      });
      try {
        const report = await testImporter.importResponse(response);
        const skippedKeys = report.skipped.filter((s) => s.reason === "invalid-field" || s.reason === "unsupported-key");
        if (skippedKeys.length > 0) {
          return { id: "A-22", profile: policy.profile, outcome: "succeeded", evidence: `malformed CXF accepted at protocol level; ${skippedKeys.length} credential(s) skipped as invalid at import` };
        }
        return { id: "A-22", profile: policy.profile, outcome: "succeeded", evidence: "malformed CXF document accepted without strict validation" };
      } catch (err) {
        return { id: "A-22", profile: policy.profile, outcome: "rejected", evidence: `${err instanceof Error ? err.message : String(err)}` };
      }
    } finally {
      await world.close();
    }
  },
};
