/**
 * README §7 scenario catalog: metadata only. Keep in sync with the README
 * table (checked by test/security/catalog.test.ts).
 */
import type { ScenarioDefinition } from "./types.js";

const std = { "spec-minimal": "succeeds", hardened: "fails" } as const;

export const SCENARIO_CATALOG: readonly ScenarioDefinition[] = [
  { id: "A-01", title: "Importer public-key substitution in an indirect Export Request file", gaps: ["GAP-05", "GAP-06"], threats: ["T-ER-01"], expected: std, hardenedMitigationReady: true },
  { id: "A-02", title: "Active MITM on a direct channel, relaying a substituted importer key", gaps: ["GAP-05", "GAP-19"], threats: ["T-ER-02"], expected: std, hardenedMitigationReady: true },
  { id: "A-03", title: "Replay of a captured ExportResponse to the importer", gaps: ["GAP-01", "GAP-11", "GAP-31"], threats: ["T-ER-03"], expected: std, hardenedMitigationReady: true },
  { id: "A-04", title: "HPKE suite / archive negotiation tampering", gaps: ["GAP-02", "GAP-03"], threats: ["T-ER-04"], expected: std, hardenedMitigationReady: true },
  { id: "A-05", title: "Protocol version downgrade", gaps: ["GAP-04", "GAP-24"], threats: ["T-ER-05"], expected: std, hardenedMitigationReady: true },
  { id: "A-06", title: "Swapping or reordering files inside the archive", gaps: ["GAP-07", "GAP-09"], threats: ["T-ER-06"], expected: std, hardenedMitigationReady: true },
  { id: "A-07", title: "Credential injection by an unauthenticated exporter", gaps: ["GAP-14", "GAP-30"], threats: ["T-ER-07"], expected: std, hardenedMitigationReady: true },
  { id: "A-08", title: "Decompression bomb via deflate or largeBlob", gaps: ["GAP-12"], threats: ["T-ER-08"], expected: std, hardenedMitigationReady: true },
  { id: "A-09", title: "Post-import memory residue of PKCS#8 keys", gaps: ["GAP-13"], threats: ["T-ER-09"], expected: { "spec-minimal": "succeeds", hardened: "reduced" }, hardenedMitigationReady: true },
  { id: "A-10", title: "Clone use of source and migrated credential goes undetected by the RP", gaps: ["GAP-15", "GAP-17"], threats: ["T-ER-10"], expected: { "spec-minimal": "succeeds", hardened: "succeeds" }, hardenedMitigationReady: true },
  { id: "A-11", title: "PRF seed reuse across two importers", gaps: ["GAP-16"], threats: ["T-ER-11"], expected: { "spec-minimal": "succeeds", hardened: "succeeds" }, hardenedMitigationReady: true },
  { id: "A-12", title: "Metadata observable to a passive observer of the Export Response", gaps: ["GAP-08", "GAP-18"], threats: ["T-ER-12"], expected: { "spec-minimal": "succeeds", hardened: "reduced" }, hardenedMitigationReady: true },
  { id: "A-13", title: "Consent phishing: victim approves an attacker-crafted Export Request", gaps: ["GAP-05", "GAP-06", "GAP-29"], threats: ["T-ER-13"], expected: std, hardenedMitigationReady: true },
];
