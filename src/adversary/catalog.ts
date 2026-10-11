/**
 * README §7 scenario catalog: metadata only. Keep in sync with the README
 * table (checked by test/security/catalog.test.ts).
 */
import type { ScenarioDefinition } from "./types.js";

const std = { "spec-minimal": "succeeds", hardened: "fails" } as const;

export const SCENARIO_CATALOG: readonly ScenarioDefinition[] = [
  { id: "A-01", title: "Importer public-key substitution in an indirect Export Request file", gaps: ["GAP-05", "GAP-06"], threats: ["T-ER-01"], expected: std, hardenedMitigationReady: true },
  { id: "A-02", title: "Active MITM on a direct channel, relaying a substituted importer key", gaps: ["GAP-05", "GAP-19"], threats: ["T-ER-01"], expected: std, hardenedMitigationReady: true },
  { id: "A-03", title: "Replay of a captured ExportResponse to the importer", gaps: ["GAP-01", "GAP-11", "GAP-31"], threats: ["T-RS-01a", "T-IM-03"], expected: std, hardenedMitigationReady: true },
  { id: "A-04", title: "HPKE suite / archive negotiation tampering", gaps: ["GAP-02", "GAP-03"], threats: ["T-ER-03a"], expected: std, hardenedMitigationReady: true },
  { id: "A-05", title: "Protocol version downgrade", gaps: ["GAP-04", "GAP-24"], threats: ["T-ER-03b"], expected: std, hardenedMitigationReady: true },
  { id: "A-06", title: "Swapping or reordering files inside the archive", gaps: ["GAP-07", "GAP-09"], threats: ["T-RS-03a", "T-EX-06"], expected: std, hardenedMitigationReady: true },
  { id: "A-07", title: "Credential injection by an unauthenticated exporter", gaps: ["GAP-14", "GAP-30"], threats: ["T-RS-02", "T-IM-03"], expected: std, hardenedMitigationReady: true },
  { id: "A-08", title: "Decompression bomb via deflate or largeBlob", gaps: ["GAP-12"], threats: ["T-RS-06a", "T-IM-02c"], expected: std, hardenedMitigationReady: true },
  { id: "A-09", title: "Post-import memory residue of PKCS#8 keys", gaps: ["GAP-13"], threats: ["T-IM-01", "T-EX-05a"], expected: { "spec-minimal": "succeeds", hardened: "reduced" }, hardenedMitigationReady: true },
  { id: "A-10", title: "Clone use of source and migrated credential goes undetected by the RP", gaps: ["GAP-15", "GAP-17"], threats: ["T-IM-04a", "T-IM-04b"], expected: { "spec-minimal": "succeeds", hardened: "succeeds" }, hardenedMitigationReady: true },
  { id: "A-11", title: "PRF seed reuse across two importers", gaps: ["GAP-16"], threats: ["T-IM-04c"], expected: { "spec-minimal": "succeeds", hardened: "succeeds" }, hardenedMitigationReady: true },
  { id: "A-12", title: "Metadata observable to a passive observer of the Export Response", gaps: ["GAP-08", "GAP-18"], threats: ["T-RS-05a", "T-ER-06a"], expected: { "spec-minimal": "succeeds", hardened: "reduced" }, hardenedMitigationReady: true },
  { id: "A-13", title: "Consent phishing: victim approves an attacker-crafted Export Request", gaps: ["GAP-05", "GAP-06", "GAP-29"], threats: ["T-EX-01b", "T-EX-02a", "T-ER-02a"], expected: std, hardenedMitigationReady: true },
  { id: "A-14", title: "Scope tampering: remove credentialTypes from the request", gaps: ["GAP-32"], threats: ["T-ER-03c"], expected: std, hardenedMitigationReady: true },
  { id: "A-15", title: "Silent exclusion of a passkey with a non-zero signature counter", gaps: ["GAP-33"], threats: ["T-EX-04"], expected: { "spec-minimal": "succeeds", hardened: "succeeds" }, hardenedMitigationReady: true },
  { id: "A-16", title: "Stale CXF document accepted without freshness check", gaps: ["GAP-21"], threats: ["T-IM-02b"], expected: std, hardenedMitigationReady: true },
  { id: "A-17", title: "Exporter identity mismatch between CXP envelope and CXF header", gaps: ["GAP-22"], threats: ["T-RS-04"], expected: std, hardenedMitigationReady: true },
  { id: "A-18", title: "Malformed CXF document violating producer MUSTs", gaps: ["GAP-20"], threats: ["T-IM-02a"], expected: std, hardenedMitigationReady: true },
];
