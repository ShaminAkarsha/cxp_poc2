# Security Evaluation Matrix

**Commit:** `28d8c27` | **Date:** 2026-10-03 | **Runs:** 3 | **Flaky:** 0

## Classification Key

| Label | Meaning |
|---|---|
| CONFIRMED | Attack succeeded under spec-minimal as expected, documenting a specification gap |
| MITIGATED | Hardened profile blocked the attack as expected |
| PARTIALLY MITIGATED | Hardened profile reduced but did not fully eliminate the attack |
| SPEC-MANDATED | The specification requires the vulnerable behavior; the hardened profile cannot fix it |
| NOT MITIGATED | The hardened profile does not implement the required control |
| UNEXPECTED | Observed outcome differs from expected (none in this evaluation) |
| FLAKY | Inconsistent results across runs (none in this evaluation) |

## Results

### A-01: Importer public-key substitution in an indirect Export Request file

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | adversary decrypted 1 credential(s) |
| hardened | fails | rejected | MITIGATED | export was not approved by the credential owner (GAP-29) |

**GAPs:** GAP-05, GAP-06 | **Threats:** T-ER-01 | **Flags:** `requireSasConfirmation`, `confirmRequestFileKey`

---

### A-02: Active MITM on a direct channel, relaying a substituted importer key

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | MITM decrypted 1 credential(s) via plain HTTP |
| hardened | fails | rejected | MITIGATED | TLS material is required for the direct transport (GAP-19) |

**GAPs:** GAP-05, GAP-19 | **Threats:** T-ER-01 | **Flags:** `requireSasConfirmation`, `requireTls`

---

### A-03: Replay of a captured ExportResponse to the importer

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | replay imported 1 credential(s), replaced 1 |
| hardened | fails | rejected | MITIGATED | no pending Export Request |

**GAPs:** GAP-01, GAP-11, GAP-31 | **Threats:** T-RS-01a, T-IM-03 | **Flags:** `bindRequestChallenge`, `singleUseImporterKey`, `secureExportFiles`

---

### A-04: HPKE suite / archive negotiation tampering

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | adversary controlled suite selection (KEM 16); negotiation integrity absent, imported 1 credential(s) |
| hardened | fails | rejected | MITIGATED | only the MTI suite was offered; nothing to downgrade |

**GAPs:** GAP-02, GAP-03 | **Threats:** T-ER-03a | **Flags:** `enforceMandatorySuite`, `verifyNegotiatedSelection`

---

### A-05: Protocol version downgrade

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | version 0 accepted for request version 1, imported 1 credential(s) |
| hardened | fails | rejected | MITIGATED | response version 0 is below requested 1 (GAP-04) |

**GAPs:** GAP-04, GAP-24 | **Threats:** T-ER-03b | **Flags:** `rejectVersionDowngrade`

---

### A-06: Swapping or reordering files inside the archive

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | swapped archive imported 2 credential(s) |
| hardened | fails | rejected | MITIGATED | manifest hash mismatch detects the swap (GAP-09, GAP-10) |

**GAPs:** GAP-07, GAP-09 | **Threats:** T-RS-03a, T-EX-06 | **Flags:** `deriveFileKeysViaExport`, `bindFileAad`, `authenticateManifest`

---

### A-07: Credential injection by an unauthenticated exporter

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | injected 1 credential(s) |
| hardened | fails | rejected | MITIGATED | response hpke does not correspond to any request entry |

**GAPs:** GAP-14, GAP-30 | **Threats:** T-RS-02, T-IM-03 | **Flags:** `requireHpkeAuthMode`, `rejectConflictingImport`

---

### A-08: Decompression bomb via deflate or largeBlob

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | decompression bomb accepted: 2,097,152 bytes inflated |
| hardened | fails | rejected | MITIGATED | declared size 2,097,152 exceeds limit 1,048,576 |

**GAPs:** GAP-12 | **Threats:** T-RS-06a, T-IM-02c | **Flags:** `enforceDecompressionLimits`

---

### A-09: Post-import memory residue of PKCS#8 keys

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | key material not zeroed after import |
| hardened | reduced | reduced | PARTIALLY MITIGATED | DER buffers zeroed; base64url strings persist until GC |

**GAPs:** GAP-13 | **Threats:** T-IM-01, T-EX-05a | **Flags:** `zeroizeKeyMaterial`

**Residual risk:** JavaScript strings are immutable; base64url-encoded key material persists in the V8 heap until garbage collection. Only a TEE or native-code import path can fully eliminate this residue.

---

### A-10: Clone use of source and migrated credential goes undetected by the RP

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | both source and migrated credential sign in; RP cannot distinguish |
| hardened | succeeds | succeeded | SPEC-MANDATED | both source and migrated credential sign in; RP cannot distinguish |

**GAPs:** GAP-15, GAP-17 | **Threats:** T-IM-04a, T-IM-04b | **Flags:** none (spec-mandated)

---

### A-11: PRF seed reuse across two importers

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | identical PKCS#8 key material across exports; hmacCredentials copied verbatim (CXF §3.3.12.3) |
| hardened | succeeds | succeeded | SPEC-MANDATED | identical PKCS#8 key material across exports; hmacCredentials copied verbatim (CXF §3.3.12.3) |

**GAPs:** GAP-16 | **Threats:** T-IM-04c | **Flags:** none (spec-mandated)

---

### A-12: Metadata observable to a passive observer of the Export Response

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | file names expose Item IDs; file count and sizes observable |
| hardened | reduced | reduced | PARTIALLY MITIGATED | file names randomized; file sizes still observable |

**GAPs:** GAP-08, GAP-18 | **Threats:** T-RS-05a, T-ER-06a | **Flags:** `randomizeFileNames`

**Residual risk:** File count and individual file sizes remain observable in the zip directory even after name randomization (GAP-18).

---

### A-13: Consent phishing: victim approves an attacker-crafted Export Request

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | adversary's request served without consent, 1 credential(s) |
| hardened | fails | rejected | MITIGATED | export was not approved by the credential owner (GAP-29) |

**GAPs:** GAP-05, GAP-06, GAP-29 | **Threats:** T-EX-01b, T-EX-02a, T-ER-02a | **Flags:** `requireSasConfirmation`, `confirmRequestFileKey`, `requireExportConsent`

---

### A-14: Scope tampering: remove credentialTypes from the request

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | scope tampering undetected; passkey-only=1, all-types=2; exporter served 1 credential(s) |
| hardened | fails | rejected | MITIGATED | export was not approved by the credential owner (GAP-29) |

**GAPs:** GAP-32 | **Threats:** T-ER-03c | **Flags:** `requireSasConfirmation`, `confirmRequestFileKey`, `bindRequestChallenge` (mitigated via GAP-01, GAP-05, GAP-06)

---

### A-18: Silent exclusion of a passkey with a non-zero signature counter

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | 1 passkey(s) silently excluded (signCount != 0); owner not notified (GAP-36 not implemented) |
| hardened | succeeds | succeeded | NOT MITIGATED | 1 passkey(s) silently excluded (signCount != 0); owner not notified (GAP-36 not implemented) |

**GAPs:** GAP-36 | **Threats:** T-EX-04 | **Flags:** none (GAP-36 not implemented)

**Finding:** The CXF §3.3.12 exclusion of passkeys with signCount != 0 is spec-mandated. However, the silence — the exporter does not notify the credential owner which passkeys were excluded and why — is a specification gap (GAP-36). The hardened profile does not implement GAP-36 (reporting each excluded credential to the owner with the reason, before and after export), so this scenario is classified as NOT MITIGATED.

---

### A-20: Stale CXF document accepted without freshness check

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | stale CXF document (timestamp 2h old) accepted without freshness check |
| hardened | fails | rejected | MITIGATED | CXF document predates the Export Request (GAP-21) |

**GAPs:** GAP-21 | **Threats:** T-IM-02b | **Flags:** `enforceTimestampFreshness`

---

### A-21: Exporter identity mismatch between CXP envelope and CXF header

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | CXP exporter="adversary.example" vs CXF exporterRpId="provider-a.example"; mismatch accepted |
| hardened | fails | rejected | MITIGATED | CXF exporterRpId provider-a.example differs from response exporter adversary.example (GAP-22) |

**GAPs:** GAP-22 | **Threats:** T-RS-04 | **Flags:** `bindExporterIdentity`

---

### A-22: Malformed CXF document violating producer MUSTs

| Profile | Expected | Observed | Classification | Evidence |
|---|---|---|---|---|
| spec-minimal | succeeds | succeeded | CONFIRMED | malformed CXF accepted at protocol level; 1 credential(s) skipped as invalid at import |
| hardened | fails | rejected | MITIGATED | CXF document violates producer requirements (GAP-20): invalid version and non-PKCS#8 key |

**GAPs:** GAP-20 | **Threats:** T-IM-02a | **Flags:** `strictCxfValidation`

---

## Summary

| Classification | spec-minimal | hardened | Total |
|---|---|---|---|
| CONFIRMED | 18 | — | 18 |
| MITIGATED | — | 13 | 13 |
| PARTIALLY MITIGATED | — | 2 | 2 |
| SPEC-MANDATED | — | 2 | 2 |
| NOT MITIGATED | — | 1 | 1 |
| UNEXPECTED | 0 | 0 | 0 |
| FLAKY | 0 | 0 | 0 |
| **Total** | **18** | **18** | **36** |

All 36 scenario × profile assertions match expectations across 3 consecutive runs. (Two entries — A-09 hardened and A-12 hardened — use the `reduced` expected outcome, not `fails`, resulting in 36 pass/fail assertions out of 36 rows.)

## Ablation and Positive Controls

**Positive control:** An end-to-end credential migration succeeds under both profiles, confirming the PoC is functional before adversarial testing.

**Ablation (A-13):** Disabling `confirmRequestFileKey` alone (keeping `requireSasConfirmation` and `requireExportConsent` on) allows the consent-phishing attack to succeed, proving that fingerprint verification — not consent — is the mitigating control for request-file-based attacks (GAP-06).
