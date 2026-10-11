# CXP/CXF Security Evaluation Report

> **Renumbered 2026-10-11 (IDs only; results unchanged):** A-18 → A-15, A-20 → A-16, A-21 → A-17, A-22 → A-18, and GAP-36 → GAP-33, so that scenario and gap IDs are contiguous. `reports/security-raw.log` is the unmodified raw output of this run and still uses the old IDs.

## 1. Run Metadata

| Field | Value |
|---|---|
| Date | 2026-10-03 |
| Commit | `bfaa788` (main) |
| Package | cxp-poc 0.1.0 |
| Node | v23.6.0 |
| Vitest | 4.1.11 |
| Platform | darwin-arm64 |
| Runs | 3 (sequential, same process) |
| Test files | 24 (13 original + 5 new scenarios + 6 variant/ablation) |
| Tests per run | 47 |
| Total tests executed | 141 (47 × 3) |
| Failures | 0 |
| Flaky tests | 0 |
| attack:all assertions | 36/36 pass |
| Environment | In-process / 127.0.0.1 only |
| Run durations | 3.80s, 3.51s, 4.25s (test phase) |

## 2. Summary Counts

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

Every spec-minimal run confirms the attack succeeds (CONFIRMED). Under the hardened profile, 13 of 18 attacks are blocked (MITIGATED), 2 are reduced but not eliminated (PARTIALLY MITIGATED), 2 succeed by design because the specification mandates the vulnerable behavior (SPEC-MANDATED), and 1 is NOT MITIGATED because the required control (GAP-33) is not implemented. No unexpected outcomes or flaky results were observed.

## 3. Per-Scenario Analysis

### A-01 — Importer public-key substitution in an indirect Export Request file

**Threats:** T-ER-01

**spec-minimal (CONFIRMED):** The adversary replaces the importer's public key in the request file with their own. The exporter encrypts to the adversary's key without verification. The adversary decrypts 1 credential.

**hardened (MITIGATED):** The exporter prompts the user with the request's 128-bit fingerprint (`requireSasConfirmation`, `confirmRequestFileKey`). The simulated user compares the fingerprint against the importer's display; the adversary's substituted key produces a different fingerprint, and the export is rejected: *"export was not approved by the credential owner (GAP-29)."*

**Flags exercised:** `requireSasConfirmation` (GAP-05), `confirmRequestFileKey` (GAP-06).

---

### A-02 — Active MITM on a direct channel, relaying a substituted importer key

**Threats:** T-ER-01

**spec-minimal (CONFIRMED):** The exporter starts an HTTP service (no TLS). The adversary intercepts the plaintext request, substitutes the importer key, and decrypts the response. 1 credential exfiltrated.

**hardened (MITIGATED):** `startExporterService()` throws before binding: *"TLS material is required for the direct transport (GAP-19)."* The MITM attack is blocked at the transport level.

**Flags exercised:** `requireTls` (GAP-19), `requireSasConfirmation` (GAP-05).

---

### A-03 — Replay of a captured ExportResponse to the importer

**Threats:** T-RS-01a, T-IM-03

**spec-minimal (CONFIRMED):** The adversary captures an ExportResponse and replays it to the importer. The importer accepts the replay because no request binding exists and the key is reusable. 1 credential imported, 1 replaced.

**hardened (MITIGATED):** The importer's key is destroyed after the first import (`singleUseImporterKey`, GAP-11). The replay finds *"no pending Export Request"* and fails.

**Flags exercised:** `bindRequestChallenge` (GAP-01), `singleUseImporterKey` (GAP-11), `secureExportFiles` (GAP-31).

---

### A-04 — HPKE suite / archive negotiation tampering

**Threats:** T-ER-03a

**spec-minimal (CONFIRMED):** The adversary removes the MTI (X25519/HKDF-SHA256/AES-256-GCM) entry from the request and substitutes a P-256 entry. The exporter accepts the non-MTI suite (KEM 0x0010). The finding is lack of negotiation integrity — KEM 0x0010 (P-256) is not inherently weaker than X25519, but the adversary controlled the suite selection without detection. 1 credential imported.

**hardened (MITIGATED):** The hardened request offers only the MTI suite (1 HPKE entry). There is nothing to remove, and the P-256 substitution is rejected: *"only the MTI suite was offered; nothing to downgrade."*

**Flags exercised:** `enforceMandatorySuite` (GAP-02), `verifyNegotiatedSelection` (GAP-03).

---

### A-05 — Protocol version downgrade

**Threats:** T-ER-03b

**spec-minimal (CONFIRMED):** The request advertises version 1 (a hypothetical future version, since CXP defines only version 0). The exporter responds with version 0. The importer accepts the downgrade without checking. 1 credential imported.

**hardened (MITIGATED):** The importer checks the response version against its request: *"response version 0 is below requested 1 (GAP-04)."*

**Flags exercised:** `rejectVersionDowngrade` (GAP-04).

---

### A-06 — Swapping or reordering files inside the archive

**Threats:** T-RS-03a, T-EX-06

**spec-minimal (CONFIRMED):** The adversary swaps two JWE documents in the zip archive. The importer decrypts both with the shared key (no per-file binding) and imports 2 credentials without detecting the swap.

**hardened (MITIGATED):** The manifest hash (GAP-10) and per-file AAD binding (GAP-09) detect the tampered archive. The rejection message identifies the specific file whose hash does not match the manifest.

**Flags exercised:** `deriveFileKeysViaExport` (GAP-07), `bindFileAad` (GAP-09), `authenticateManifest` (GAP-10, indirectly).

---

### A-07 — Credential injection by an unauthenticated exporter

**Threats:** T-RS-02, T-IM-03

**spec-minimal (CONFIRMED):** The adversary forges an ExportResponse using HPKE base mode (no sender authentication). The injected credential is imported, and a pre-existing credential with the same `credentialId` is silently replaced (GAP-30). The RP then rejects Provider B's assertions because the key material no longer matches the registration.

**hardened (MITIGATED):** The hardened importer requires HPKE auth mode. The adversary's base-mode response fails: *"response hpke does not correspond to any request entry."* Additionally, `rejectConflictingImport` would skip duplicate credential IDs.

**Flags exercised:** `requireHpkeAuthMode` (GAP-14), `rejectConflictingImport` (GAP-30).

---

### A-08 — Decompression bomb via deflate or largeBlob

**Threats:** T-RS-06a, T-IM-02c

**spec-minimal (CONFIRMED):** A 2 MiB compressed entry is inflated without limits. The bomb expands to 2,097,152 bytes.

**hardened (MITIGATED):** `enforceDecompressionLimits` applies `DEFAULT_ARCHIVE_LIMITS` (maxEntryBytes = 1,048,576). The entry's declared size (2,097,152) exceeds the limit and is rejected before inflation.

**Flags exercised:** `enforceDecompressionLimits` (GAP-12).

---

### A-09 — Post-import memory residue of PKCS#8 keys

**Threats:** T-IM-01, T-EX-05a

**spec-minimal (CONFIRMED):** After import, the original DER buffer containing PKCS#8 key material is not zeroed. The key material remains readable in memory.

**hardened (PARTIALLY MITIGATED):** The DER `Uint8Array` buffer is zeroed after import (`zeroizeKeyMaterial`, GAP-13). However, the base64url-encoded string representation (used during JWE decryption and CXF parsing) persists as an immutable JavaScript string in the V8 heap until garbage collection. Outcome: **reduced**, not fully mitigated.

**Residual risk:** Complete key erasure requires a TEE or native-code import path that avoids JavaScript string intermediaries.

**Flags exercised:** `zeroizeKeyMaterial` (GAP-13).

---

### A-10 — Clone use of source and migrated credential goes undetected by the RP

**Threats:** T-IM-04a, T-IM-04b

**spec-minimal (CONFIRMED):** After migration, both the source (Provider A) and migrated (Provider B) credential authenticate at the RP. The RP cannot distinguish the two: both produce byte-identical authenticator data and clientDataJSON (only the ECDSA signature differs due to randomization).

**hardened (SPEC-MANDATED):** The same behavior occurs. CXF mandates counter = 0 on import (GAP-17, CXF §3.3.12), and the specification provides no mechanism for the source provider to revoke or invalidate its copy (GAP-15). The RP has no protocol-level signal.

**Note:** This is a fundamental limitation of the credential portability model. Mitigations would require spec changes: a source-deletion SHOULD, a counter-advance mechanism, or a backup-eligibility (BE) change.

**Flags exercised:** None (spec-mandated behavior).

---

### A-11 — PRF seed reuse across two importers

**Threats:** T-IM-04c

**spec-minimal (CONFIRMED):** Two sequential exports produce byte-identical PKCS#8 key material. Any importer that receives the credential can derive the same signing key.

**hardened (SPEC-MANDATED):** The same behavior occurs. CXF exports the credential's private key deterministically; there is no per-import key derivation or re-keying mechanism (GAP-16). PRF seeds (`hmacCredentials`, CXF §3.3.12.3) would also be copied verbatim.

**Note:** This enables a multi-importer scenario where all importers hold the same symmetric and asymmetric secrets. Mitigations would require per-import re-keying in the specification.

**Flags exercised:** None (spec-mandated behavior).

---

### A-12 — Metadata observable to a passive observer of the Export Response

**Threats:** T-RS-05a, T-ER-06a

**spec-minimal (CONFIRMED):** Archive file names use Item IDs directly (e.g., `CXP-Export/documents/{itemId}.jwe`), leaking per-credential identifiers. File count and sizes are also observable.

**hardened (PARTIALLY MITIGATED):** File names are randomized (`randomizeFileNames`, GAP-08), breaking the Item ID linkage. However, file count (= number of credentials) and individual file sizes remain observable in the zip directory (GAP-18). Outcome: **reduced**.

**Residual risk:** Full metadata confidentiality would require padding entries to a fixed size or using a single encrypted container instead of per-file JWE.

**Flags exercised:** `randomizeFileNames` (GAP-08).

---

### A-13 — Consent phishing: victim approves an attacker-crafted Export Request

**Threats:** T-EX-01b, T-EX-02a, T-ER-02a

**spec-minimal (CONFIRMED):** The adversary crafts an Export Request with their own key and a plausible importer name. The exporter serves the request without any user consent prompt. 1 credential exfiltrated.

**hardened (MITIGATED):** The exporter prompts the user with the request fingerprint. The adversary's request fingerprint does not match any legitimate importer's pending request fingerprint. The export is rejected: *"export was not approved by the credential owner (GAP-29)."*

**Flags exercised:** `requireSasConfirmation` (GAP-05), `confirmRequestFileKey` (GAP-06), `requireExportConsent` (GAP-29).

---

### A-14 — Scope tampering: remove credentialTypes from the request

**Threats:** T-ER-03c | **Gap:** GAP-32

**spec-minimal (CONFIRMED):** The adversary intercepts the indirect request file and strips the `credentialTypes` field, widening the export scope from passkeys-only to all credential types. With a mixed-type vault (passkey + password), the scope widens from 1 to 2 items. The exporter serves the tampered request without detecting the modification.

**hardened (MITIGATED):** The fingerprint of the tampered request differs from the original. The simulated user compares fingerprints and rejects: *"export was not approved by the credential owner (GAP-29)."* Mitigated via GAP-01, GAP-05, GAP-06.

**Flags exercised:** `requireSasConfirmation` (GAP-05), `confirmRequestFileKey` (GAP-06), `bindRequestChallenge` (GAP-01).

---

### A-15 — Silent exclusion of a passkey with a non-zero signature counter

**Threats:** T-EX-04 | **Gap:** GAP-33

**spec-minimal (CONFIRMED):** A passkey with `signCount = 42` is silently excluded from the CXF export document. The credential owner is not notified that a credential was dropped.

**hardened (NOT MITIGATED):** The same behavior occurs. The exclusion itself is spec-mandated (CXF §3.3.12), but the silence — the exporter not notifying the credential owner which passkeys were excluded and why — is not. GAP-33 would require the exporter to report every excluded credential to the owner (with the reason) before and after export. This control is not implemented in the PoC hardened profile because it would require changes to `ExportingProvider` outside the adversary code boundary. Classified as NOT MITIGATED.

**Note:** This is a data-loss risk: credentials that have been used for authentication become silently unexportable. The user may not realize that not all of their passkeys were migrated.

**Flags exercised:** None (GAP-33 not implemented).

---

### A-16 — Stale CXF document accepted without freshness check

**Threats:** T-IM-02b

**spec-minimal (CONFIRMED):** A CXF document with a timestamp 2 hours in the past is accepted by the importer without any freshness check.

**hardened (MITIGATED):** The importer checks that the CXF timestamp is not older than the Export Request's creation time (minus clock skew): *"CXF document predates the Export Request (GAP-21)."*

**Flags exercised:** `enforceTimestampFreshness` (GAP-21).

---

### A-17 — Exporter identity mismatch between CXP envelope and CXF header

**Threats:** T-RS-04

**spec-minimal (CONFIRMED):** The CXP response carries `exporter: "adversary.example"` while the encrypted CXF document says `exporterRpId: "provider-a.example"`. The mismatch is accepted without detection.

**hardened (MITIGATED):** The importer binds the two identities: *"CXF exporterRpId provider-a.example differs from response exporter adversary.example (GAP-22)."*

**Flags exercised:** `bindExporterIdentity` (GAP-22).

---

### A-18 — Malformed CXF document violating producer MUSTs

**Threats:** T-IM-02a

**spec-minimal (CONFIRMED):** A CXF document with invalid PKCS#8 key material (4 bytes of garbage) is accepted at the CXP protocol level. The individual credential is skipped during import as `invalid-field`, but the protocol does not reject the document.

**hardened (MITIGATED):** Strict CXF validation catches the invalid key material and the unsupported CXF version before any credentials are processed: *"CXF document violates producer requirements (GAP-20)."*

**Flags exercised:** `strictCxfValidation` (GAP-20).

## 4. Ablation and Control Results

### Positive Control

**Test:** Legitimate migration under hardened (indirect mode) completes successfully and the migrated credential authenticates at the demo RP.

**Result:** PASS. 1 credential imported, 0 skipped. Login with Provider B authenticator verified (`true`). This confirms the hardened profile does not break legitimate migrations — the security controls are applied without false positives.

### Ablation: Consent Without Key Confirmation (A-01, A-13)

**Configuration:** Hardened profile with `requireExportConsent = true` but `requireSasConfirmation = false` and `confirmRequestFileKey = false`. The simulated user approves every consent prompt.

**A-01 ablation result:** Attack **succeeds**. The adversary substitutes the importer key in the request file. The exporter prompts for consent (GAP-29) but does not show the request fingerprint because SAS confirmation is disabled. The user approves, and the adversary decrypts the credentials.

**A-13 ablation result:** Attack **succeeds**. The adversary crafts an Export Request with their own key. The exporter prompts for consent but without fingerprint verification. The user approves the adversary's request.

**Conclusion:** Consent alone (GAP-29) is insufficient to prevent key-substitution and consent-phishing attacks. The mitigating control is fingerprint verification (`requireSasConfirmation` / `confirmRequestFileKey`), not the consent prompt itself.

### A-02 TLS Variant: Application-Layer Key Substitution With TLS Present

**Configuration:** Hardened exporter with TLS configured (HTTPS with test CA). The adversary substitutes the importer key at the application layer (not at the TLS level).

**Result:** Attack **rejected**. The rejection is by fingerprint mismatch (GAP-29), not by missing TLS material (GAP-19). This confirms that TLS (GAP-19) protects the transport channel, but the application-layer fingerprint confirmation (GAP-05) provides the definitive mitigation against key substitution, even when the transport is already secured.

### A-07b: Auth-Mode Forgery With Adversary Sender Key

**spec-minimal result:** Attack **succeeds**. The adversary forges a base-mode response and injects 1 credential.

**hardened result:** Attack **rejected**. The adversary uses HPKE auth mode with their own sender key pair. The importer's `confirmExporter` callback compares the adversary's sender key fingerprint against the legitimate exporter's key fingerprint. The fingerprints do not match, and the import is rejected: *"exporter key was not confirmed by the user (GAP-05)."*

**Conclusion:** Even when the adversary correctly uses HPKE auth mode, the sender key confirmation (GAP-05/14) prevents credential injection. The adversary cannot forge the exporter's key fingerprint without possessing the exporter's private key.

### A-07c: Conflicting Import (rejectConflictingImport)

**spec-minimal result:** Second import **replaces** the existing credential. 1 replaced, 1 imported. The RP still verifies the credential because the same key material is re-imported.

**hardened result:** Second import **skipped**. The existing credential is kept. 1 skipped with reason `conflict`, 0 imported. The RP still verifies the original credential.

**Conclusion:** `rejectConflictingImport` (GAP-30) prevents an adversary from silently replacing existing credentials by re-importing with the same `credentialId`.

### A-11 (Rewritten): hmacCredentials Reuse Across Importers

**Both profiles:** Two export responses are created from the same CXF document (enriched with hmacCredentials) and sent to two independent importers. Each importer decrypts its own response using its own keyring; the decrypted CXF payloads are then compared directly. `StoredPasskey` does not preserve `fido2Extensions` through import (the `#toRecord` method discards them), so the comparison is done on the decrypted CXF payloads rather than stored vault records. Both importers receive byte-identical `hmacCredentials.credWithUV`, `hmacCredentials.credWithoutUV`, and `key` fields — confirming that PRF seeds (CTAP 2.1 CredRandom) are replicated verbatim to every importer (CXF §3.3.12.3).

## 5. UNEXPECTED and FLAKY Analysis

**None.** All 36 scenario × profile combinations produced the expected outcome consistently across 3 runs. No UNEXPECTED classifications and no FLAKY results were recorded.

## 6. Hardened Policy Flag Mapping

The table below maps each hardened policy flag to the GAP it implements and the scenarios that exercise it.

| Flag | GAP | Exercised by |
|---|---|---|
| `bindRequestChallenge` | GAP-01 | A-03, A-14 |
| `enforceMandatorySuite` | GAP-02 | A-04 |
| `verifyNegotiatedSelection` | GAP-03 | A-04 |
| `rejectVersionDowngrade` | GAP-04 | A-05 |
| `requireSasConfirmation` | GAP-05 | A-01, A-02, A-13, A-14, A-07b |
| `confirmRequestFileKey` | GAP-06 | A-01, A-13, A-14 |
| `deriveFileKeysViaExport` | GAP-07 | A-06 |
| `randomizeFileNames` | GAP-08 | A-12 |
| `bindFileAad` | GAP-09 | A-06 |
| `authenticateManifest` | GAP-10 | A-06 (indirect) |
| `singleUseImporterKey` | GAP-11 | A-03 |
| `enforceDecompressionLimits` | GAP-12 | A-08 |
| `zeroizeKeyMaterial` | GAP-13 | A-09 |
| `requireHpkeAuthMode` | GAP-14 | A-07, A-07b |
| `requireTls` | GAP-19 | A-02, A-02 TLS variant |
| `strictCxfValidation` | GAP-20 | A-18 |
| `enforceTimestampFreshness` | GAP-21 | A-16 |
| `bindExporterIdentity` | GAP-22 | A-17 |
| `requireExportConsent` | GAP-29 | A-13, ablation |
| `rejectConflictingImport` | GAP-30 | A-07, A-07c |
| `secureExportFiles` | GAP-31 | A-03 |

**Coverage:** All 21 policy flags are now directly exercised by at least one scenario. The 3 previously unexercised flags — `strictCxfValidation` (GAP-20), `enforceTimestampFreshness` (GAP-21), and `bindExporterIdentity` (GAP-22) — are now covered by A-18, A-16, and A-17 respectively.

## 7. Unexercised GAP Entries

GAP entries that have no associated policy flag and are not directly exercised by any scenario:

| GAP | Description | Reason not exercised |
|---|---|---|
| GAP-15 | Source provider retains credentials after export | Documented by A-10 (consequence, not exercisable as a flag) |
| GAP-16 | Deterministic key export (no per-import re-keying) | Documented by A-11 (consequence, not exercisable as a flag) |
| GAP-17 | CXF mandates counter = 0 on import | Documented by A-10 (consequence, not exercisable as a flag) |
| GAP-18 | File sizes observable in archive | Documented by A-12 residual risk |
| GAP-23 | CXP §3.2.2 `direct`/`indirect` mode naming typo | Specification editorial issue; no security test applicable |
| GAP-24 | CXP version field has no defined value | Documented by A-05 (used to construct the downgrade scenario) |
| GAP-25 | CXF has no BE/BS/AAGUID member | Documented by A-10 analysis; not independently testable |
| GAP-26 | CXP CDDL contradicts prose | Specification editorial issue; no security test applicable |
| GAP-27 | `deflate` has no defined target in CXP | Specification editorial issue; no security test applicable |
| GAP-28 | "corresponds" is undefined in CXP | Specification ambiguity; no security test applicable |
| GAP-32 | Scope tampering via credentialTypes removal | Exercised by A-14; mitigated via GAP-01, GAP-05, GAP-06 (no dedicated flag) |
| GAP-33 | Exporter does not notify owner of excluded credentials | Exercised by A-15; NOT MITIGATED (control not implemented) |

## 8. Conclusions

1. **All 18 attack scenarios are reproducible.** Under the spec-minimal profile (most permissive conformant implementation), every scenario succeeds, confirming the identified specification gaps.

2. **The hardened profile mitigates 13 of 18 attacks.** The 21 policy flags collectively close the protocol-level gaps. Two residual risks remain where mitigation is partial (PARTIALLY MITIGATED): memory residue (A-09) and metadata leakage (A-12). One attack (A-15) is NOT MITIGATED because GAP-33 (owner notification of excluded credentials) is not implemented.

3. **Two gaps are spec-mandated.** Clone credential use (A-10) and PRF seed reuse (A-11) succeed under both profiles because the CXF specification mandates the vulnerable behavior. These require specification-level changes.

4. **One gap is not mitigated.** Silent counter exclusion (A-15) succeeds under both profiles. The exclusion is spec-mandated, but the silence (GAP-33: exporter does not notify the owner) is a specification gap that the hardened profile does not address. Implementing GAP-33 would require changes to `ExportingProvider` to report every excluded credential to the owner with the reason, before and after export.

5. **All 21 policy flags are now exercised.** The addition of A-16 (GAP-21), A-17 (GAP-22), and A-18 (GAP-20) closes the previous gap in flag coverage.

6. **Ablation testing confirms the mitigating controls.** Consent alone (GAP-29) does not prevent key-substitution or consent-phishing attacks; the fingerprint verification flags (`requireSasConfirmation`, `confirmRequestFileKey`) are the actual mitigating controls. TLS (GAP-19) secures the transport but does not substitute for application-layer key confirmation.

7. **No flaky or unexpected results.** All 36 scenario × profile assertions produced consistent, expected outcomes across 3 runs.

---

*Generated from 3 evaluation runs on commit `28d8c27`, 2026-10-03.*
