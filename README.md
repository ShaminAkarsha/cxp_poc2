# CXP Migration PoC — Security Evaluation Testbed

Proof-of-concept implementation of the FIDO Credential Exchange Protocol (CXP) and Credential Exchange Format (CXF), built as an experimental testbed for the final-year research project:

> **Security and Privacy Analysis of Cross-Provider Passkey Migration using the FIDO Credential Exchange Protocol (CXP)**
> P. A. Akarsha Shamin (22001867) — SCS 4224, University of Colombo School of Computing
> Supervisor: Prof. T.N.K. De Zoysa

This file is the **single source of truth** for the coding agent and the researcher. It must be read at the start of every session and updated at the end of every session.

---

## 1. Purpose and Research Contract

The PoC exists to produce **experimental evidence** for a threat model (PASTA, with STRIDE applied to protocol data flows). It is not a production credential manager.

The PoC must demonstrate three things:

1. **Functional correctness.** A passkey migrated from Provider A to Provider B with CXP/CXF still completes a WebAuthn authentication ceremony at a relying party.
2. **Conformant vulnerability.** Identified threats are exploitable against an implementation that satisfies every normative requirement of the specifications (`spec-minimal` profile).
3. **Mitigation effectiveness.** The same attacks fail against an implementation that fills specification gaps with established standard practice (`hardened` profile).

A claim of the form "CXP is vulnerable to X" is valid only if X succeeds under `spec-minimal`, and every choice enabling X is traceable to a MAY, a SHOULD, or specification silence (a GAP-xx entry). The result must never depend on the implementation violating a MUST.

---

## 2. Pinned Specifications

| ID | Document | Status | Location |
|---|---|---|---|
| CXP | Credential Exchange Protocol, 3 Oct 2024 (`cxp-v1.0-wd-20241003`) | Working Draft | `docs/specs/Credential_Exchange_Protocol.pdf` |
| CXF | Credential Exchange Format, 9 Mar 2026 (`cxf-v1.0-ps-errata-20260309`) | Proposed Standard | `docs/specs/Credential_Exchange_Format.pdf` |
| HPKE | RFC 9180 | Informational RFC | external |
| JWK | RFC 7517 | Proposed Standard | external |
| WebAuthn | W3C WebAuthn Level 3 | Recommendation | external |

**Version skew (documented limitation).** CXP normatively references a June 2024 CXF draft, but this PoC implements the March 2026 CXF Proposed Standard. Any incompatibility this causes is recorded in the Gap Register rather than silently resolved.

**Citation convention.** Every spec-driven code path carries a comment of the form `// CXP §3.2 (MUST)` or `// CXF §3.3.12 (SHOULD)`. Every gap-driven path carries `// GAP-07`.

---

## 3. Conformance Profiles

The profile is selected at runtime (`--profile spec-minimal|hardened`, or `CXP_PROFILE`). Behavioural differences are expressed only through named boolean policy flags in `src/policy/`, and each flag maps to exactly one GAP-xx entry.

| Profile | Rule |
|---|---|
| `spec-minimal` | Satisfies every MUST. Where the specification says MAY, SHOULD, or is silent, takes the most permissive choice a conformant implementer could legitimately make, and justifies it in the Gap Register. |
| `hardened` | Identical to `spec-minimal`, except each gap is closed using a cited standard practice (RFC, IETF draft, NIST, OWASP). |

The following are **forbidden**:
- adding a mitigation to `spec-minimal`;
- weakening any MUST in either profile;
- introducing a profile difference without a GAP-xx entry.

---

## 4. Architecture

```
┌──────────────┐  ExportRequest  ┌──────────────┐
│  Provider B  │ ──────────────▶ │  Provider A  │
│  (Importer)  │                 │  (Exporter)  │
│  vault + SW  │ ◀────────────── │  vault + SW  │
│ authenticator│  ExportResponse │ authenticator│
└──────┬───────┘                 └──────┬───────┘
       │ assertion                      │ registration
       ▼                                ▼
┌─────────────────────────────────────────────┐
│ Demo Relying Party (Express + SimpleWebAuthn)│
└─────────────────────────────────────────────┘
         ▲ interposes on direct / indirect channels
┌─────────────────────────────────────────────┐
│ Adversary Harness (MITM proxy, file tamper, │
│ replay store, downgrade / key substitution) │
└─────────────────────────────────────────────┘
```

**Why a software authenticator.** Platform authenticators (Secure Enclave, StrongBox) do not expose private keys, so they cannot produce CXF exports. Each provider therefore embeds a software WebAuthn authenticator. It generates P-256 credentials, returns `none` attestation at registration, and signs assertions. This is standard practice for protocol PoCs, and it is a documented threat to external validity.

### 4.1 Planned repository layout

```
docs/specs/            pinned specification PDFs
src/cxf/               CXF types + zod schemas (Account, Collection, Item, Passkey, Fido2Extensions)
src/cxp/               ExportRequest/Response builders, negotiation, response modes
src/crypto/            HPKE (RFC 9180) wrapper, JWE packaging, archive, key encoding
src/policy/            profile definitions and policy flags (one flag ↔ one GAP)
src/provider/          vault, software authenticator, exporter, importer
src/rp/                demo relying party
src/adversary/         attack harness and scenarios
src/cli/               demo CLI (migrate, attack, report)
test/                  unit, integration, and attack tests (vitest)
test/fixtures/         spec-derived fixtures with provenance (e.g. CXF Appendix A)
reports/               generated attack-matrix results (JSON + Markdown)
```

### 4.2 Technology stack

Node.js 20+ LTS, TypeScript (strict), `hpke-js` (`@hpke/core` + a DHKEM X25519/P-256 module), `jose`, `zod`, `fflate`, `express`, `@simplewebauthn/server`, and `vitest`. Node `crypto` is used for P-256 keys and PKCS#8 DER encoding. Package names and APIs must be verified at install time.

**Installed so far (M0–M1, verified 2026-09-24):** pnpm 10, `typescript` 6.0.3 (pinned below 6.1 because `typescript-eslint` 8.70 supports only `<6.1`), `zod` 4.6 (`z.looseObject`, `z.int`), `vitest` 4.1 (vitest 5 drops Node 20), `eslint` 9 + `typescript-eslint` 8.70, `@types/node` 22. Development machine runs Node 23.6, which is not an LTS release and is outside vitest's declared engine range; tests pass on it, but Node 22 or 24 LTS is recommended.

**Commands:** `pnpm install`, then `pnpm check` (typecheck + lint + tests), `pnpm test`, `pnpm lint`, `pnpm typecheck`. Profile: `--profile spec-minimal|hardened` or `CXP_PROFILE` (default `spec-minimal`).

---

## 5. Scope

**In scope:**
- CXF `Account`, `Collection`, `Item`, and `Passkey` (including `Fido2Extensions` with `hmacCredentials`).
- CXP `direct` and `indirect` response modes.
- HPKE `base` mode, plus `auth` mode for `hardened`.
- The end-to-end migration and post-migration authentication.
- The adversary harness.

**Out of scope until Phase 3:**
- `self` mode and `psk`/`auth-psk` modes.
- Non-passkey credential types, except minimal fixtures.
- The simulated TEE.

**Out of scope entirely:**
- Real platform enclave APIs.
- Production UI.
- Network deployment.

---

## 6. Spec-Gap Register

Each entry records the specification clause, the `spec-minimal` choice with its justification, and the `hardened` choice with its standard reference. The agent must add a new entry **before** implementing any behaviour the specification does not fully determine. The seed entries below come from the researcher's preliminary specification analysis and must be verified against the PDFs.

| ID | Gap (spec clause) | `spec-minimal` (conformant, permissive) | `hardened` (standard practice) | Threat link |
|---|---|---|---|---|
| GAP-01 | CXP §2 describes a challenge and a signed challenge response, but the §3.2/§3.3 CDDL defines no such fields | No challenge; the response is not bound to the request | 32-byte random nonce; SHA-256 of the canonical ExportRequest bound into HPKE `info` (RFC 9180 §5.1, RFC 8785 JCS) | TBD |
| GAP-02 | CXP §5 (Implementation Requirements) is empty, so there is no mandatory-to-implement suite | Accept any mutually listed suite in the importer's preference order | MTI suite DHKEM(X25519, HKDF-SHA256) 0x0020 / HKDF-SHA256 0x0001 / AES-256-GCM 0x0002; reject others | TBD |
| GAP-03 | CXP §3.3: the exporter's selection of `hpke`/`archive` is not integrity-bound to the request | Importer accepts any selection present in its own list | Transcript binding via GAP-01; importer verifies the selection equals the first mutually supported entry | TBD |
| GAP-04 | CXP §3.3: version downgrade — "Importing Provider MAY refuse" | Accept a lower version | Reject any version below the requested one | TBD |
| GAP-05 | CXP §3.2 `importer` and §3.3 `exporter` RP IDs are self-asserted and unauthenticated | Display only; no verification | Short Authentication String over the key fingerprints, confirmed by the user on both sides (numeric-comparison pattern; NIST SP 800-63B out-of-band guidance) | TBD |
| GAP-06 | CXP §3.2.1/§3.2.2: the `indirect` Export Request file passes through the filesystem with no integrity protection | Load the file as-is | GAP-05 SAS confirmation of the importer public key before export | TBD |
| GAP-07 | CXP §3.4/§3.5.1: the mapping from HPKE to JWE and the placement of the encapsulated key `enc` are unspecified | Single HPKE context; `enc` carried as a JWK in `ExportResponse.hpke.key`; files sealed in sequence | Per-file content keys derived via the HPKE secret export (RFC 9180 §5.3, label = file path); JWE `alg:"dir"`, `enc:"A256GCM"` (RFC 7516) | TBD |
| GAP-08 | CXP §3.4 references an "anonymous identifier in the export request" that does not exist in the §3.2 CDDL | File names derived from CXF entity IDs | Random 128-bit file names; mapping held only inside the encrypted `index.jwe` | TBD |
| GAP-09 | CXP §3.4: no AAD requirement per file, so files could be swapped or reordered | No AAD | AAD = file path ‖ request digest | TBD |
| GAP-10 | CXP §3.4 references a zip archive layout "as defined in [CXF]", but CXF PS 2026 defines no archive | Zip layout as illustrated in CXP §3.4 (`index.jwe`, `documents/*.jwe`) | Same layout plus a signed or AEAD-bound manifest | TBD |
| GAP-11 | No replay or single-use rule for an ExportResponse, and no importer key lifetime | Importer key reusable; response importable more than once | Ephemeral importer key per request, destroyed after first successful import | TBD |
| GAP-12 | CXP §3.5.3 `deflate` and CXF §3.3.12.5 `uncompressedSize` are claimed values with no limits | No size limits | Enforce decompressed-size caps; verify `uncompressedSize` (decompression-bomb defence, OWASP) | TBD |
| GAP-13 | No normative guidance on handling decrypted PKCS#8 material in memory | Decode to string/JSON freely; no clearing | Keep keys in `Uint8Array`; zero after import (best effort); document JavaScript GC and string-immutability limits | TBD |
| GAP-14 | CXP §3.5.2 `base` mode: the importer cannot authenticate the exporter, so credentials can be injected | Accept any well-formed response | HPKE `auth` mode with the exporter key confirmed via GAP-05 | TBD |
| GAP-15 | CXP §1.1: destruction of source credentials is out of scope | Source copy retained | Out of protocol scope; document as a residual risk | TBD |
| GAP-16 | CXF §3.3.12.3: PRF/hmac-secret seeds MUST be identical across all importers (spec-mandated) | As specified (a MUST in both profiles) | Cannot be mitigated conformantly; demonstrate and recommend a spec change | TBD |
| GAP-17 | CXF §3.3.12 note: signature counter MUST be zero and never incremented (spec-mandated) | As specified | Cannot be mitigated conformantly; demonstrate loss of relying-party clone detection | TBD |
| GAP-18 | CXF §1.3: entity identifiers are shared in clear text during CXP sessions (metadata) | Use CXF IDs as file names/metadata | Minimise clear-text metadata; see GAP-08 | TBD |
| GAP-19 | CXP `direct` mode: transport security is unspecified | Plain HTTP on loopback | TLS on loopback (self-signed test CA) plus GAP-01 binding | TBD |
| GAP-20 | CXF §1.3, §2.1, §2.1.2, §3.1.1, §3.3.12, §3.3.12.3: MUSTs bind the *producer* of a CXF document (identifiers ≤ 64 bytes and unique per Account; optional arrays absent when empty; `version` a published CXF level; `key` is PKCS#8 DER), but no clause says what an importer does with a document that breaks them. b64url padding/canonical form is unspecified (RFC 4648 §3.2 requires padding unless the referring spec says otherwise; CXF does not say, but its Appendix A omits padding). `credWithUV`/`credWithoutUV` length is only a SHOULD (32 bytes) | Importer rejects only structurally malformed input (missing required members, wrong JSON types, non-base64url alphabet). It tolerates producer-MUST violations, accepts padded and non-canonical b64url, any CXF version, and any hmac credential length (Postel; our exporter still emits conformant documents in both profiles, so no MUST is weakened) | Reject any producer-MUST violation; require unpadded canonical base64url (RFC 4648 §3.5, §5; JOSE convention RFC 7515 §2); require `version.major = 1`; require 32-byte hmac credentials (CTAP 2.1 hmac-secret `CredRandom`) | TBD |
| GAP-21 | CXF §3.1 `timestamp`: no freshness requirement; the importer is never told to check it | Timestamp ignored | Reject documents dated in the future (beyond clock skew) or older than the Export Request (replay resistance, NIST SP 800-63B §5.2.8) | TBD |
| GAP-22 | CXF §3.1 `exporterRpId` and CXP §3.3 `exporter` are both self-asserted, and nothing requires them to agree | No cross-check | Require `Header.exporterRpId` = `ExportResponse.exporter` = the GAP-05 confirmed identity | TBD |
| GAP-23 | CXP §3.2.2 `direct` reads "if **indirect** is requested, the Exporter MUST return the Export Response over the same transport": apparently an editorial error for `direct` (indirect MUST write to the filesystem) | Read as `direct` (only coherent reading) | Same (no profile difference) | — |
| GAP-24 | CXP §3.2 `version` "MUST correspond to a published level of the CXP standard", but no level has been published (Working Draft) and no numbering is defined | Use `0` (the CDDL `.default`) | Same (no profile difference). Consequence: a downgrade below 0 is impossible, so A-05 must use a hypothetical request `version: 1` | — |

The Threat link column is filled in once the PASTA/STRIDE threat model assigns T-xx identifiers.

---

## 7. Attack Scenarios (planned)

Each scenario is a vitest test executed under both profiles. The expected outcome is **succeeds** under `spec-minimal` and **fails (detected or rejected)** under `hardened`. The only exceptions are spec-mandated gaps (GAP-16, GAP-17), which are expected to succeed under both profiles.

| ID | Scenario | Gaps exercised | Expected (min / hard) | Result |
|---|---|---|---|---|
| A-01 | Importer public-key substitution in an `indirect` Export Request file | 05, 06 | succeeds / fails | — |
| A-02 | Active MITM on a `direct` channel, relaying a substituted importer key | 05, 19 | succeeds / fails | — |
| A-03 | Replay of a captured ExportResponse to the importer | 01, 11 | succeeds / fails | — |
| A-04 | HPKE suite / archive negotiation tampering | 02, 03 | succeeds / fails | — |
| A-05 | Protocol version downgrade (needs a hypothetical request `version: 1`; see GAP-24) | 04, 24 | succeeds / fails | — |
| A-06 | Swapping or reordering files inside the archive | 07, 09 | succeeds / fails | — |
| A-07 | Credential injection by an unauthenticated exporter | 14 | succeeds / fails | — |
| A-08 | Decompression bomb via `deflate` or `largeBlob` | 12 | succeeds / fails | — |
| A-09 | Post-import memory residue of PKCS#8 keys (heap snapshot) | 13 | succeeds / reduced | — |
| A-10 | Clone use of source and migrated credential goes undetected by the RP | 15, 17 | succeeds / succeeds | — |
| A-11 | PRF seed reuse across two importers | 16 | succeeds / succeeds | — |
| A-12 | Metadata observable to a passive observer of the Export Response | 18 | succeeds / reduced | — |

Results are written to `reports/attack-matrix.{json,md}` by `pnpm attack:all`.

---

## 8. Milestone Board

Status values: `todo` / `in-progress` / `done` / `blocked`.

| ID | Milestone | Exit criteria | Status |
|---|---|---|---|
| M0 | Scaffold | TS strict, vitest, lint, `docs/specs/` present, `CLAUDE.md` created, policy/profile skeleton | done |
| M1 | CXF model | zod schemas for Header, Account, Collection, Item, Passkey, Fido2Extensions; round-trip tests against CXF Appendix A example | done |
| M2 | Authenticator + RP | Software authenticator registers and authenticates at the demo RP (baseline, no migration) | todo |
| M3 | CXP crypto core | HPKE wrapper, ExportRequest/Response builders + schemas, JWE packaging, archive; RFC 9180 test vectors pass | todo |
| M4 | Exporter / Importer | `direct` and `indirect` modes working under both profiles | todo |
| M5 | End-to-end migration | Provider A → B migration; migrated passkey authenticates at the RP; counter = 0 verified | todo |
| M6 | Adversary harness | A-01 to A-12 implemented; attack matrix report generated | todo |
| M7 | Hardened profile | All hardened policy flags implemented; matrix shows the expected split | todo |
| M8 | Demo interface | CLI walkthrough plus a minimal local web dashboard for supervisor demonstration | todo |
| M9 | Simulated TEE (Phase 3) | Enclave-boundary simulation; decapsulation and import inside the simulated boundary; exposure comparison | todo |

---

## 9. Working Rules for the Agent

1. Read this file first in every session, then work only on the earliest milestone that is not `done`, unless instructed otherwise.
2. Before coding a milestone, state the plan and the spec clauses it depends on.
3. On any specification ambiguity or silence, **stop and add a GAP-xx entry** before implementing it. Never resolve a gap silently.
4. The PDFs in `docs/specs/` override this README. Record any discrepancy in the Session Log and correct the README.
5. Honour the profile rules in §3 exactly. One policy flag corresponds to one GAP.
6. No real user credentials, no network egress beyond loopback, and no telemetry.
7. Every milestone ships with tests; attack scenarios assert profile-specific outcomes.
8. Verify library APIs against installed packages instead of assuming them.
9. At session end, update the Milestone Board, the Gap Register, the Attack Scenarios results, and the Session Log.

---

## 10. Researcher Notes (for the dissertation)

- **Claim scope.** Results show that a *specification-conformant implementation* can exhibit the identified weaknesses. They do not show that any deployed product does.
- **External validity.** Threats include the use of a software authenticator, a Working Draft CXP, and version skew between CXP (2024) and CXF (2026).
- **Deliverable.** The `hardened` deltas, with their standard references, constitute the proposed secure-development practices and recommendations for future CXP revisions.
- **Out of scope for this PoC.** Apple's iOS 26 import/export is CXF without CXP: an orchestrating party under CXF §5.1. It is analysed separately in the threat model, not in this PoC.

---

## 11. Session Log

| Date | Session summary | Milestones touched | New/changed GAPs |
|---|---|---|---|
| — | README created; seed Gap Register from preliminary spec analysis | — | GAP-01 to GAP-19 (seed) |
| 2026-09-24 | **M0:** moved the spec PDFs from `doce/specs/` (typo, spaced file names) to `docs/specs/` using the names in §2; added `CLAUDE.md`, pnpm, strict TypeScript, vitest and ESLint; added `src/policy/`, with one flag per GAP, `GAPS_WITHOUT_FLAG` listing the flagless GAPs with reasons, frozen profiles, and `--profile`/`CXP_PROFILE` selection. Tests check that `spec-minimal` has every flag off and that each flag's GAP appears in this register. **M1:** `src/cxf/`: structural zod schemas (both profiles, loose objects per CXF §3.1.1); b64url helpers; GAP-20 producer checks (`strict.ts`); `parseCxfHeader(input, policy)`; a serializer that enforces the CXF §2.1.2 array rules. `test/fixtures/cxf-appendix-a.json` was extracted verbatim from the PDF. It parses and round-trips under both profiles, its passkey `key` is a valid P-256 PKCS#8 key, and its `largeBlob` inflates to the claimed 129 bytes. 75 tests pass. **Spec verification:** the seed GAP-01 to GAP-19 clause citations match the PDFs (GAP-10 confirmed: CXF PS 2026 contains no archive or zip definition). **README/PDF discrepancies and notes:** (1) the spec location was wrong (fixed by moving files); (2) CXP normatively cites WebAuthn **Level 2**, while CXF cites Level 3 and §2 pins Level 3, another version-skew item; (3) CXP §1.2's BCP 14 boilerplate is unrendered (`{::boilerplate bcp14-tagged}`), so CXP never formally declares RFC 2119 keywords; (4) the CXF Conformance section says RFC 2119 keywords are normative even in lower case, so lower-case "should/must" in CXF must be read as normative; (5) the CXP §3.2.2 `direct`/`indirect` typo (GAP-23); (6) the CXP version has no defined value (GAP-24), which affects A-05. Byte-identical JSON round-trip is not a criterion, because zod re-emits keys in schema order and JSON member order has no meaning (RFC 8259 §4). | M0, M1 | GAP-20 (implemented, flag `strictCxfValidation`); GAP-21, GAP-22 (flags defined, implementation M4/M7); GAP-23, GAP-24 (no flag) |