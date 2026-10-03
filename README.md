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

Authenticator design decisions (implemented in M2, identical in both profiles):
- **Signature counter is always 0.** Under CXF §3.3.12 (MUST), a passkey with a non-zero counter is excluded from export, so a provider whose passkeys are exportable cannot count (GAP-17). SimpleWebAuthn compares counters only when one of them is non-zero, so the RP never runs a clone check on these passkeys. This is the precondition for A-10.
- **BE = BS = 1** (multi-device, backed up) on every credential (GAP-25).
- **Discoverable credentials; user verification simulated as performed** (UV = 1). The AAGUID is all zeros.
- **Simplified client checks.** The WebAuthn client checks are simplified: the RP ID must equal the origin host or a parent domain of it, and the origin must be `https:` or loopback. The public-suffix check is omitted because the PoC uses loopback only.
- **Demo RP settings.** The demo RP uses RP ID `localhost`, origin `http://localhost:<port>`, and listens on `127.0.0.1` only. Its challenges are single-use, and it checks that a returned `userHandle` belongs to the credential's owner (WebAuthn L3 §7.2 step 6), a check SimpleWebAuthn does not perform itself.

### 4.1 Planned repository layout

```
docs/specs/            pinned specification PDFs
src/cxf/               CXF types + zod schemas (Account, Collection, Item, Passkey, Fido2Extensions)
src/cxp/               ExportRequest/Response builders, negotiation, response modes
src/crypto/            HPKE (RFC 9180) wrapper, JWE packaging, archive, key encoding
src/policy/            profile definitions and policy flags (one flag ↔ one GAP)
src/provider/          vault, software authenticator, exporter, importer
src/rp/                demo relying party
src/scenario/          the experimental world (RP + Provider A + Provider B) and `migrate()`
src/adversary/         attack harness and scenarios
src/cli/               demo CLI (walkthrough, migrate, e2e, exchange, baseline)
src/dashboard/         local web dashboard (M8), 127.0.0.1 only
test/                  unit, integration, and attack tests (vitest)
test/fixtures/         spec-derived fixtures with provenance (e.g. CXF Appendix A)
reports/               generated attack-matrix results (JSON + Markdown)
```

### 4.2 Technology stack

Node.js 20+ LTS, TypeScript (strict), `hpke-js` (`@hpke/core` + a DHKEM X25519/P-256 module), `jose`, `zod`, `fflate`, `express`, `@simplewebauthn/server`, and `vitest`. Node `crypto` is used for P-256 keys and PKCS#8 DER encoding. Package names and APIs must be verified at install time.

**Installed so far (M0–M3, verified 2026-09-24):** pnpm 10, `@hpke/core` 1.9 (includes `DhkemX25519HkdfSha256` and `DhkemP256HkdfSha256`, so no separate KEM module is needed; `createSenderContext({recipientPublicKey, info, senderKey?, ekm?})`, `context.export(ctx, L)`), `jose` 6.2 (`CompactEncrypt` / `compactDecrypt` with `alg: "dir"`), `fflate` 0.8 (`zipSync` / `unzipSync`), `@simplewebauthn/server` 14.0 (`verifyAuthenticationResponse` takes `credential: {id, publicKey, counter}`; CBOR/authData helpers under `@simplewebauthn/server/helpers`), `express` 5.2 (async handler rejections reach the error middleware), `tsx` 4 (runs the TS scripts), `typescript` 6.0.3 (pinned below 6.1 because `typescript-eslint` 8.70 supports only `<6.1`), `zod` 4.6 (`z.looseObject`, `z.int`), `vitest` 4.1 (vitest 5 drops Node 20), `eslint` 9 + `typescript-eslint` 8.70, `@types/node` 22. `@peculiar/x509` 2.1 (test CA for GAP-19; needs `reflect-metadata` imported first), `reflect-metadata` 0.2. `tsconfig` includes the `DOM` lib only for the WebCrypto global types (`CryptoKey`, `CryptoKeyPair`, `JsonWebKey`) that `@hpke/core`'s typings use. Development machine runs Node 23.6, which is not an LTS release and is outside vitest's declared engine range; tests pass on it, but Node 22 or 24 LTS is recommended.

**Commands:** `pnpm install`, then `pnpm check` (typecheck + lint + tests), `pnpm test`, `pnpm lint`, `pnpm typecheck`; **`pnpm walkthrough [--compare] [--mode indirect|direct]`** (the whole story step by step, optionally for both profiles); **`pnpm dashboard`** (web page at http://127.0.0.1:4000, runs both profiles side by side and lists every flag with its GAP; `DASHBOARD_PORT` to change); `pnpm demo:baseline` (register + sign in at the demo RP, printed step by step); `pnpm demo:e2e [--mode indirect|direct]` (register at the RP with Provider A, migrate, sign in with Provider B, and show that A's copy still works); `pnpm demo:migrate [--mode indirect|direct]` (Provider A → Provider B through a real response mode; indirect-mode files are kept in `out/indirect/`); `pnpm demo:exchange` (prints the Export Request, the negotiation, the Export Response, what is visible in the archive without a key, and the decrypted CXF); `pnpm rp` (demo RP alone on 127.0.0.1:3000, `RP_PORT` to change). Profile: `--profile spec-minimal|hardened` or `CXP_PROFILE` (default `spec-minimal`).

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
| GAP-05 | CXP §3.2 `importer` and §3.3 `exporter` RP IDs are self-asserted and unauthenticated | Display only; no verification | 128-bit key/request fingerprint (RFC 7638 thumbprint; SHA-256 of the RFC 8785 canonical request) compared by the user on both sides. *(Changed from a short numeric SAS: in `indirect` mode the request file is seen before substitution, so a short code could be searched for offline; short codes are only safe with a hash commitment, as in ZRTP, RFC 6189, which a one-shot file cannot provide.)* | TBD |
| GAP-06 | CXP §3.2.1/§3.2.2: the `indirect` Export Request file passes through the filesystem with no integrity protection | Load the file as-is | GAP-05 SAS confirmation of the importer public key before export | TBD |
| GAP-07 | CXP §3.4/§3.5.1: the mapping from HPKE to JWE and the placement of the encapsulated key `enc` are unspecified. §3.4 says each file is "separately encrypted using **the key** defined by the selected HPKE Parameters" | One HPKE context (`info` empty, GAP-01). **One** payload key = HPKE secret export (RFC 9180 §5.3, exporter context `"CXP payload key"`), used as the CEK of every file: JWE compact, `alg:"dir"`, `enc` = `A128GCM` for AEAD 0x0001, `A256GCM` for 0x0002 and export-only 0xFFFF (ChaCha20-Poly1305 0x0003 unsupported: no registered JOSE `enc`); random IV, no extra AAD. `enc` is carried as a JWK (RFC 7518 §6.2 / RFC 8037) in `ExportResponse.hpke.key`. *(Corrected from the seed "files sealed in sequence": sequential sealing makes the nonce depend on file order, which is an incidental mitigation, not the most permissive choice.)* | Per-file content keys derived via the HPKE secret export (RFC 9180 §5.3, label = file path); JWE `alg:"dir"`, `enc:"A256GCM"` (RFC 7516) | TBD |
| GAP-08 | CXP §3.4 references an "anonymous identifier in the export request" that does not exist in the §3.2 CDDL | File names derived from CXF entity IDs | Random 128-bit file names; mapping held only inside the encrypted `index.jwe` | TBD |
| GAP-09 | CXP §3.4: no AAD requirement per file, so files could be swapped or reordered | No AAD | AAD = file path ‖ request digest | TBD |
| GAP-10 | CXP §3.4 references a zip archive layout "as defined in [CXF]", but CXF PS 2026 defines no archive, and nothing says what `index.jwe` and `documents/*.jwe` contain | Zip as illustrated in CXP §3.4. `CXP-Export/index.jwe` holds JSON `{header, documents}`: `header` is the CXF Header with every Account's `items` emptied, and `documents` lists `{path, account}`. Each `CXP-Export/documents/<name>.jwe` holds one CXF Item. Unlisted documents are ignored; listed but missing documents are skipped (partial import) | Same layout plus a signed or AEAD-bound manifest | TBD |
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
| GAP-25 | CXF §3.3.12 Passkey has no member for the WebAuthn backup flags (BE/BS) or the AAGUID, and WebAuthn L3 §6.1.3 fixes BE for a credential's lifetime. So the importer cannot know or preserve the source value, and the RP sees whatever the destination authenticator reports | Both authenticators report BE=1, BS=1 (every passkey is exportable, so it is "multi-device"); nothing is carried in CXF | Same (no conformant CXF field exists). Recommend a CXF member for BE/BS. Relevant to whether an RP can notice a migration (A-10) | TBD |
| GAP-26 | CXP §3.2/§3.5.1 CDDL contradicts the prose: `credentialTypes` and `knownExtensions` are `[+ ...]` (non-empty), yet the prose defines what an *empty* list means; `HPKEParameters.key` is required in CDDL, yet the prose says it is "only present" without a pre-shared key. CXP also never says whether unknown members are ignored | Follow the prose (empty lists accepted with their stated meaning; `key` optional in the schema, always sent in `base`/`auth`); ignore and keep unknown members, as CXF §3.1.1 does | Same (no profile difference) | — |
| GAP-27 | CXP §3.5.3 `deflate` does not say what is compressed (zip entries, JWE plaintext via RFC 7516 `zip:"DEF"`, or the whole payload), while §3.4 requires the zip format whatever algorithm is selected | Zip entries stored with DEFLATE (zip method 8, RFC 1951); JWE plaintexts are not compressed | Same (no profile difference). Size limits on inflation are GAP-12 | TBD |
| GAP-28 | CXP §3.3: the response `hpke` "MUST correspond to an entry in `hpke`", but the two cannot be equal (the request `key` is the importer's public key, the response `key` is the exporter's `enc`), and "correspond" is undefined | Correspond = equal `mode`, `kem`, `kdf`, `aead`. The importer uses the private key of the first request entry with those values | Same (no profile difference) | — |
| GAP-29 | CXP §2 step 2 and §2.1 mention approval by the end-user and/or an authorizing party only descriptively. No clause requires consent, defines what the user is shown, requires re-authentication, or binds the approval to the request's key. The only related normative text is §3.2's SHOULD that the user validate `credentialTypes` | Starting the export (supplying the request) counts as approval: no confirmation screen, no re-authentication, nothing bound to the request | Before export, show the claimed importer, the SAS over the importer key (GAP-05), the credential types and the item count; require user verification; bind the approval to SHA-256 of the exact request (OWASP Transaction Authorization Cheat Sheet, "what you see is what you sign"; NIST SP 800-63B re-authentication) | TBD |
| GAP-30 | CXP/CXF say nothing about importing a credential whose `credentialId` (or `rpId` + `userHandle`) already exists in the importer's vault | Imported credential replaces the existing one (last import wins, as WebAuthn §6.3.2 does for a new credential with the same RP and user) | Keep the existing credential, report the conflict, and require explicit user confirmation to replace it (fail-safe defaults, Saltzer & Schroeder 1975) | TBD |
| GAP-31 | CXP §3.2.1/§3.2.2 `indirect`: request and response files go through the filesystem with no guidance on location, permissions, or removal after import | Files written with default permissions (umask) and left in place after import | Files created `0600`; the response file is deleted after a successful import (best effort: SSD and backup remanence remain), and the request file once answered (OWASP File Storage / Cryptographic Storage guidance) | TBD |

The Threat link column is filled in once the PASTA/STRIDE threat model assigns T-xx identifiers.

---

## 7. Attack Scenarios (planned)

Each scenario is a vitest test executed under both profiles. The expected outcome is **succeeds** under `spec-minimal` and **fails (detected or rejected)** under `hardened`. The only exceptions are spec-mandated gaps (GAP-16, GAP-17), which are expected to succeed under both profiles.

| ID | Scenario | Gaps exercised | Expected (min / hard) | Result |
|---|---|---|---|---|
| A-01 | Importer public-key substitution in an `indirect` Export Request file | 05, 06 | succeeds / fails | — |
| A-02 | Active MITM on a `direct` channel, relaying a substituted importer key | 05, 19 | succeeds / fails | — |
| A-03 | Replay of a captured ExportResponse to the importer (including a response file left on disk) | 01, 11, 31 | succeeds / fails | — |
| A-04 | HPKE suite / archive negotiation tampering | 02, 03 | succeeds / fails | — |
| A-05 | Protocol version downgrade (needs a hypothetical request `version: 1`; see GAP-24) | 04, 24 | succeeds / fails | — |
| A-06 | Swapping or reordering files inside the archive | 07, 09 | succeeds / fails | — |
| A-07 | Credential injection by an unauthenticated exporter (including replacing a credential the victim already holds) | 14, 30 | succeeds / fails | — |
| A-08 | Decompression bomb via `deflate` or `largeBlob` | 12 | succeeds / fails | — |
| A-09 | Post-import memory residue of PKCS#8 keys (heap snapshot) | 13 | succeeds / reduced | — |
| A-10 | Clone use of source and migrated credential goes undetected by the RP | 15, 17 | succeeds / succeeds | — |
| A-11 | PRF seed reuse across two importers | 16 | succeeds / succeeds | — |
| A-12 | Metadata observable to a passive observer of the Export Response (Item IDs as file names; per-document sizes) | 08, 18 | succeeds / reduced | — |
| A-13 | Consent phishing: the victim approves an attacker-crafted Export Request (attacker key, plausible `importer` name) | 05, 06, 29 | succeeds / fails | — |

Results are written to `reports/attack-matrix.{json,md}` by `pnpm attack:all`.

---

## 8. Milestone Board

Status values: `todo` / `in-progress` / `done` / `blocked`.

| ID | Milestone | Exit criteria | Status |
|---|---|---|---|
| M0 | Scaffold | TS strict, vitest, lint, `docs/specs/` present, `CLAUDE.md` created, policy/profile skeleton | done |
| M1 | CXF model | zod schemas for Header, Account, Collection, Item, Passkey, Fido2Extensions; round-trip tests against CXF Appendix A example | done |
| M2 | Authenticator + RP | Software authenticator registers and authenticates at the demo RP (baseline, no migration) | done |
| M3 | CXP crypto core | HPKE wrapper, ExportRequest/Response builders + schemas, JWE packaging, archive; RFC 9180 test vectors pass | done |
| M4 | Exporter / Importer | `direct` and `indirect` modes working under both profiles | done |
| M5 | End-to-end migration | Provider A → B migration; migrated passkey authenticates at the RP; counter = 0 verified | done |
| M6 | Adversary harness | A-01 to A-12 implemented; attack matrix report generated | todo |
| M7 | Hardened profile | All hardened policy flags implemented; matrix shows the expected split | in-progress |
| M8 | Demo interface | CLI walkthrough plus a minimal local web dashboard for supervisor demonstration | done |
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
| 2026-09-24 | **M2:** added `src/provider/`: a minimal CBOR encoder (RFC 8949 Appendix A vectors, cross-decoded with SimpleWebAuthn), an in-memory `Vault` whose records map field-for-field onto a CXF Passkey, and `SoftwareAuthenticator`, a combined WebAuthn client and authenticator (`create`/`get`, ES256, `none` attestation, counter 0, BE/BS = 1). Added `src/rp/`: `DemoRelyingParty` (SimpleWebAuthn 14), an Express 5 server on loopback and `RpHttpClient`. Added `src/cli/demo-baseline.ts`. Tests cover authData layout and flags, that the COSE key matches the vault key, signature validity, client rejections (`SecurityError`, `NotSupportedError`, `InvalidStateError`, `NotAllowedError`), and HTTP ceremonies: registration, username-first and discoverable login, counter staying 0, replay, wrong origin, tampered signature, unknown credential and forged `userHandle`. 122 tests pass. **Findings:** CXF has no BE/BS/AAGUID member (GAP-25). SimpleWebAuthn skips the counter comparison when both counters are 0, confirming the A-10 precondition at the library level. The WebAuthn `userHandle` is not covered by the assertion signature, so the RP must check it. There are no profile differences in M2: the RP and authenticator are WebAuthn fixtures. | M2 | GAP-25 (new, no flag) |
| 2026-09-24 | **M3:** added `src/crypto/`: `hpke.ts` (a wrapper over `@hpke/core`: X25519 and P-256 KEMs, HKDF-SHA256, AES-128/256-GCM and export-only; base and auth modes; secret export; KEM public key ↔ JWK per RFC 8037 / RFC 7518), `jwe.ts` (compact JWE, `dir` + AES-GCM) and `archive.ts` (zip, DEFLATE entries). Added `src/cxp/`: loose zod schemas for ExportRequest and ExportResponse, `createExportRequest` (one key pair per KEM, kept in an `ImporterKeyring`), exporter negotiation, `sealPayload` / `openPayload` (GAP-07/08/10 layout) and `createExportResponse` / `openExportResponse`. **RFC 9180 vectors pass**: 12 CFRG vectors (base and auth × X25519/P-256 × AES-128-GCM/AES-256-GCM/export-only), checking keys, `enc`, sealing and opening up to sequence 256, and exports. The Appendix A document round-trips through request → response → decrypt under both profiles with three suites. Tests also cover wrong importer key, tampered ciphertext, non-corresponding `hpke`, archive not offered, and nothing mutually supported. Characterisation tests pin the spec-minimal attack preconditions: Item IDs visible as file names (A-12), two documents swappable undetected (A-06), a removed document silently skipped, and the same response importable twice (A-03). Added `pnpm demo:exchange`. 189 tests pass. **Decisions:** the seed GAP-07 spec-minimal choice was corrected from "files sealed in sequence" to "one exported key for all files", because sequential sealing binds file order and so is an incidental mitigation. GAP-10's layout was made concrete. **Findings:** the CXP CDDL contradicts its prose (GAP-26); `deflate` has no defined target (GAP-27); "corresponds" is undefined (GAP-28). The demo also shows that document **sizes** are visible without a key (an SSH-key Item is plainly the largest), extending A-12, and that CXF `exporterRpId` and CXP `exporter` can differ unchecked (GAP-22). Hardened CXP behaviour (GAP-01 to GAP-14 flags) is still unimplemented, as planned for M7: until then the hardened profile runs the spec-minimal CXP path, except GAP-20 validation. | M3 | GAP-07 (spec-minimal corrected), GAP-10 (layout specified), GAP-26, GAP-27, GAP-28 (new, no flag) |
| 2026-09-25 | **Consent analysis:** CXP mentions approval by the user or an authorizing party only descriptively (§2 step 2, §2.1). The only normative user check is §3.2's SHOULD on validating `credentialTypes`. Added GAP-29 and attack A-13 (consent phishing). **M4:** vault records gained a random, stable `itemId` (CXF §1.3), so file names cannot be linked to credential IDs by an RP. Added `ExportingProvider` (vault → CXF, including the counter-exclusion MUST, the `credentialTypes` rules with the empty-list MUST, and the `knownExtensions` MUST; `respond`; `exportToFile` for indirect mode) and `ImportingProvider` (`createRequest`, `writeRequestFile`, `importResponse[File]`; counter set to 0 (MUST); non-passkeys and non-P-256 keys skipped and reported). Added `direct.ts` (exporter service on 127.0.0.1, JSON over HTTP; `indirect` and `self` requests over this transport and malformed input get HTTP 400, per GAP-23) and `pnpm demo:migrate`. Tests cover both modes under both profiles, checking field-for-field equality, the same public key, counter 0, and a Provider B signature that verifies under Provider A's key; plus filters, error paths, and spec-minimal characterisation (re-import replaces credentials; files left on disk). 211 tests pass. **Findings:** a response carries nothing linking it to its request, so the importer must guess (the latest pending request), which is part of GAP-01. The `indirect` files are written world-readable (`0644`) and never removed (GAP-31). An imported credential silently replaces an existing one (GAP-30). Provider A keeps its copy (GAP-15). | M4 | GAP-29, GAP-30, GAP-31 (new, flags `requireExportConsent`, `rejectConflictingImport`, `secureExportFiles`); A-13 added; A-03, A-07 extended |
| 2026-09-25 | **M5:** added `src/scenario/world.ts` (`createWorld(policy)`: demo RP + Provider A + Provider B; `migrate(world, mode)`) and `pnpm demo:e2e`. The end-to-end tests cover both profiles and both modes: Alice registers at the RP with Provider A; after the CXP migration, Provider B signs in username-first and discoverably with the **same** credential. The RP recorded a single registration, the counter is 0 in every assertion from B and at the RP (CXF §3.3.12 MUST), and Provider A's original copy still signs in. 224 tests pass. **Findings (A-10 evidence):** the source and migrated assertions for the same challenge have **byte-identical** authenticator data (rpIdHash, flags UP/UV/BE/BS, counter 0) and identical clientDataJSON; only the randomised ECDSA signature differs, so the RP has no protocol-level signal of which provider signed. Two things keep it that way: CXF forces the counter to 0 (GAP-17), and both authenticators report the same BE/BS (GAP-25). An importer that reported different BE/BS would be the only visible difference, but SimpleWebAuthn 14's `WebAuthnCredential` (`id`, `publicKey`, `counter`, `transports`) has no backup-eligibility field, so an RP built on it cannot compare BE with the registered value, and the demo RP does not. | M5 | — (none new; GAP-15, GAP-17, GAP-25 evidence) |
| 2026-09-25 | **M6 not implemented by the agent:** the agent's attempts to write the attack harness were stopped by a safety classifier (twice), and it will not write the scenarios. The researcher will write M6. `src/adversary/{types,catalog,registry}.ts` hold a scenario contract, the README §7 catalog and an empty registry, with no attack logic. **M7 (in progress):** the hardened side of every flag is implemented. The pieces: `src/crypto/jcs.ts` (RFC 8785, checked against the RFC example); `src/cxp/binding.ts` (request digest bound into HPKE `info`, 128-bit fingerprints); a policy-aware request, negotiation, payload and response (GAP-01/02/03/04/07/08/09/10/12/13/14/21/22); an exporter consent prompt with the request fingerprint (GAP-05/06/29) and a static auth-mode key (GAP-14); importer single-use keys, conflict refusal, a bounded `largeBlob` check, key zeroing and file cleanup (GAP-11/30/12/13/31); `0600` files (GAP-31); direct mode over TLS 1.3 with a per-run test CA (`src/crypto/test-ca.ts`, GAP-19); `world.ts` with a simulated user who approves only when the fingerprints the two providers display match. The existing M3–M5 suites now run the full hardened profile (auth mode, MTI suite, TLS, prompts), and the end-to-end migration + RP sign-in passes under both profiles in both modes. 225 tests pass. **Remaining for M7:** a per-flag verification suite (the agent's attempt was stopped by the safety classifier; to be written by the researcher alongside M6) and the attack-matrix split, which depends on M6. **Findings:** `fflate.unzipSync` allocates from each entry's *declared* size and silently truncates the rest, so memory in spec-minimal is whatever the archive claims (GAP-12); capping declared sizes bounds it, and truncation then fails the JWE check. GAP-05's hardened choice changed from a short SAS to a 128-bit fingerprint (see the register). The hardened exporter now negotiates before prompting, so the user is never asked about an export that cannot be served. Hardened is deliberately not interoperable with spec-minimal peers (auth mode, `challenge`, `senderKey` members). | M6 (researcher), M7 | GAP-05 hardened choice changed |
| 2026-09-26 | **M8:** added `src/scenario/walkthrough.ts` (`runWalkthrough(policy, mode)`: RP registration with Provider A → Export Request → export (with consent under hardened) → Export Response → import → sign-in with Provider B → Provider A's copy still signs in; each step returns facts and the GAPs it illustrates, plus the prompts the simulated user saw). Added `pnpm walkthrough [--compare]` and `pnpm dashboard`: Express on 127.0.0.1, a self-contained page (no external assets, CSP `default-src 'self'`, text inserted with `textContent`), `GET /api/policy`, and `POST /api/run` (input validated; runs serialised). Tests: the walkthrough completes for both profiles × both modes, and only hardened prompts the user; the dashboard serves on loopback with CSP, lists every flag, and rejects bad input. 232 tests pass. The side-by-side run makes the profile differences visible: offered suites and HPKE mode, the challenge, file modes `0644`/`0600`, approval and fingerprint prompts, and files left on disk versus removed. The spec-mandated residual risk (Provider A's copy still signs in, GAP-15/17/25) shows under both profiles. | M8 | — |