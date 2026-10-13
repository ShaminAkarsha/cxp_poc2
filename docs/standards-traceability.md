# Standards traceability: how the PoC fills CXP/CXF gaps

<!-- Generated from docs/standards-traceability.json by `pnpm docs:traceability`. Do not edit by hand. -->

Last updated 2026-10-13. Specifications: **CXP**: Credential Exchange Protocol, Working Draft 2024-10-03 (cxp-v1.0-wd-20241003), docs/specs/Credential_Exchange_Protocol.pdf; **CXF**: Credential Exchange Format, Proposed Standard with errata 2026-03-09 (cxf-v1.0-ps-errata-20260309), docs/specs/Credential_Exchange_Format.pdf.

A citation marked *(section to verify)* names the right document, but the exact section has not been confirmed; check it before citing.

## Summary

- Entries: **45** (17 completion choices, 28 hardening entries).
- Hardening status: 21 closed by a flag, 2 closed through other flags, 5 not closed in the PoC.
- Citations: **89**, of which 29 are marked *section to verify*. Entries with no external standard: 8; entries with a design decision recorded: 25.

| Standard type | Citations | Entries citing it |
|---|---|---|
| IETF RFC | 62 | 26 |
| NIST | 11 | 11 |
| FIDO | 2 | 2 |
| W3C | 6 | 4 |
| OWASP guidance | 3 | 3 |
| Industry specification | 4 | 4 |
| Academic literature | 1 | 1 |
| none | - | 8 |

## 1. Completion choices

Points where CXP/CXF is silent, ambiguous or dangling and the PoC had to choose something to work at all. The choice is the same in both profiles.

| ID | Gap | Flag | Specification clause | Choice / control | Standard |
|---|---|---|---|---|---|
| IMPL-01 | - | - | CXP §3.5.1 (kem, kdf, aead) | X25519 or P-256 KEM, HKDF-SHA256, AES-GCM; @hpke/core checked against RFC 9180 vectors | RFC 9180 §7.1; RFC 9180 §7.2; RFC 9180 §7.3; RFC 9180 Appendix A |
| IMPL-02 | - | - | CXP §3.5.1 (key) | OKP JWK for X25519, EC JWK for P-256; strict decoding | RFC 7517 §4; RFC 8037 §2; RFC 7518 §6.2.1; RFC 9180 §7.1.1 (section to verify) |
| IMPL-03 | - | - | CXP §3.4 | Compact JWE, alg dir, enc A128GCM/A256GCM, algorithm allow-list on decrypt | RFC 7516 §7.1; RFC 7518 §4.5; RFC 7518 §5.3; RFC 7516 §4.1.3; RFC 8725 §3.1 |
| IMPL-04 | - | - | CXF §2.1 (b64url) | Emit unpadded canonical base64url | RFC 4648 §5; RFC 7515 §2 |
| IMPL-05 | - | - | CXF §2.1, §3.1.1 | Ignore-but-preserve unknown members; JSON-value round trip | RFC 8259 §4; RFC 8610 Appendix E |
| IMPL-06 | - | - | CXF §3.1 (timestamp), §3.2.2, §3.2.3 | uint64 fields limited to 0..2^53-1 | RFC 8259 §6; RFC 7493 §2.2 |
| IMPL-07 | - | - | CXP §3.2.1, §3.3 | UTF-8 JSON files with fixed names in a caller-chosen directory | RFC 8259 §8.1 |
| IMPL-08 | - | - | CXP §3.2.2 (direct) | HTTP POST /cxp/export on loopback, JSON bodies, 400 on error | RFC 9110 §9.3.3; RFC 9110 §15.5.1; RFC 8259 §11 |
| IMPL-09 | - | - | CXF §3.3.12 (key) | ES256 credentials, none attestation, canonical CBOR; importer accepts P-256 PKCS#8 | W3C WebAuthn Level 3 §8.7; W3C WebAuthn Level 3 §6.3.3; RFC 9053 §2.1; RFC 9053 (section to verify); RFC 8949 Appendix A; FIDO CTAP 2.1 (section to verify); RFC 5958 (section to verify) |
| IMPL-10 | - | - | CXF §1.3 (Identifier) | Random 128-bit IDs, fixed per record, not derived from credential IDs | Design decision |
| IMPL-11 | - | - | CXF §3.3 (Credential.type) | Other credential types kept opaque, not imported, reported | Design decision |
| IMPL-12 | - | - | Not CXP/CXF: W3C WebAuthn Level 3 RP ID validation | RP ID localhost; simplified client RP ID check | W3C WebAuthn Level 3 §5.1.3; W3C Secure Contexts (section to verify) |
| GAP-23 | GAP-23 | - | CXP §3.2.2 (direct) | Read 'indirect' as 'direct' | Design decision |
| GAP-24 | GAP-24 | - | CXP §3.2 (version) | version 0 (CDDL .default) | RFC 8610 (section to verify) |
| GAP-26 | GAP-26 | - | CXP §3.2, §3.5.1 | Prose wins over CDDL | RFC 8610 (section to verify) |
| GAP-27 | GAP-27 | - | CXP §3.5.3, §3.4 | DEFLATE on zip entries; no JWE compression | RFC 1951; PKWARE APPNOTE.TXT (.ZIP File Format Specification) (section to verify) |
| GAP-28 | GAP-28 | - | CXP §3.3 (hpke) | Equal mode/kem/kdf/aead | Design decision |

### IMPL-01: HPKE suites and implementation

- **Specification clause:** CXP §3.5.1 (kem, kdf, aead)
- **Specification text:** "The value SHOULD be from the HPKE KEM Identifiers IANA table"
- **What the specification leaves open:** Suite identifiers come from the HPKE registries; CXP names no suite, and §5 (mandatory to implement) is empty (see GAP-02).
- **Choice (both profiles):** Importer offers DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/AES-256-GCM, then DHKEM(P-256, HKDF-SHA256)/HKDF-SHA256/AES-128-GCM, in base mode. The exporter supports KEM 0x0010/0x0020, KDF 0x0001 and AEAD 0x0001/0x0002/0xFFFF; ChaCha20-Poly1305 (0x0003) is not offered because it has no registered JOSE enc. Implementation: @hpke/core, validated against the RFC 9180 test vectors.
- **Standards relied on:**
  - RFC 9180 §7.1 [IETF RFC]: KEM identifiers 0x0010, 0x0020
  - RFC 9180 §7.2 [IETF RFC]: KDF identifier 0x0001
  - RFC 9180 §7.3 [IETF RFC]: AEAD identifiers 0x0001, 0x0002, 0xFFFF
  - RFC 9180 Appendix A [IETF RFC]: test vectors (CFRG test-vectors.json)
- **Design decision:** Preference order (MTI suite first, P-256 second) is a PoC choice: P-256 is offered for interoperability with WebCrypto-only stacks.
- **Code:** `src/crypto/hpke.ts:23`, `src/crypto/hpke.ts:68`, `src/cxp/request.ts:11`, `src/cxp/negotiate.ts:52`
- **Tests:** `test/crypto/rfc9180-vectors.test.ts`, `test/crypto/primitives.test.ts`, `test/cxp/messages.test.ts`

### IMPL-02: JWK format of the importer key and of enc

- **Specification clause:** CXP §3.5.1 (key)
- **Specification text:** "It is a JSON Web Key representing that provider's key necessary for the other provider's generation of the AEAD key."
- **What the specification leaves open:** The key is a JWK; the key type and parameters per KEM are not specified.
- **Choice (both profiles):** The HPKE serialised public key (also the format of enc) is carried as an OKP JWK {kty OKP, crv X25519, x} for X25519 and an EC JWK {kty EC, crv P-256, x, y} for P-256 (from the uncompressed point). On input the JWK must match the KEM, coordinates must be canonical base64url of the exact length.
- **Standards relied on:**
  - RFC 7517 §4 [IETF RFC]: JWK format
  - RFC 8037 §2 [IETF RFC]: OKP key type for X25519
  - RFC 7518 §6.2.1 [IETF RFC]: EC public key parameters x, y
  - RFC 9180 §7.1.1 (section to verify) [IETF RFC]: SerializePublicKey / DeserializePublicKey encodings
- **Code:** `src/crypto/hpke.ts:108`, `src/crypto/hpke.ts:122`
- **Tests:** `test/crypto/primitives.test.ts`

### IMPL-03: JWE serialisation and header fields

- **Specification clause:** CXP §3.4
- **Specification text:** "All files are stored as JSON Web Encryption files."
- **What the specification leaves open:** Files are JWE; serialisation, alg, enc and header members are not specified (the HPKE-to-JWE mapping is GAP-07).
- **Choice (both profiles):** Compact serialisation; protected header {alg: dir, enc: A128GCM | A256GCM} only (hardened adds cxp-path and cxp-req, GAP-09); no zip header. Decryption accepts only alg dir and the expected enc.
- **Standards relied on:**
  - RFC 7516 §7.1 [IETF RFC]: compact serialisation
  - RFC 7518 §4.5 [IETF RFC]: alg dir
  - RFC 7518 §5.3 [IETF RFC]: AES-GCM content encryption
  - RFC 7516 §4.1.3 [IETF RFC]: zip header (deliberately not used, see GAP-27)
  - RFC 8725 §3.1 [IETF RFC]: algorithm verification (allow-list on decrypt)
- **Code:** `src/crypto/jwe.ts:21`, `src/crypto/jwe.ts:37`, `src/crypto/jwe.ts:47`
- **Tests:** `test/crypto/primitives.test.ts`

### IMPL-04: base64url encoding of CXF b64url values

- **Specification clause:** CXF §2.1 (b64url)
- **Specification text:** "The b64url CDDL type is a [JSON] string which contains a [RFC4648] compliant URL-safe Base 64 encoded bytes."
- **What the specification leaves open:** RFC 4648 URL-safe base64; padding and canonical form are not specified (acceptance rules are GAP-20).
- **Choice (both profiles):** Every b64url value the PoC writes is unpadded and canonical, as in the CXF Appendix A example.
- **Standards relied on:**
  - RFC 4648 §5 [IETF RFC]: base64url alphabet
  - RFC 7515 §2 [IETF RFC]: base64url with trailing '=' omitted (JOSE convention)
- **Code:** `src/cxf/b64url.ts:29`, `src/cxf/b64url.ts:14`
- **Tests:** `test/cxf/b64url.test.ts`

### IMPL-05: JSON encoding and unknown members

- **Specification clause:** CXF §2.1, §3.1.1
- **Specification text:** "Any participant using this format MUST ignore unknown fields or enumeration values."
- **What the specification leaves open:** CXF MUST support JSON encoding and MUST ignore unknown fields; whether ignored members are preserved is not stated.
- **Choice (both profiles):** Loose schemas: unknown members are ignored for processing but preserved, so a parsed document re-serialises to the same JSON value; round-trips are compared as JSON values, not bytes. Empty optional arrays are omitted on output (CXF §2.1.2 MUST).
- **Standards relied on:**
  - RFC 8259 §4 [IETF RFC]: object member order is not significant
  - RFC 8610 Appendix E [IETF RFC]: JSON-compatible CDDL prelude, as CXF §2.1 cites
- **Design decision:** Preserving unknown members keeps the CXF Appendix A round trip lossless.
- **Code:** `src/cxf/schema.ts:35`, `src/cxf/serialize.ts:42`, `src/cxp/schema.ts:24`
- **Tests:** `test/cxf/appendix-a.test.ts`, `test/cxf/validation.test.ts`

### IMPL-06: Integer range of uint .size 8

- **Specification clause:** CXF §3.1 (timestamp), §3.2.2, §3.2.3
- **Specification text:** "timestamp: uint .size 8,"
- **What the specification leaves open:** 64-bit unsigned integers in a JSON encoding; JSON number precision is not addressed.
- **Choice (both profiles):** Integers are accepted in 0..2^53-1, the range JSON numbers represent exactly in JavaScript.
- **Standards relied on:**
  - RFC 8259 §6 [IETF RFC]: number interoperability limits
  - RFC 7493 §2.2 [IETF RFC]: I-JSON: numbers beyond IEEE 754 double precision
- **Code:** `src/cxf/schema.ts:29`
- **Tests:** `test/cxf/validation.test.ts`

### IMPL-07: Request and response file format, naming and location

- **Specification clause:** CXP §3.2.1, §3.3
- **Specification text:** "the Export Request SHALL be stored as a JSON-encoded document to be supplied to the Exporter by the Credential Owner."
- **What the specification leaves open:** Both documents are JSON; file names, location and encoding details are not specified (permissions and removal are GAP-31).
- **Choice (both profiles):** UTF-8 JSON files named cxp-export-request.json and cxp-export-response-<UNIX seconds>.json in a caller-chosen directory (OS temporary directory, or out/indirect/ in the demo).
- **Standards relied on:**
  - RFC 8259 §8.1 [IETF RFC]: UTF-8 for JSON text exchanged between systems
- **Design decision:** File names and location are not standardised anywhere; fixed descriptive names make the files easy to find in experiments.
- **Code:** `src/provider/importer.ts:55`, `src/provider/importer.ts:114`, `src/provider/exporter.ts:69`, `src/provider/exporter.ts:232`
- **Tests:** `test/provider/migration-modes.test.ts`

### IMPL-08: Direct-mode transport

- **Specification clause:** CXP §3.2.2 (direct)
- **Specification text:** "In the case that a platform or Exporter provides an interface or transport over which the exchange ceremony can take place"
- **What the specification leaves open:** Direct mode uses a transport the platform or exporter provides; no transport is defined (its security is GAP-19).
- **Choice (both profiles):** JSON over HTTP: POST /cxp/export on 127.0.0.1, request body up to 256 KiB, response 200 with the Export Response or 400 with {error}. Requests whose mode is not direct are refused on this transport (GAP-23). Plain HTTP in spec-minimal, HTTPS in hardened (GAP-19).
- **Standards relied on:**
  - RFC 9110 §9.3.3 [IETF RFC]: POST method
  - RFC 9110 §15.5.1 [IETF RFC]: 400 Bad Request
  - RFC 8259 §11 [IETF RFC]: application/json media type
- **Design decision:** The endpoint path and size limit are PoC choices; the transport is loopback only (README §9 rule 6).
- **Code:** `src/provider/direct.ts:21`, `src/provider/direct.ts:30`, `src/provider/direct.ts:32`
- **Tests:** `test/provider/migration-modes.test.ts`

### IMPL-09: Passkey credential format of the software authenticator

- **Specification clause:** CXF §3.3.12 (key)
- **Specification text:** "The value MUST be PKCS#8 ASN.1 DER formatted byte string which is then Base64url encoded."
- **What the specification leaves open:** The key is PKCS#8 DER; the algorithm is whatever the original authenticator used.
- **Choice (both profiles):** Both providers' software authenticators create ES256 (P-256) credentials with none attestation, encode COSE_Key and the attestation object as CTAP2-canonical CBOR, and sign authenticatorData || SHA-256(clientDataJSON). The importer stores only P-256 PKCS#8 keys (others are skipped and reported).
- **Standards relied on:**
  - W3C WebAuthn Level 3 §8.7 [W3C]: none attestation statement format
  - W3C WebAuthn Level 3 §6.3.3 [W3C]: authenticatorGetAssertion signature input
  - RFC 9053 §2.1 [IETF RFC]: ES256 (ECDSA with SHA-256)
  - RFC 9053 (section to verify) [IETF RFC]: EC2 COSE_Key parameters (crv, x, y)
  - RFC 8949 Appendix A [IETF RFC]: CBOR encoder test vectors
  - FIDO CTAP 2.1 (section to verify) [FIDO]: CTAP2 canonical CBOR encoding (map key order)
  - RFC 5958 (section to verify) [IETF RFC]: PKCS#8 OneAsymmetricKey structure
- **Design decision:** ES256 is the algorithm every WebAuthn RP accepts; a single algorithm keeps the authenticator small.
- **Code:** `src/provider/authenticator.ts:26`, `src/provider/authenticator.ts:75`, `src/provider/authenticator.ts:194`, `src/provider/authenticator.ts:239`, `src/provider/cbor.ts:65`, `src/provider/importer.ts:210`
- **Tests:** `test/provider/authenticator.test.ts`, `test/provider/cbor.test.ts`, `test/rp/baseline.test.ts`

### IMPL-10: Generation of CXF entity identifiers

- **Specification clause:** CXF §1.3 (Identifier)
- **Specification text:** "An identifier for a given entity SHOULD be the same across different creations of a CXF document."
- **What the specification leaves open:** IDs MUST be unique per Account and at most 64 bytes, SHOULD be stable and SHOULD NOT contain personal information; how to generate them is not specified.
- **Choice (both profiles):** Account and Item IDs are 128-bit values from the platform CSPRNG, created once per account / vault record and reused in every export. They are not derived from the credential ID, so an RP cannot recognise its own passkey among archive file names.
- **Standards relied on:** none (no external standard applies).
- **Design decision:** No standard governs CXF ID generation; random, stable IDs satisfy the MUST and both SHOULDs.
- **Code:** `src/provider/authenticator.ts:166`, `src/provider/exporter.ts:74`, `src/provider/vault.ts:22`
- **Tests:** `test/provider/migration-modes.test.ts`

### IMPL-11: Non-passkey credentials

- **Specification clause:** CXF §3.3 (Credential.type)
- **Specification text:** "importers MAY attempt to store unknown item types in their own way as a best effort."
- **What the specification leaves open:** Importers may store credential types they do not model.
- **Choice (both profiles):** Non-passkey credentials are parsed as opaque objects (preserved on round trip) but not imported; each is reported as skipped.
- **Standards relied on:** none (no external standard applies).
- **Design decision:** README §5 limits the PoC to passkeys; reporting skipped credentials keeps the behaviour observable.
- **Code:** `src/cxf/schema.ts:96`, `src/provider/importer.ts:163`
- **Tests:** `test/provider/migration-modes.test.ts`

### IMPL-12: Loopback RP ID and origin for WebAuthn

- **Specification clause:** Not CXP/CXF: W3C WebAuthn Level 3 RP ID validation
- **Specification text:** none (silent).
- **What the specification leaves open:** CXP/CXF do not cover the RP; the demo RP must be a valid WebAuthn RP on loopback.
- **Choice (both profiles):** RP ID localhost, origin http://localhost:<port>, server bound to 127.0.0.1. The software client checks that the RP ID equals the origin host or a parent domain and that the origin is https or loopback; the public-suffix check is omitted (loopback only).
- **Standards relied on:**
  - W3C WebAuthn Level 3 §5.1.3 [W3C]: client RP ID validation in create()
  - W3C Secure Contexts (section to verify) [W3C]: localhost treated as potentially trustworthy
- **Code:** `src/provider/authenticator.ts:96`, `src/rp/server.ts:79`
- **Tests:** `test/provider/authenticator.test.ts`, `test/rp/baseline.test.ts`

### GAP-23: Editorial defect in the direct-mode MUST

- **Specification clause:** CXP §3.2.2 (direct)
- **Specification text:** "if indirect is requested, the Exporter MUST return the Export Response over the same transport or return an appropriate error."
- **What the specification leaves open:** The direct-mode paragraph names indirect, which contradicts the indirect-mode MUST to write to the filesystem.
- **Choice (both profiles):** Read as direct: a direct request is answered over the same transport or with an error (HTTP 400).
- **Standards relied on:** none (no external standard applies).
- **Design decision:** The only coherent reading of the paragraph.
- **Code:** `src/provider/direct.ts:37`
- **Tests:** `test/provider/migration-modes.test.ts`

### GAP-24: CXP version value

- **Specification clause:** CXP §3.2 (version)
- **Specification text:** "The version MUST correspond to a published level of the CXP standard."
- **What the specification leaves open:** No level of CXP has been published, so no valid value exists.
- **Choice (both profiles):** version = 0, the CDDL default.
- **Standards relied on:**
  - RFC 8610 (section to verify) [IETF RFC]: .default control operator
- **Design decision:** The CDDL default is the only value the specification itself supplies.
- **Code:** `src/cxp/schema.ts:14`
- **Tests:** `test/cxp/messages.test.ts`, `test/security/a05-version-downgrade.test.ts`

### GAP-26: CDDL contradicts prose

- **Specification clause:** CXP §3.2, §3.5.1
- **Specification text:** "If this member is present but the list is empty, the Exporting Provider MUST send only the Account object without any Collection information."
- **What the specification leaves open:** credentialTypes and knownExtensions are [+ ...] (non-empty) in CDDL, yet the prose defines empty lists; key is required in CDDL but 'only present' without a PSK in prose; unknown members are not addressed.
- **Choice (both profiles):** Follow the prose: empty lists accepted with their stated meaning, key optional in the schema (always sent in base/auth), unknown members ignored and kept.
- **Standards relied on:**
  - RFC 8610 (section to verify) [IETF RFC]: occurrence indicators (+, ?)
- **Design decision:** The prose states behaviour explicitly; the CDDL appears not to have been updated.
- **Code:** `src/cxp/schema.ts:30`, `src/cxp/schema.ts:45`, `src/provider/exporter.ts:122`
- **Tests:** `test/cxp/messages.test.ts`, `test/provider/migration-modes.test.ts`

### GAP-27: What deflate compresses

- **Specification clause:** CXP §3.5.3, §3.4
- **Specification text:** "Archiving through the use of the DEFLATE algorithm defined in [RFC1951]."
- **What the specification leaves open:** Whether DEFLATE applies to zip entries, to JWE plaintext or to the whole payload is not stated.
- **Choice (both profiles):** Zip entries use DEFLATE (compression method 8); JWE plaintexts are not compressed.
- **Standards relied on:**
  - RFC 1951 [IETF RFC]: DEFLATE format (whole document)
  - PKWARE APPNOTE.TXT (.ZIP File Format Specification) (section to verify) [Industry specification]: compression method 8 (deflated)
- **Design decision:** Compressing before encryption can leak plaintext length information; compressing ciphertext is harmless.
- **Code:** `src/crypto/archive.ts:19`, `src/crypto/archive.ts:41`
- **Tests:** `test/crypto/primitives.test.ts`

### GAP-28: Meaning of 'correspond'

- **Specification clause:** CXP §3.3 (hpke)
- **Specification text:** "The value MUST correspond to an entry in hpke."
- **What the specification leaves open:** The response key (enc) can never equal the request key, and 'correspond' is not defined.
- **Choice (both profiles):** Correspond = equal mode, kem, kdf and aead; the importer uses the private key of that request entry.
- **Standards relied on:** none (no external standard applies).
- **Design decision:** The four algorithm fields are the only members both objects can share.
- **Code:** `src/cxp/negotiate.ts:76`, `src/cxp/response.ts:99`
- **Tests:** `test/cxp/messages.test.ts`

## 2. Hardening controls

### 2.1 Closed in `hardened` by a policy flag

| ID | Gap | Flag | Specification clause | Choice / control | Standard |
|---|---|---|---|---|---|
| GAP-01 | GAP-01 | `bindRequestChallenge` | CXP §2 (step 1, 3), §3.2/§3.3 CDDL | Challenge + SHA-256(JCS(request)) bound into HPKE info | RFC 9180 §5.1; RFC 8785 §3.2.3; FIPS 180-4 (section to verify); RFC 8446 §4.4.1 |
| GAP-02 | GAP-02 | `enforceMandatorySuite` | CXP §5 | MTI suite X25519 / HKDF-SHA256 / AES-256-GCM only | RFC 9180 §7.1; RFC 9180 §7.2; RFC 9180 §7.3; RFC 7748; NIST SP 800-38D |
| GAP-03 | GAP-03 | `verifyNegotiatedSelection` | CXP §3.2 (hpke), §3.3 | Exporter must take the importer's first entries | RFC 8446 §4.4.1 |
| GAP-04 | GAP-04 | `rejectVersionDowngrade` | CXP §3.3 (version) | Reject version below the requested one | RFC 8446 §4.1.3 |
| GAP-05 | GAP-05 | `requireSasConfirmation` | CXP §3.2 (importer), §3.3 (exporter) | 128-bit fingerprint comparison by the user | RFC 7638 §3; RFC 8785 §3.2.3; RFC 6189 (section to verify) |
| GAP-06 | GAP-06 | `confirmRequestFileKey` | CXP §3.2.1, §3.2.2 (indirect) | Request-file fingerprint confirmed before export | RFC 8785 §3.2.3; FIPS 180-4 (section to verify) |
| GAP-07 | GAP-07 | `deriveFileKeysViaExport` | CXP §3.4, §3.5.1 | Per-file keys via HPKE secret export (label = path) | RFC 9180 §5.3; RFC 7518 §4.5; RFC 7518 §5.3; NIST SP 800-38D (section to verify) |
| GAP-08 | GAP-08 | `randomizeFileNames` | CXP §3.4 | Random 128-bit file names | RFC 6973 (section to verify) |
| GAP-09 | GAP-09 | `bindFileAad` | CXP §3.4 | Path and request digest in the authenticated JWE header | RFC 7516 §5.1; RFC 5116 (section to verify) |
| GAP-10 | GAP-10 | `authenticateManifest` | CXP §3.4 | SHA-256 manifest inside the encrypted index | PKWARE APPNOTE.TXT (.ZIP File Format Specification) (section to verify); FIPS 180-4 (section to verify) |
| GAP-11 | GAP-11 | `singleUseImporterKey` | CXP §3.2, §3.3 | Importer key discarded after first import | NIST SP 800-57 Part 1 Rev. 5 (section to verify) |
| GAP-12 | GAP-12 | `enforceDecompressionLimits` | CXP §3.5.3, CXF §3.3.12.5 | Entry/total size caps, payload cap, bounded largeBlob | OWASP File Upload Cheat Sheet; PKWARE APPNOTE.TXT (.ZIP File Format Specification) (section to verify) |
| GAP-13 | GAP-13 | `zeroizeKeyMaterial` | CXP/CXF (no clause) | Best-effort zeroisation of buffers | NIST SP 800-57 Part 1 Rev. 5 (section to verify) |
| GAP-14 | GAP-14 | `requireHpkeAuthMode` | CXP §3.5.2 | HPKE auth mode with a confirmed exporter key | RFC 9180 §5.1.3; RFC 7638 §3 |
| GAP-19 | GAP-19 | `requireTls` | CXP §1.1, §3.2.2 | TLS 1.3 with pinned per-run test CA | RFC 8446; RFC 5280 §4.2.1.6; RFC 5280 §4.2.1.9; RFC 5280 §4.2.1.12; NIST SP 800-52 Rev. 2 (section to verify); OWASP Transport Layer Security Cheat Sheet |
| GAP-20 | GAP-20 | `strictCxfValidation` | CXF §1.3, §2.1, §2.1.2, §3.1.1, §3.3.12, §3.3.12.3 | Reject producer-MUST violations; canonical base64url | RFC 4648 §3.2; RFC 4648 §3.5; RFC 7515 §2; RFC 5958 (section to verify); FIDO CTAP 2.1 (section to verify) |
| GAP-21 | GAP-21 | `enforceTimestampFreshness` | CXF §3.1 (timestamp) | Timestamp window with 300 s skew | NIST SP 800-63B-4 (section to verify) |
| GAP-22 | GAP-22 | `bindExporterIdentity` | CXF §3.1 (exporterRpId), CXP §3.3 (exporter) | exporterRpId must equal response exporter | Design decision |
| GAP-29 | GAP-29 | `requireExportConsent` | CXP §2 (step 2), §2.1 | Consent prompt bound to the request fingerprint | OWASP Transaction Authorization Cheat Sheet; NIST SP 800-63B-4 (section to verify) |
| GAP-30 | GAP-30 | `rejectConflictingImport` | CXP/CXF (no clause) | Never silently replace an existing credential | Saltzer & Schroeder, The Protection of Information in Computer Systems (1975) (section to verify) |
| GAP-31 | GAP-31 | `secureExportFiles` | CXP §3.2.1, §3.2.2 (indirect) | 0600 files, deleted after import | POSIX.1 (IEEE Std 1003.1), open()/file mode bits (section to verify); NIST SP 800-88 Rev. 1 (section to verify) |

#### GAP-01: Response not bound to the request

- **Specification clause:** CXP §2 (step 1, 3), §3.2/§3.3 CDDL
- **Specification text:** "The import request includes a challenge, the scope of the export request, and a declaration of the type of encryption scheme to be used."
- **What the specification leaves open:** The overview describes a challenge and a signed challenge response, but neither exists in the CDDL.
- **Policy flag:** `bindRequestChallenge`
- **spec-minimal:** No challenge; HPKE info empty; a response is matched to the latest pending request.
- **hardened:** 32-byte random challenge in the request; SHA-256 of the RFC 8785 canonical request is bound into HPKE info, so a response decrypts only for that exact request; the exporter refuses requests without a challenge.
- **Standards relied on:**
  - RFC 9180 §5.1 [IETF RFC]: info input to the key schedule
  - RFC 8785 §3.2.3 [IETF RFC]: canonical JSON (member sorting)
  - FIPS 180-4 (section to verify) [NIST]: SHA-256
  - RFC 8446 §4.4.1 [IETF RFC]: analogous practice: transcript hash binding
- **Code:** `src/cxp/request.ts:78`, `src/cxp/binding.ts:29`, `src/cxp/binding.ts:36`, `src/cxp/response.ts:69`
- **Tests:** `test/security/a03-replay.test.ts`, `test/security/a14-scope-tamper.test.ts`, `test/crypto/jcs.test.ts`

#### GAP-02: No mandatory-to-implement suite

- **Specification clause:** CXP §5
- **Specification text:** "This section defines which algorithms and features of this specification are mandatory to implement."
- **What the specification leaves open:** The section contains no algorithms.
- **Policy flag:** `enforceMandatorySuite`
- **spec-minimal:** Any mutually listed suite is accepted, in the importer's order.
- **hardened:** Only DHKEM(X25519, HKDF-SHA256) 0x0020 / HKDF-SHA256 0x0001 / AES-256-GCM 0x0002 is offered, selected and accepted.
- **Standards relied on:**
  - RFC 9180 §7.1 [IETF RFC]: KEM 0x0020
  - RFC 9180 §7.2 [IETF RFC]: KDF 0x0001
  - RFC 9180 §7.3 [IETF RFC]: AEAD 0x0002
  - RFC 7748 [IETF RFC]: X25519 (whole document)
  - NIST SP 800-38D [NIST]: AES-GCM (whole document)
- **Design decision:** Choosing one suite as mandatory is a design decision: no standard names a mandatory HPKE suite for CXP.
- **Code:** `src/crypto/hpke.ts:38`, `src/cxp/request.ts:52`, `src/cxp/negotiate.ts:37`, `src/cxp/response.ts:163`
- **Tests:** `test/security/a04-negotiation-tamper.test.ts`

#### GAP-03: Negotiated selection not integrity-protected

- **Specification clause:** CXP §3.2 (hpke), §3.3
- **Specification text:** "It is up to the Exporting Provider to select a matching set of parameters that both support."
- **What the specification leaves open:** Nothing lets the importer check what the exporter chose against what it offered.
- **Policy flag:** `verifyNegotiatedSelection`
- **spec-minimal:** Any selection present in the importer's lists is accepted.
- **hardened:** The importer requires the first HPKE entry and the first supported archive; with GAP-01 the offered lists are also bound into HPKE info.
- **Standards relied on:**
  - RFC 8446 §4.4.1 [IETF RFC]: analogous practice: negotiation covered by the transcript hash
- **Design decision:** Requiring the first entry is stricter than TLS (which authenticates any choice); acceptable because the hardened importer offers one suite.
- **Code:** `src/cxp/response.ts:167`
- **Tests:** `test/security/a04-negotiation-tamper.test.ts`

#### GAP-04: Version downgrade

- **Specification clause:** CXP §3.3 (version)
- **Specification text:** "The Importing Provider MAY refuse this version downgrade."
- **What the specification leaves open:** Refusal is optional.
- **Policy flag:** `rejectVersionDowngrade`
- **spec-minimal:** A lower response version is accepted.
- **hardened:** A response version below the requested version is rejected.
- **Standards relied on:**
  - RFC 8446 §4.1.3 [IETF RFC]: analogous practice: downgrade protection
- **Code:** `src/cxp/response.ts:174`
- **Tests:** `test/security/a05-version-downgrade.test.ts`

#### GAP-05: Self-asserted importer/exporter identities

- **Specification clause:** CXP §3.2 (importer), §3.3 (exporter)
- **Specification text:** "This member is the Relying Party Identifier of the Importing Provider."
- **What the specification leaves open:** Both identities are plain claims with no authentication.
- **Policy flag:** `requireSasConfirmation`
- **spec-minimal:** Identities are display-only.
- **hardened:** The user compares 128-bit fingerprints shown by both providers: SHA-256 of the canonical request (direct channel) and the RFC 7638 thumbprint of the exporter's static key (importer side, with GAP-14).
- **Standards relied on:**
  - RFC 7638 §3 [IETF RFC]: JWK thumbprint of the exporter key
  - RFC 8785 §3.2.3 [IETF RFC]: canonical request for the request fingerprint
  - RFC 6189 (section to verify) [IETF RFC]: rationale: short codes need a hash commitment (ZRTP SAS)
- **Design decision:** 128 bits (not a 6-digit SAS) because in indirect mode the request is seen before substitution, so a short code could be searched for offline.
- **Code:** `src/cxp/binding.ts:56`, `src/cxp/binding.ts:61`, `src/cxp/response.ts:190`, `src/provider/exporter.ts:177`
- **Tests:** `test/security/a01-key-substitution.test.ts`, `test/security/a02-mitm-direct.test.ts`, `test/security/a13-consent-phishing.test.ts`, `test/security/ablation-consent.test.ts`

#### GAP-06: Unprotected request file

- **Specification clause:** CXP §3.2.1, §3.2.2 (indirect)
- **Specification text:** "the Export Request SHALL be stored as a JSON-encoded document to be supplied to the Exporter by the Credential Owner."
- **What the specification leaves open:** The file has no integrity protection on its way to the exporter.
- **Policy flag:** `confirmRequestFileKey`
- **spec-minimal:** The file is loaded as-is.
- **hardened:** Before a file-channel export the exporter shows the request fingerprint; the user approves only if it matches the importer's display.
- **Standards relied on:**
  - RFC 8785 §3.2.3 [IETF RFC]: canonical request
  - FIPS 180-4 (section to verify) [NIST]: SHA-256
- **Code:** `src/provider/exporter.ts:177`, `src/provider/importer.ts:77`
- **Tests:** `test/security/a01-key-substitution.test.ts`, `test/security/a13-consent-phishing.test.ts`

#### GAP-07: HPKE-to-JWE mapping

- **Specification clause:** CXP §3.4, §3.5.1
- **Specification text:** "where each file is separately encrypted using the key defined by the selected HPKE Parameters."
- **What the specification leaves open:** How HPKE produces the JWE key, and where enc travels, are not specified.
- **Policy flag:** `deriveFileKeysViaExport`
- **spec-minimal:** One payload key from the HPKE secret export (context "CXP payload key") is the CEK of every file; enc travels as a JWK in ExportResponse.hpke.key.
- **hardened:** A per-file key is exported with context "CXP file key " || path.
- **Standards relied on:**
  - RFC 9180 §5.3 [IETF RFC]: secret export
  - RFC 7518 §4.5 [IETF RFC]: alg dir
  - RFC 7518 §5.3 [IETF RFC]: AES-GCM
  - NIST SP 800-38D (section to verify) [NIST]: IV uniqueness under one key (spec-minimal reuses a key with random IVs)
- **Design decision:** Exporter-context labels are PoC choices.
- **Code:** `src/cxp/payload.ts:25`, `src/cxp/payload.ts:76`, `src/crypto/jwe.ts:21`
- **Tests:** `test/security/a06-file-swap.test.ts`, `test/cxp/exchange.test.ts`

#### GAP-08: Dangling 'anonymous identifier' for file names

- **Specification clause:** CXP §3.4
- **Specification text:** "The file names are replaced with the anonymous identifier in the export request."
- **What the specification leaves open:** No such identifier exists in the §3.2 CDDL.
- **Policy flag:** `randomizeFileNames`
- **spec-minimal:** Document names are CXF Item IDs.
- **hardened:** Random 128-bit names; the mapping exists only in the encrypted index.
- **Standards relied on:**
  - RFC 6973 (section to verify) [IETF RFC]: data minimisation (privacy considerations)
- **Design decision:** No standard defines archive file naming; random names minimise clear-text metadata.
- **Code:** `src/cxp/payload.ts:68`
- **Tests:** `test/security/a12-metadata-leakage.test.ts`

#### GAP-09: No per-file binding (AAD)

- **Specification clause:** CXP §3.4
- **Specification text:** none (silent).
- **What the specification leaves open:** Silent: nothing binds a file to its name, position or request.
- **Policy flag:** `bindFileAad`
- **spec-minimal:** No binding beyond the JWE protected header.
- **hardened:** Protected header carries cxp-path and cxp-req (request digest); both are checked on decryption.
- **Standards relied on:**
  - RFC 7516 §5.1 [IETF RFC]: protected header is the AEAD AAD
  - RFC 5116 (section to verify) [IETF RFC]: AEAD associated data
- **Code:** `src/cxp/payload.ts:84`, `src/cxp/payload.ts:180`
- **Tests:** `test/security/a06-file-swap.test.ts`

#### GAP-10: Archive layout undefined

- **Specification clause:** CXP §3.4
- **Specification text:** "The format MUST follow the zip archive format as defined in [CXF]"
- **What the specification leaves open:** CXF PS 2026 defines no archive, and the contents of index.jwe and documents/ are unspecified.
- **Policy flag:** `authenticateManifest`
- **spec-minimal:** Zip with CXP-Export/index.jwe ({header, documents}) and one CXF Item per CXP-Export/documents/<name>.jwe; missing listed documents are skipped, unlisted files ignored.
- **hardened:** The encrypted index lists a SHA-256 per document; missing, unlisted or altered files are rejected.
- **Standards relied on:**
  - PKWARE APPNOTE.TXT (.ZIP File Format Specification) (section to verify) [Industry specification]: zip container
  - FIPS 180-4 (section to verify) [NIST]: SHA-256
- **Design decision:** The index/document layout follows the CXP §3.4 illustration; the manifest is a PoC design.
- **Code:** `src/cxp/payload.ts:20`, `src/cxp/payload.ts:131`, `src/cxp/payload.ts:203`, `src/cxp/payload.ts:226`
- **Tests:** `test/cxp/exchange.test.ts`

#### GAP-11: No single-use rule or key lifetime

- **Specification clause:** CXP §3.2, §3.3
- **Specification text:** none (silent).
- **What the specification leaves open:** Silent: no replay rule for a response and no lifetime for the importer key.
- **Policy flag:** `singleUseImporterKey`
- **spec-minimal:** The request and its keys remain usable; a response can be imported again.
- **hardened:** The pending request and keyring are discarded after the first successful import (references dropped; JavaScript cannot guarantee erasure).
- **Standards relied on:**
  - NIST SP 800-57 Part 1 Rev. 5 (section to verify) [NIST]: cryptoperiod / ephemeral key usage
- **Code:** `src/provider/importer.ts:135`
- **Tests:** `test/security/a03-replay.test.ts`

#### GAP-12: Unbounded decompression

- **Specification clause:** CXP §3.5.3, CXF §3.3.12.5
- **Specification text:** "The claimed uncompressed size of the DEFLATE compressed data in data."
- **What the specification leaves open:** Sizes are claims; no limits are set.
- **Policy flag:** `enforceDecompressionLimits`
- **spec-minimal:** No limits; fflate allocates from each entry's declared size.
- **hardened:** Before inflating: at most 10 000 entries, 1 MiB per entry, 64 MiB in total, methods 0/8 only; payload length capped; largeBlob inflated with a 64 KiB bound and checked against uncompressedSize.
- **Standards relied on:**
  - OWASP File Upload Cheat Sheet [OWASP guidance]: limit decompressed size and file count
  - PKWARE APPNOTE.TXT (.ZIP File Format Specification) (section to verify) [Industry specification]: declared sizes in local and central headers
- **Design decision:** Numeric limits are PoC choices sized for credential exports.
- **Code:** `src/crypto/archive.ts:32`, `src/crypto/archive.ts:47`, `src/cxp/response.ts:149`, `src/provider/importer.ts:188`
- **Tests:** `test/security/a08-decompression-bomb.test.ts`

#### GAP-13: Decrypted key material in memory

- **Specification clause:** CXP/CXF (no clause)
- **Specification text:** none (silent).
- **What the specification leaves open:** Silent: no guidance on handling decrypted PKCS#8 keys.
- **Policy flag:** `zeroizeKeyMaterial`
- **spec-minimal:** No clearing.
- **hardened:** Decrypted file plaintexts, content-encryption keys and the PKCS#8 DER buffer are zeroed after use (best effort: immutable JavaScript strings and GC copies remain).
- **Standards relied on:**
  - NIST SP 800-57 Part 1 Rev. 5 (section to verify) [NIST]: key destruction / zeroisation
- **Code:** `src/cxp/payload.ts:188`, `src/cxp/payload.ts:191`, `src/provider/importer.ts:207`
- **Tests:** `test/security/a09-memory-residue.test.ts`

#### GAP-14: Unauthenticated exporter (base mode)

- **Specification clause:** CXP §3.5.2
- **Specification text:** "Base mode of encrypting a public key."
- **What the specification leaves open:** In base mode the importer cannot authenticate the exporter.
- **Policy flag:** `requireHpkeAuthMode`
- **spec-minimal:** Any well-formed base-mode response is accepted.
- **hardened:** HPKE auth mode with the exporter's static key (sent as hpke.senderKey); the user confirms its fingerprint (GAP-05).
- **Standards relied on:**
  - RFC 9180 §5.1.3 [IETF RFC]: authentication using an asymmetric key
  - RFC 7638 §3 [IETF RFC]: exporter key fingerprint
- **Design decision:** The senderKey member is a PoC extension: CXP has a single key member.
- **Code:** `src/cxp/request.ts:54`, `src/cxp/negotiate.ts:34`, `src/cxp/response.ts:179`, `src/cxp/payload.ts:102`
- **Tests:** `test/security/a07-credential-injection.test.ts`, `test/security/a07b-auth-mode-forgery.test.ts`

#### GAP-19: Direct-mode transport security

- **Specification clause:** CXP §1.1, §3.2.2
- **Specification text:** "This protocol does not make any assumptions about the channels in which credential data is passed from the source provider to the destination provider."
- **What the specification leaves open:** No transport security is required.
- **Policy flag:** `requireTls`
- **spec-minimal:** Plain HTTP on loopback.
- **hardened:** HTTPS with TLS 1.3 minimum and a per-run test CA (server certificate with SAN 127.0.0.1/localhost, serverAuth EKU); the client trusts only that CA and refuses http URLs.
- **Standards relied on:**
  - RFC 8446 [IETF RFC]: TLS 1.3 (whole document)
  - RFC 5280 §4.2.1.6 [IETF RFC]: subject alternative name
  - RFC 5280 §4.2.1.9 [IETF RFC]: basic constraints
  - RFC 5280 §4.2.1.12 [IETF RFC]: extended key usage
  - NIST SP 800-52 Rev. 2 (section to verify) [NIST]: TLS version guidance
  - OWASP Transport Layer Security Cheat Sheet [OWASP guidance]: TLS configuration
- **Code:** `src/provider/direct.ts:61`, `src/provider/direct.ts:66`, `src/provider/direct.ts:132`, `src/crypto/test-ca.ts:31`
- **Tests:** `test/security/a02-mitm-direct.test.ts`, `test/security/a02-tls-app-layer.test.ts`

#### GAP-20: Importer handling of producer-MUST violations

- **Specification clause:** CXF §1.3, §2.1, §2.1.2, §3.1.1, §3.3.12, §3.3.12.3
- **Specification text:** "Identifiers MUST be unique for a given exchanged Account and have a maximum of 64 bytes in length."
- **What the specification leaves open:** MUSTs bind the producer; the importer's reaction to violations, and b64url padding, are unspecified.
- **Policy flag:** `strictCxfValidation`
- **spec-minimal:** Only structurally malformed input is rejected; padded/non-canonical b64url, any version and any hmac length are accepted.
- **hardened:** Producer-MUST violations rejected: ID length/uniqueness, empty optional arrays, major version 1, PKCS#8 key, canonical unpadded b64url, 32-byte hmac credentials.
- **Standards relied on:**
  - RFC 4648 §3.2 [IETF RFC]: padding
  - RFC 4648 §3.5 [IETF RFC]: canonical encoding
  - RFC 7515 §2 [IETF RFC]: unpadded base64url convention
  - RFC 5958 (section to verify) [IETF RFC]: PKCS#8 structure
  - FIDO CTAP 2.1 (section to verify) [FIDO]: hmac-secret 32-byte credential random
- **Code:** `src/cxf/parse.ts:41`, `src/cxf/strict.ts:25`, `src/cxf/b64url.ts:34`
- **Tests:** `test/security/a18-malformed-cxf.test.ts`, `test/cxf/validation.test.ts`

#### GAP-21: No freshness check

- **Specification clause:** CXF §3.1 (timestamp)
- **Specification text:** "The UNIX timestamp in seconds during at which the export document was completed."
- **What the specification leaves open:** The importer is never told to check it.
- **Policy flag:** `enforceTimestampFreshness`
- **spec-minimal:** Timestamp ignored.
- **hardened:** Reject documents more than 300 s in the future or older than the Export Request (minus 300 s skew).
- **Standards relied on:**
  - NIST SP 800-63B-4 (section to verify) [NIST]: replay resistance
- **Design decision:** The 300 s skew is a PoC choice (a common clock-skew allowance).
- **Code:** `src/cxp/response.ts:39`, `src/cxp/response.ts:219`
- **Tests:** `test/security/a16-stale-document.test.ts`

#### GAP-22: Two unrelated exporter identities

- **Specification clause:** CXF §3.1 (exporterRpId), CXP §3.3 (exporter)
- **Specification text:** "The name of the exporting app as a relying party identifier."
- **What the specification leaves open:** Nothing requires the CXF and CXP identities to agree.
- **Policy flag:** `bindExporterIdentity`
- **spec-minimal:** No cross-check.
- **hardened:** Header.exporterRpId must equal ExportResponse.exporter (the identity shown when the exporter key is confirmed).
- **Standards relied on:** none (no external standard applies).
- **Design decision:** Consistency check between two self-asserted fields; no standard applies.
- **Code:** `src/cxp/response.ts:215`
- **Tests:** `test/security/a17-exporter-identity.test.ts`

#### GAP-29: No required user consent

- **Specification clause:** CXP §2 (step 2), §2.1
- **Specification text:** "If an end-user and/or authorizing party approves the request"
- **What the specification leaves open:** Approval is mentioned descriptively only; nothing defines what is shown or binds it to the request.
- **Policy flag:** `requireExportConsent`
- **spec-minimal:** Supplying the request is the approval.
- **hardened:** A prompt shows importer, request fingerprint, credential types and item count; export proceeds only on approval of that exact request. User verification is simulated (the approval callback stands for it).
- **Standards relied on:**
  - OWASP Transaction Authorization Cheat Sheet [OWASP guidance]: what you see is what you sign
  - NIST SP 800-63B-4 (section to verify) [NIST]: re-authentication before sensitive operations
- **Code:** `src/provider/exporter.ts:177`, `src/provider/exporter.ts:207`
- **Tests:** `test/security/a13-consent-phishing.test.ts`, `test/security/ablation-consent.test.ts`

#### GAP-30: Conflicting import

- **Specification clause:** CXP/CXF (no clause)
- **Specification text:** none (silent).
- **What the specification leaves open:** Silent: nothing covers importing a credential that already exists.
- **Policy flag:** `rejectConflictingImport`
- **spec-minimal:** The imported credential replaces the existing one.
- **hardened:** The existing credential is kept and the conflict reported (skipped with reason 'conflict').
- **Standards relied on:**
  - Saltzer & Schroeder, The Protection of Information in Computer Systems (1975) (section to verify) [Academic literature]: fail-safe defaults
- **Code:** `src/provider/importer.ts:173`
- **Tests:** `test/security/a07c-conflict-import.test.ts`

#### GAP-31: Indirect-mode file handling

- **Specification clause:** CXP §3.2.1, §3.2.2 (indirect)
- **Specification text:** "which MUST output the Export Response to the filesystem."
- **What the specification leaves open:** No guidance on location, permissions or removal.
- **Policy flag:** `secureExportFiles`
- **spec-minimal:** Default permissions (umask, typically 0644); files left in place.
- **hardened:** Files created with mode 0600; response and request files deleted after a successful import (best effort: storage remanence and backups remain).
- **Standards relied on:**
  - POSIX.1 (IEEE Std 1003.1), open()/file mode bits (section to verify) [Industry specification]: owner-only permissions
  - NIST SP 800-88 Rev. 1 (section to verify) [NIST]: deletion is not sanitisation (documented limitation)
- **Code:** `src/provider/importer.ts:114`, `src/provider/importer.ts:146`, `src/provider/exporter.ts:232`
- **Tests:** `test/security/a03-replay.test.ts`, `test/provider/migration-modes.test.ts`

### 2.2 Closed in `hardened` through other flags (no dedicated flag)

| ID | Gap | Flag | Specification clause | Choice / control | Standard |
|---|---|---|---|---|---|
| GAP-18 | GAP-18 | - | CXF §1.3 (Identifier) | Via GAP-08 random file names | RFC 6973 (section to verify) |
| GAP-32 | GAP-32 | - | CXP §3.2 (credentialTypes) | Via GAP-01/05/06 request binding | RFC 8785 §3.2.3; RFC 9180 §5.1 |

#### GAP-18: Clear-text identifiers

- **Specification clause:** CXF §1.3 (Identifier)
- **Specification text:** "Identifiers SHOULD NOT have any personally identifying information contained as they will be shared in clear text during any given [CXP] exchange sessions."
- **What the specification leaves open:** Identifiers are expected to be visible in clear text.
- **Closed through flags:** `randomizeFileNames`
- **spec-minimal:** Item IDs appear as archive file names.
- **hardened:** Realised by GAP-08: random file names, IDs only inside encrypted files.
- **Standards relied on:**
  - RFC 6973 (section to verify) [IETF RFC]: data minimisation
- **Code:** `src/cxp/payload.ts:68`
- **Tests:** `test/security/a12-metadata-leakage.test.ts`

#### GAP-32: Scope widening by removing credentialTypes

- **Specification clause:** CXP §3.2 (credentialTypes)
- **Specification text:** "If this member is not present then it is understood that the Importing Provider is requesting all credential types."
- **What the specification leaves open:** Absence silently means 'all types', so stripping the member widens the export.
- **Closed through flags:** `bindRequestChallenge`, `requireSasConfirmation`, `confirmRequestFileKey`
- **spec-minimal:** Absent = all types.
- **hardened:** An altered request changes its fingerprint (user declines) and its digest in HPKE info (response does not decrypt).
- **Standards relied on:**
  - RFC 8785 §3.2.3 [IETF RFC]: canonical request
  - RFC 9180 §5.1 [IETF RFC]: info binding
- **Code:** `src/cxp/binding.ts:36`, `src/provider/exporter.ts:177`
- **Tests:** `test/security/a14-scope-tamper.test.ts`

### 2.3 Not closed in the PoC

| ID | Gap | Flag | Specification clause | Choice / control | Standard |
|---|---|---|---|---|---|
| GAP-15 | GAP-15 | - | CXP §1.1 | Not closed (out of scope) | Design decision |
| GAP-16 | GAP-16 | - | CXF §3.3.12.3 | Not closed (requires spec change) | Design decision |
| GAP-17 | GAP-17 | - | CXF §3.3.12 (note) | Not closed (requires spec change) | W3C WebAuthn Level 3 §7.2 |
| GAP-25 | GAP-25 | - | CXF §3.3.12 (Passkey members) | Not closed (requires spec change) | W3C WebAuthn Level 3 §6.1.3 (section to verify) |
| GAP-33 | GAP-33 | - | CXF §3.3.12 (note) | Not closed (not implemented) | Design decision |

#### GAP-15: Source copy retained

- **Specification clause:** CXP §1.1
- **Specification text:** "The destruction of credentials after migration by the credential provider source is out of scope as well."
- **What the specification leaves open:** Destruction is out of scope.
- **spec-minimal:** Source copy retained.
- **hardened:** Same (residual risk, documented).
- **Not closed because:** Out of protocol scope: CXP excludes source-credential destruction; closing it needs a specification change or provider policy outside CXP.
- **Standards relied on:** none (no external standard applies).
- **Design decision:** Residual risk; recommendation for a future CXP revision.
- **Code:** none (no control implemented)
- **Tests:** `test/security/a10-clone-credential.test.ts`, `test/scenario/end-to-end.test.ts`

#### GAP-16: Identical PRF/hmac-secret seeds across importers

- **Specification clause:** CXF §3.3.12.3
- **Specification text:** "If these credentials are exchanged to multiple importing providers who support both values, they MUST all have the same value."
- **What the specification leaves open:** Every importer receives the same seeds.
- **spec-minimal:** As specified.
- **hardened:** As specified (MUST in both profiles).
- **Not closed because:** Spec-mandated (CXF MUST); a conformant mitigation is impossible, so it requires a specification change.
- **Standards relied on:** none (no external standard applies).
- **Design decision:** Demonstrated and recommended for a specification change.
- **Code:** none (no control implemented)
- **Tests:** `test/security/a11-prf-seed-reuse.test.ts`, `test/security/a11-hmac-reuse.test.ts`

#### GAP-17: Signature counter forced to zero

- **Specification clause:** CXF §3.3.12 (note)
- **Specification text:** "Importers MUST set a zero value for the imported passkey signature counters and MUST NOT increment them after the fact."
- **What the specification leaves open:** Disables RP clone detection for migrated passkeys.
- **spec-minimal:** As specified.
- **hardened:** As specified (MUST in both profiles).
- **Not closed because:** Spec-mandated (CXF MUST: counter zero, never incremented); requires a specification change.
- **Standards relied on:**
  - W3C WebAuthn Level 3 §7.2 [W3C]: RP signature-counter check that a zero counter disables
- **Code:** `src/provider/importer.ts:221`
- **Tests:** `test/security/a10-clone-credential.test.ts`, `test/scenario/end-to-end.test.ts`

#### GAP-25: Backup flags not carried by CXF

- **Specification clause:** CXF §3.3.12 (Passkey members)
- **Specification text:** none (silent).
- **What the specification leaves open:** Silent: the Passkey dictionary has no backup-eligibility/state or AAGUID member.
- **spec-minimal:** Both authenticators report BE=1, BS=1.
- **hardened:** Same.
- **Not closed because:** No conformant CXF field carries BE/BS or the AAGUID; requires a CXF change.
- **Standards relied on:**
  - W3C WebAuthn Level 3 §6.1.3 (section to verify) [W3C]: backup eligibility fixed for the credential lifetime
- **Code:** `src/provider/authenticator.ts:174`, `src/provider/importer.ts:222`
- **Tests:** `test/scenario/end-to-end.test.ts`

#### GAP-33: Excluded passkeys not reported to the owner

- **Specification clause:** CXF §3.3.12 (note)
- **Specification text:** "the exporter SHOULD inform the user that such passkeys are excluded from the export."
- **What the specification leaves open:** Exclusion is a MUST; informing the user is a SHOULD.
- **spec-minimal:** Exclusion reported to the calling code (ExportReport.excludedNonZeroCounter) but not to the owner.
- **hardened:** Same.
- **Not closed because:** Not implemented in the PoC: notifying the owner would need ExportingProvider changes outside the adversary code boundary (the exclusion itself is a CXF MUST and is implemented).
- **Standards relied on:** none (no external standard applies).
- **Design decision:** No external standard applies: the obligation is the CXF SHOULD itself; recorded as a recommendation (report each excluded credential and the reason to the owner).
- **Code:** `src/provider/exporter.ts:109`
- **Tests:** `test/security/a15-nonzero-counter.test.ts`
