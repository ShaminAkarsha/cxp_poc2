# Attack Matrix

Generated: 2026-10-03T07:52:42.397Z

| ID | Scenario | Gaps | spec-minimal | hardened |
|---|---|---|---|---|
| A-01 | Importer public-key substitution in an indirect Export Request file | GAP-05, GAP-06 | ✓ succeeded | ✓ rejected |
| A-02 | Active MITM on a direct channel, relaying a substituted importer key | GAP-05, GAP-19 | ✓ succeeded | ✓ rejected |
| A-03 | Replay of a captured ExportResponse to the importer | GAP-01, GAP-11, GAP-31 | ✓ succeeded | ✓ rejected |
| A-04 | HPKE suite / archive negotiation tampering | GAP-02, GAP-03 | ✓ succeeded | ✓ rejected |
| A-05 | Protocol version downgrade | GAP-04, GAP-24 | ✓ succeeded | ✓ rejected |
| A-06 | Swapping or reordering files inside the archive | GAP-07, GAP-09 | ✓ succeeded | ✓ rejected |
| A-07 | Credential injection by an unauthenticated exporter | GAP-14, GAP-30 | ✓ succeeded | ✓ rejected |
| A-08 | Decompression bomb via deflate or largeBlob | GAP-12 | ✓ succeeded | ✓ rejected |
| A-09 | Post-import memory residue of PKCS#8 keys | GAP-13 | ✓ succeeded | ✓ reduced |
| A-10 | Clone use of source and migrated credential goes undetected by the RP | GAP-15, GAP-17 | ✓ succeeded | ✓ succeeded |
| A-11 | PRF seed reuse across two importers | GAP-16 | ✓ succeeded | ✓ succeeded |
| A-12 | Metadata observable to a passive observer of the Export Response | GAP-08, GAP-18 | ✓ succeeded | ✓ reduced |
| A-13 | Consent phishing: victim approves an attacker-crafted Export Request | GAP-05, GAP-06, GAP-29 | ✓ succeeded | ✓ rejected |

## Evidence

### A-01: Importer public-key substitution in an indirect Export Request file

- **spec-minimal**: succeeded — adversary decrypted 1 credential(s)
- **hardened**: rejected — export was not approved by the credential owner (GAP-29)

### A-02: Active MITM on a direct channel, relaying a substituted importer key

- **spec-minimal**: succeeded — MITM decrypted 1 credential(s) via plain HTTP
- **hardened**: rejected — TLS material is required for the direct transport (GAP-19)

### A-03: Replay of a captured ExportResponse to the importer

- **spec-minimal**: succeeded — replay imported 1 credential(s), replaced 1
- **hardened**: rejected — no pending Export Request

### A-04: HPKE suite / archive negotiation tampering

- **spec-minimal**: succeeded — forced non-MTI suite (KEM 16), imported 1 credential(s)
- **hardened**: rejected — only the MTI suite was offered; nothing to downgrade

### A-05: Protocol version downgrade

- **spec-minimal**: succeeded — version 0 accepted for request version 1, imported 1 credential(s)
- **hardened**: rejected — response version 0 is below requested 1 (GAP-04)

### A-06: Swapping or reordering files inside the archive

- **spec-minimal**: succeeded — swapped archive imported 2 credential(s)
- **hardened**: rejected — CXP-Export/documents/ocTuME6YGDwaoeGc_VxAoQ.jwe does not match the manifest

### A-07: Credential injection by an unauthenticated exporter

- **spec-minimal**: succeeded — injected 1 credential(s)
- **hardened**: rejected — response hpke does not correspond to any request entry

### A-08: Decompression bomb via deflate or largeBlob

- **spec-minimal**: succeeded — decompression bomb accepted: 2097152 bytes inflated
- **hardened**: rejected — bomb.bin: declared size 2097152 exceeds 1048576

### A-09: Post-import memory residue of PKCS#8 keys

- **spec-minimal**: succeeded — key material not zeroed after import
- **hardened**: reduced — DER buffers zeroed; base64url strings persist until GC

### A-10: Clone use of source and migrated credential goes undetected by the RP

- **spec-minimal**: succeeded — both source and migrated credential sign in; RP cannot distinguish
- **hardened**: succeeded — both source and migrated credential sign in; RP cannot distinguish

### A-11: PRF seed reuse across two importers

- **spec-minimal**: succeeded — identical PKCS#8 key material across exports; hmacCredentials would also be copied verbatim (CXF §3.3.12.3)
- **hardened**: succeeded — identical PKCS#8 key material across exports; hmacCredentials would also be copied verbatim (CXF §3.3.12.3)

### A-12: Metadata observable to a passive observer of the Export Response

- **spec-minimal**: succeeded — file names expose Item IDs: CXP-Export/documents/crO22SMX_lyr8BqHaH-bUw.jwe, CXP-Export/documents/MO6T_UCL22AyfKy3qJsC9g.jwe
- **hardened**: reduced — file names randomized; 2 file sizes still observable

### A-13: Consent phishing: victim approves an attacker-crafted Export Request

- **spec-minimal**: succeeded — adversary's request served without consent, 1 credential(s)
- **hardened**: rejected — export was not approved by the credential owner (GAP-29)
