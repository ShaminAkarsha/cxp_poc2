# Test fixtures

| File | Provenance |
|---|---|
| `cxf-appendix-a.json` | CXF PS 2026-03-09 (`cxf-v1.0-ps-errata-20260309`), Appendix A "Example Payload", pp. 50–64 of `docs/specs/Credential_Exchange_Format.pdf`. Extracted from the PDF text layer with page headers/footers and interleaved non-example prose removed; JSON content, key order and whitespace otherwise verbatim. Contains no real credentials. |
| `rfc9180-vectors.json` | CFRG HPKE test vectors (`test-vectors.json` in github.com/cfrg/draft-irtf-cfrg-hpke at commit `5f503c564da00b0687b3de75f1dfbdfc4079ad31`, 2021-05-24, the vectors accompanying RFC 9180; full file SHA-256 `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`). Filtered to modes base/auth, KEM 0x0010/0x0020, KDF 0x0001, AEAD 0x0001/0x0002/0xFFFF (12 vectors); per vector only encryptions at sequence 0, 1, 2 and the last are kept (the test regenerates the rest, since the vectors' AAD is `Count-<seq>`). Downloaded at development time on 2026-09-24; nothing is fetched at runtime. |
