# Architecture — CXP Migration PoC

Every network component binds to the IPv4 loopback address **127.0.0.1**; nothing listens on another interface and nothing talks to the internet (README §9 rule 6). Ports are chosen by the OS (`listen(0)`) unless a standalone script fixes them.

## 1. Components and addresses

```mermaid
flowchart LR
  subgraph HOST["Developer machine: loopback only, 127.0.0.1"]
    direction LR

    subgraph ENTRY["Entry points (pnpm scripts)"]
      CLI["CLI demos<br/>demo:baseline, demo:exchange, demo:migrate,<br/>demo:e2e, walkthrough"]
      TESTS["vitest suites<br/>test/crypto, cxf, cxp, provider, rp,<br/>scenario, security"]
      ATK["attack:all<br/>src/cli/attack-all.ts"]
    end

    subgraph DASH["Dashboard: http://127.0.0.1:4000 (DASHBOARD_PORT)"]
      DUI["GET /<br/>self-contained page, CSP default-src self"]
      DAPI["GET /api/policy<br/>POST /api/run"]
    end

    subgraph WORLD["Scenario world: src/scenario/world.ts and walkthrough.ts"]
      USER(["Simulated user<br/>compares fingerprints (hardened)"])
      RPC["RpHttpClient<br/>plays the browser"]

      subgraph RPBOX["Demo Relying Party: http://127.0.0.1:random port<br/>standalone pnpm rp: http://127.0.0.1:3000 (RP_PORT)<br/>RP ID localhost, origin http://localhost:port"]
        RPAPI["POST /webauthn/register/options and /verify<br/>POST /webauthn/login/options and /verify<br/>GET /healthz"]
        RPCORE["DemoRelyingParty<br/>SimpleWebAuthn 14, users, single-use challenges,<br/>userHandle owner check"]
      end

      subgraph PA["Provider A: Exporter (provider-a.example)"]
        AUTHA["SoftwareAuthenticator A<br/>ES256, none attestation, counter 0, BE=BS=1"]
        VA[("Vault A<br/>StoredPasskey records")]
        EXP["ExportingProvider<br/>vault to CXF, scope filters,<br/>consent prompt, static HPKE key"]
        SVC["Direct export service: POST /cxp/export<br/>spec-minimal: http://127.0.0.1:random port<br/>hardened: https://127.0.0.1:random port, TLS 1.3, test CA"]
      end

      subgraph PB["Provider B: Importer (provider-b.example)"]
        IMP["ImportingProvider<br/>Export Request, keyring,<br/>open response, store passkeys"]
        VB[("Vault B")]
        AUTHB["SoftwareAuthenticator B"]
      end
    end

    subgraph FS["Filesystem (indirect mode)<br/>OS temp dir cxp-indirect-*, or out/indirect/"]
      REQF[/"cxp-export-request.json"/]
      RESF[/"cxp-export-response-TIMESTAMP.json"/]
    end

    subgraph LIB["Core libraries"]
      POL["src/policy<br/>spec-minimal or hardened<br/>one flag per GAP-xx"]
      CXP["src/cxp<br/>schemas, negotiation, request, response,<br/>payload, binding: JCS digest, fingerprints"]
      CXF["src/cxf<br/>zod schemas, parse, strict checks (GAP-20),<br/>serialize"]
      CRY["src/crypto<br/>HPKE RFC 9180, JWE dir + AES-GCM,<br/>zip (fflate), JCS RFC 8785, test CA"]
    end

    ADV["Adversary harness (in-process, no ports)<br/>src/adversary, scenarios A-01 to A-18"]
    REP[/"reports/attack-matrix.json and .md"/]
  end

  %% entry points
  CLI --> WORLD
  TESTS --> WORLD
  DAPI -->|runWalkthrough| WORLD
  ATK --> ADV
  ATK --> REP

  %% WebAuthn
  RPC -->|"HTTP JSON to 127.0.0.1"| RPAPI
  RPAPI --> RPCORE
  RPC -->|"create / get"| AUTHA
  RPC -->|"get (after migration)"| AUTHB
  AUTHA <--> VA
  AUTHB <--> VB

  %% CXP: indirect mode
  IMP -->|"1 write Export Request"| REQF
  REQF -->|"2 user carries file"| EXP
  EXP -->|"3 write Export Response"| RESF
  RESF -->|"4 read and import"| IMP

  %% CXP: direct mode
  IMP ==>|"direct: POST Export Request"| SVC
  SVC --> EXP
  SVC ==>|"Export Response JSON"| IMP

  EXP -->|reads| VA
  IMP -->|"stores, counter 0"| VB

  %% user prompts (hardened)
  USER -.->|"approve export"| EXP
  USER -.->|"confirm exporter key"| IMP

  %% libraries
  EXP --> CXP
  IMP --> CXP
  CXP --> CXF
  CXP --> CRY
  POL -.-> EXP
  POL -.-> IMP
  POL -.-> CXP

  %% adversary interposes on channels and stored data
  ADV -.->|interposes| REQF
  ADV -.->|interposes| RESF
  ADV -.->|interposes| SVC
  ADV -.->|uses| WORLD
```

## 2. Migration sequence (one run)

```mermaid
sequenceDiagram
  autonumber
  actor U as User (simulated)
  participant RPC as RpHttpClient
  participant RP as Demo RP<br/>127.0.0.1:port<br/>origin http://localhost:port
  participant A as Provider A<br/>Exporter
  participant FS as Filesystem
  participant S as Export service<br/>127.0.0.1:port /cxp/export
  participant B as Provider B<br/>Importer

  RPC->>RP: POST /webauthn/register/options
  RP-->>RPC: creation options (RP ID localhost, challenge)
  RPC->>A: authenticator.create(): new ES256 key in Vault A
  RPC->>RP: POST /webauthn/register/verify
  B->>B: createRequest(): keys, challenge (hardened)
  alt indirect mode
    B->>FS: cxp-export-request.json (0644 spec-minimal, 0600 hardened)
    U->>A: hands the request file to Provider A
    A->>U: consent prompt with request fingerprint (hardened)
    A->>FS: cxp-export-response-TIMESTAMP.json
    FS->>B: importResponseFile()
  else direct mode
    B->>S: POST /cxp/export (HTTP spec-minimal, HTTPS TLS 1.3 hardened)
    S->>A: respond(request)
    A->>U: consent prompt (hardened)
    S-->>B: Export Response JSON
  end
  B->>U: confirm exporter key fingerprint (hardened, HPKE auth mode)
  B->>B: HPKE decap, JWE decrypt, CXF parse, store in Vault B (counter 0)
  RPC->>RP: POST /webauthn/login/options and /verify, signed by Provider B
  RP-->>RPC: verified: same credential, counter 0
```

## 3. Addresses and ports

| Component | Bind address | Port | Protocol | Started by |
|---|---|---|---|---|
| Demo RP (tests, demos, dashboard runs) | 127.0.0.1 | random (OS-assigned) | HTTP | `startDemoRp()` via `createWorld()` |
| Demo RP (standalone) | 127.0.0.1 | 3000 (`RP_PORT`) | HTTP | `pnpm rp` |
| WebAuthn origin / RP ID | `http://localhost:<port>` / `localhost` | same as RP | — | reported in clientDataJSON; `localhost` is a secure context |
| Direct export service (spec-minimal) | 127.0.0.1 | random | HTTP | `startExporterService()` |
| Direct export service (hardened) | 127.0.0.1 | random | HTTPS, TLS 1.3, per-run test CA (SAN 127.0.0.1, localhost) | `startExporterService({ tls })` |
| Dashboard | 127.0.0.1 | 4000 (`DASHBOARD_PORT`) | HTTP | `pnpm dashboard` |
| Indirect-mode files | — | — | filesystem | OS temp dir `cxp-indirect-*`, or `out/indirect/` (`pnpm demo:migrate`) |
| Adversary harness | — (in-process) | none | — | `pnpm attack:all`, `test/security/*` |
