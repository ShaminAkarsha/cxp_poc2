import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CxfValidationError,
  normaliseCxfHeader,
  parseCxfHeader,
  parseCxfHeaderJson,
  type Header,
} from "../../src/cxf/index.js";
import { getPolicy, PROFILE_NAMES } from "../../src/policy/index.js";

const specMinimal = getPolicy("spec-minimal");
const hardened = getPolicy("hardened");

const b64 = (bytes: Uint8Array | Buffer) => Buffer.from(bytes).toString("base64url");
const bytes = (n: number, fill = 1) => b64(Buffer.alloc(n, fill));

const pkcs8 = b64(
  generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "der", type: "pkcs8" }),
);

/** A minimal conformant CXF document with one passkey item. */
function makeDoc(): Header {
  return {
    version: { major: 1, minor: 0 },
    exporterRpId: "exporter.test",
    exporterDisplayName: "Exporter",
    timestamp: 1_700_000_000,
    accounts: [
      {
        id: bytes(16, 1),
        username: "",
        email: "user@example.test",
        collections: [{ id: bytes(16, 2), title: "Work", items: [{ item: bytes(16, 3) }] }],
        items: [
          {
            id: bytes(16, 3),
            title: "RP",
            credentials: [
              {
                type: "passkey",
                credentialId: bytes(16, 4),
                rpId: "rp.test",
                username: "user",
                userDisplayName: "User",
                userHandle: bytes(32, 5),
                key: pkcs8,
                fido2Extensions: {
                  hmacCredentials: { algorithm: "hmac-sha256", credWithUV: bytes(32, 6), credWithoutUV: bytes(32, 7) },
                },
              },
            ],
          },
        ],
      },
    ],
  };
}

type Mutator = (doc: Header & Record<string, unknown>) => void;
const mutate = (fn: Mutator): unknown => {
  const doc = structuredClone(makeDoc()) as Header & Record<string, unknown>;
  fn(doc);
  return doc;
};
const account = (d: Header) => d.accounts[0]!;
const item = (d: Header) => account(d).items[0]!;
const passkey = (d: Header) => item(d).credentials[0] as Record<string, unknown>;

describe.each(PROFILE_NAMES)("structural validation (both profiles) — %s", (profile) => {
  const policy = getPolicy(profile);

  it("accepts the conformant baseline", () => {
    expect(() => parseCxfHeader(makeDoc(), policy)).not.toThrow();
  });

  it("CXF §3.1.1 (MUST): ignores unknown fields and unknown credential types, preserving them", () => {
    const doc = mutate((d) => {
      d.futureField = { x: 1 };
      (item(d) as Record<string, unknown>).futureItemField = true;
      passkey(d).futurePasskeyField = "v";
      item(d).credentials.push({ type: "future-type", anything: [1, 2] });
    });
    const header = parseCxfHeader(doc, policy) as Record<string, unknown>;
    expect(header.futureField).toEqual({ x: 1 });
    expect(normaliseCxfHeader(header as Header)).toEqual(doc);
  });

  const malformed: [string, Mutator][] = [
    ["missing required Header member", (d) => void delete (d as Partial<Header>).exporterRpId],
    ["missing required array (CXF §2.1.2)", (d) => void delete (account(d) as Partial<Header["accounts"][0]>).collections],
    ["missing required Passkey member", (d) => void delete passkey(d).key],
    ["wrong JSON type for timestamp", (d) => void ((d as Record<string, unknown>).timestamp = "1700000000")],
    ["negative uint", (d) => void (d.timestamp = -1)],
    ["version.major outside uint .size 1", (d) => void (d.version.major = 256)],
    ["non-base64url alphabet in b64url", (d) => void (passkey(d).credentialId = "abc+/")],
    ["impossible b64url length", (d) => void (passkey(d).userHandle = "abcde")],
    ["credential without type", (d) => void delete (item(d).credentials[0] as Record<string, unknown>).type],
    ["non-boolean payments", (d) => void ((passkey(d).fido2Extensions as Record<string, unknown>).payments = "yes")],
  ];

  it.each(malformed)("rejects: %s", (_name, fn) => {
    expect(() => parseCxfHeader(mutate(fn), policy)).toThrow(CxfValidationError);
  });

  it("rejects non-JSON input", () => {
    expect(() => parseCxfHeaderJson("{not json", policy)).toThrow(CxfValidationError);
  });
});

/**
 * GAP-20: producer-MUST violations. spec-minimal accepts (the spec gives the
 * importer no rejection rule); hardened rejects.
 */
describe("GAP-20 strictCxfValidation: profile split", () => {
  const cases: [string, Mutator][] = [
    ["identifier longer than 64 bytes (CXF §1.3)", (d) => void (item(d).id = bytes(65, 9))],
    ["duplicate identifier within an Account (CXF §1.3)", (d) => void (account(d).collections[0]!.id = item(d).id)],
    ["LinkedItem reference longer than 64 bytes", (d) => void (account(d).collections[0]!.items[0]!.item = bytes(65))],
    ["empty optional array present (CXF §2.1.2)", (d) => void (item(d).tags = [])],
    ["empty optional subCollections present", (d) => void (account(d).collections[0]!.subCollections = [])],
    ["unsupported CXF major version (CXF §3.1)", (d) => void (d.version.major = 2)],
    ["key is not PKCS#8 DER (CXF §3.3.12)", (d) => void (passkey(d).key = bytes(32))],
    ["padded b64url", (d) => void (passkey(d).credentialId = "AQEBAQEBAQEBAQEBAQEBAQ==")],
    ["non-canonical b64url trailing bits", (d) => void (passkey(d).credentialId = "AQEBAQEBAQEBAQEBAQEBAR")],
    [
      "hmac credential not 32 bytes (CXF §3.3.12.3 SHOULD)",
      (d) =>
        void ((passkey(d).fido2Extensions as { hmacCredentials: { credWithUV: string } }).hmacCredentials.credWithUV =
          bytes(16)),
    ],
  ];

  it.each(cases)("%s: spec-minimal accepts, hardened rejects", (_name, fn) => {
    const doc = mutate(fn);
    expect(() => parseCxfHeader(doc, specMinimal)).not.toThrow();
    expect(() => parseCxfHeader(doc, hardened)).toThrow(/GAP-20/);
  });

  it("accepts a future minor version in both profiles (CXF §3.1.1 additive changes)", () => {
    const doc = mutate((d) => void (d.version.minor = 7));
    expect(() => parseCxfHeader(doc, specMinimal)).not.toThrow();
    expect(() => parseCxfHeader(doc, hardened)).not.toThrow();
  });
});

describe("serialisation (CXF §2.1.2, both profiles)", () => {
  it("omits empty optional arrays (MUST) and keeps empty required arrays (MUST)", () => {
    const doc = mutate((d) => {
      item(d).tags = [];
      item(d).extensions = [];
      account(d).extensions = [];
      account(d).collections[0]!.subCollections = [{ id: bytes(16, 8), title: "Sub", items: [], extensions: [] }];
    });
    const out = normaliseCxfHeader(parseCxfHeader(doc, specMinimal));
    const outItem = item(out);
    expect(outItem).not.toHaveProperty("tags");
    expect(outItem).not.toHaveProperty("extensions");
    expect(account(out)).not.toHaveProperty("extensions");
    const sub = account(out).collections[0]!.subCollections![0]!;
    expect(sub).not.toHaveProperty("extensions");
    expect(sub.items).toEqual([]);
    // A normalised document satisfies the strict producer checks.
    expect(() => parseCxfHeader(out, hardened)).not.toThrow();
  });
});
