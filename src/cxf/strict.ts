/**
 * GAP-20: checks that a CXF document honours the MUSTs CXF places on its
 * producer. CXF never tells an importer to reject a document that breaks
 * them, so these run only when `strictCxfValidation` is enabled (hardened).
 * The exporter in this PoC produces conformant documents in both profiles.
 */
import { createPrivateKey } from "node:crypto";
import { b64urlByteLength, decodeB64url, isCanonicalB64url } from "./b64url.js";
import { isPasskey, type Collection, type Header } from "./schema.js";

/** CXF §1.3 (MUST) identifiers have a maximum of 64 bytes. */
export const MAX_IDENTIFIER_BYTES = 64;

/** CXF §3.1.1: the only published major version. */
export const SUPPORTED_MAJOR_VERSION = 1;

/** CXF §3.3.12.3 (SHOULD) 32-byte hmac credentials; CTAP 2.1 CredRandom. */
export const HMAC_CREDENTIAL_BYTES = 32;

export interface StrictViolation {
  readonly path: string;
  readonly rule: string;
}

export function collectStrictViolations(header: Header): StrictViolation[] {
  const violations: StrictViolation[] = [];
  const report = (path: string, rule: string) => violations.push({ path, rule });

  const checkB64 = (path: string, value: string | undefined) => {
    if (value !== undefined && !isCanonicalB64url(value)) {
      report(path, "b64url must be unpadded canonical base64url (RFC 4648 §3.5, §5)");
    }
  };
  const checkOptionalArray = (path: string, value: readonly unknown[] | undefined) => {
    // CXF §2.1.2 (MUST) an optional array MUST NOT be present when empty.
    if (value?.length === 0) report(path, "optional array must be absent when empty (CXF §2.1.2)");
  };

  // CXF §3.1 (MUST) version corresponds to a published level of CXF.
  if (header.version.major !== SUPPORTED_MAJOR_VERSION) {
    report("$.version.major", `unsupported CXF major version (expected ${SUPPORTED_MAJOR_VERSION})`);
  }

  header.accounts.forEach((account, a) => {
    const ap = `$.accounts[${a}]`;
    // CXF §1.3 (MUST) identifiers unique for a given exchanged Account, ≤ 64 bytes.
    const seen = new Map<string, string>();
    const checkId = (path: string, id: string) => {
      checkB64(path, id);
      if (b64urlByteLength(id) > MAX_IDENTIFIER_BYTES) {
        report(path, `identifier exceeds ${MAX_IDENTIFIER_BYTES} bytes (CXF §1.3)`);
      }
      const canonical = Buffer.from(decodeB64url(id)).toString("hex");
      const previous = seen.get(canonical);
      if (previous !== undefined) report(path, `identifier duplicates ${previous} (CXF §1.3)`);
      else seen.set(canonical, path);
    };

    checkId(`${ap}.id`, account.id);
    checkOptionalArray(`${ap}.extensions`, account.extensions);

    const walkCollection = (collection: Collection, cp: string) => {
      checkId(`${cp}.id`, collection.id);
      collection.items.forEach((linked, l) => {
        const lp = `${cp}.items[${l}]`;
        checkB64(`${lp}.item`, linked.item);
        checkB64(`${lp}.account`, linked.account);
        if (b64urlByteLength(linked.item) > MAX_IDENTIFIER_BYTES) {
          report(`${lp}.item`, `identifier exceeds ${MAX_IDENTIFIER_BYTES} bytes (CXF §1.3)`);
        }
      });
      checkOptionalArray(`${cp}.subCollections`, collection.subCollections);
      checkOptionalArray(`${cp}.extensions`, collection.extensions);
      collection.subCollections?.forEach((sub, s) => walkCollection(sub, `${cp}.subCollections[${s}]`));
    };
    account.collections.forEach((c, i) => walkCollection(c, `${ap}.collections[${i}]`));

    account.items.forEach((item, i) => {
      const ip = `${ap}.items[${i}]`;
      checkId(`${ip}.id`, item.id);
      checkOptionalArray(`${ip}.tags`, item.tags);
      checkOptionalArray(`${ip}.extensions`, item.extensions);
      item.scope?.androidApps.forEach((app, k) =>
        checkB64(`${ip}.scope.androidApps[${k}].certificate.fingerprint`, app.certificate?.fingerprint),
      );

      item.credentials.forEach((credential, c) => {
        if (!isPasskey(credential)) return;
        const pp = `${ip}.credentials[${c}]`;
        checkB64(`${pp}.credentialId`, credential.credentialId);
        checkB64(`${pp}.userHandle`, credential.userHandle);
        checkB64(`${pp}.key`, credential.key);
        // CXF §3.3.12 (MUST) key is a PKCS#8 ASN.1 DER byte string.
        if (!isPkcs8Der(credential.key)) report(`${pp}.key`, "key is not PKCS#8 DER (CXF §3.3.12)");

        const ext = credential.fido2Extensions;
        if (ext === undefined) return;
        checkB64(`${pp}.fido2Extensions.credBlob`, ext.credBlob);
        checkB64(`${pp}.fido2Extensions.largeBlob.data`, ext.largeBlob?.data);
        const hmac = ext.hmacCredentials;
        if (hmac !== undefined) {
          for (const field of ["credWithUV", "credWithoutUV"] as const) {
            const path = `${pp}.fido2Extensions.hmacCredentials.${field}`;
            checkB64(path, hmac[field]);
            if (b64urlByteLength(hmac[field]) !== HMAC_CREDENTIAL_BYTES) {
              report(path, `hmac credential must be ${HMAC_CREDENTIAL_BYTES} bytes (CXF §3.3.12.3 SHOULD)`);
            }
          }
        }
      });
    });
  });

  return violations;
}

function isPkcs8Der(b64: string): boolean {
  try {
    createPrivateKey({ key: Buffer.from(b64, "base64url"), format: "der", type: "pkcs8" });
    return true;
  } catch {
    return false;
  }
}
