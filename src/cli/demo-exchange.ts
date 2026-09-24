/**
 * M3 demo: the CXP messages at message level (no transport yet — M4).
 * Prints the Export Request the importer sends, what the exporter selects,
 * the Export Response, what is visible in the archive, and the decrypted CXF.
 *
 *   pnpm demo:exchange [--profile spec-minimal|hardened]
 */
import { readFileSync } from "node:fs";
import { readZip } from "../crypto/archive.js";
import {
  createExportRequest,
  createExportResponse,
  openExportResponse,
  parseExportRequestJson,
  selectArchive,
  selectHpkeParameters,
  serializeExportRequest,
  serializeExportResponse,
} from "../cxp/index.js";
import { decodeB64url, isPasskey, parseCxfHeader } from "../cxf/index.js";
import { resolvePolicy } from "../policy/index.js";

const policy = resolvePolicy();
const fixture: unknown = JSON.parse(
  readFileSync(new URL("../../test/fixtures/cxf-appendix-a.json", import.meta.url), "utf8"),
);
const exporterVault = parseCxfHeader(fixture, policy);

const section = (title: string) => console.log(`\n=== ${title} ${"=".repeat(Math.max(0, 60 - title.length))}`);
console.log(`profile: ${policy.profile} (hardened CXP behaviour is implemented in M7; M3 runs the spec-minimal path)`);

// 1. Importer creates the Export Request (CXP §3.2) and keeps its private keys.
const { request, keyring } = await createExportRequest({ importer: "provider-b.example", mode: "indirect" });
const requestFile = serializeExportRequest(request);
section("1. Export Request (importer -> exporter), as the JSON file of CXP §3.2.1");
console.log(JSON.stringify(JSON.parse(requestFile), null, 2));
console.log("\nNote: no challenge or nonce (GAP-01); `importer` is only a claim (GAP-05); the file has no integrity protection (GAP-06).");

// 2. Exporter reads the file and negotiates (CXP §3.2, §3.5.1).
const received = parseExportRequestJson(requestFile);
const hpke = selectHpkeParameters(received.hpke);
section("2. Exporter negotiation");
console.log("selected HPKE:", hpke && { mode: hpke.mode, kem: hpke.kem, kdf: hpke.kdf, aead: hpke.aead });
console.log("selected archive:", selectArchive(received.archive));

// 3. Exporter builds the Export Response (CXP §3.3).
const response = await createExportResponse({ request: received, header: exporterVault, exporter: "provider-a.example" });
section("3. Export Response (exporter -> importer)");
console.log(JSON.stringify({ ...response, payload: `${response.payload.slice(0, 60)}… (${response.payload.length} chars)` }, null, 2));

// 4. What a passive observer of the response sees without any key.
section("4. Visible to anyone holding the response (no key needed)");
for (const [name, data] of readZip(decodeB64url(response.payload))) console.log(`  ${name}  (${data.length} bytes)`);
console.log("File names are CXF Item IDs (GAP-08, GAP-18).");

// 5. Importer opens it with its private key.
const imported = await openExportResponse({
  request,
  response: JSON.parse(serializeExportResponse(response)),
  keyring,
  policy,
});
section("5. Importer decrypted the CXF document");
const items = imported.accounts.flatMap((a) => a.items);
console.log(`${imported.accounts.length} account(s), ${items.length} item(s) from ${imported.exporterRpId}`);
for (const item of items) {
  const passkey = item.credentials.find(isPasskey);
  if (passkey) console.log(`  passkey for rpId=${passkey.rpId}, user=${passkey.username}, key=${passkey.key.slice(0, 24)}…`);
}
