/**
 * GAP-19 (hardened): TLS material for the loopback `direct` transport — a
 * throwaway test CA and a server certificate for 127.0.0.1 / localhost,
 * generated in memory for each run. Never used beyond loopback.
 */
// @peculiar/x509 uses tsyringe, which needs the Reflect metadata polyfill loaded first.
import "reflect-metadata";
import { webcrypto } from "node:crypto";
import * as x509 from "@peculiar/x509";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALG = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;

export interface LoopbackTls {
  /** PEM of the test CA certificate: the client's only trust anchor. */
  readonly caPem: string;
  readonly certPem: string;
  readonly keyPem: string;
}

async function keyPair(): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as CryptoKeyPair;
}

function toPem(der: ArrayBuffer, label: string): string {
  const b64 = Buffer.from(der).toString("base64").replace(/.{64}/g, "$&\n");
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

export async function createLoopbackTls(validForSeconds = 3600): Promise<LoopbackTls> {
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(Date.now() + validForSeconds * 1000);

  const caKeys = await keyPair();
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=CXP PoC Test CA",
    notBefore,
    notAfter,
    keys: caKeys,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });

  const serverKeys = await keyPair();
  const server = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    subject: "CN=127.0.0.1",
    issuer: ca.subject,
    notBefore,
    notAfter,
    publicKey: serverKeys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.SubjectAlternativeNameExtension([
        { type: "ip", value: "127.0.0.1" },
        { type: "dns", value: "localhost" },
      ]),
    ],
  });

  const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", serverKeys.privateKey);
  return { caPem: ca.toString("pem"), certPem: server.toString("pem"), keyPem: toPem(pkcs8, "PRIVATE KEY") };
}
