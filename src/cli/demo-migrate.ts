/**
 * M4 demo: Provider A -> Provider B through a real response mode.
 *
 *   pnpm demo:migrate [--mode indirect|direct] [--profile spec-minimal|hardened]
 *
 * indirect: files are written under ./out/indirect/ so you can open them.
 * direct:   the exporter serves the request over HTTP on 127.0.0.1.
 */
import { join } from "node:path";
import { encodeB64url } from "../cxf/index.js";
import { resolvePolicy } from "../policy/index.js";
import { SoftwareAuthenticator } from "../provider/authenticator.js";
import { importDirect, startExporterService } from "../provider/direct.js";
import { ExportingProvider } from "../provider/exporter.js";
import { ImportingProvider } from "../provider/importer.js";
import { Vault } from "../provider/vault.js";

const policy = resolvePolicy();
const modeArg = process.argv.find((a) => a.startsWith("--mode="))?.slice(7) ?? process.argv[process.argv.indexOf("--mode") + 1];
const mode = modeArg === "direct" ? "direct" : "indirect";

const vaultA = new Vault();
const authA = new SoftwareAuthenticator(vaultA);
for (const [user, fill] of [["alice", 2], ["alice.work", 3]] as const) {
  authA.create(
    {
      rp: { id: "rp.example", name: "Example RP" },
      user: { id: encodeB64url(new Uint8Array(32).fill(fill)), name: user, displayName: user },
      challenge: encodeB64url(new Uint8Array(32).fill(1)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    },
    "https://rp.example",
  );
}
const exporter = new ExportingProvider({
  rpId: "provider-a.example",
  displayName: "Provider A",
  vault: vaultA,
  policy,
  account: { username: "alice", email: "alice@example.test" },
});
const vaultB = new Vault();
const importer = new ImportingProvider({ rpId: "provider-b.example", vault: vaultB, policy });

console.log(`profile: ${policy.profile}, mode: ${mode}`);
console.log(`Provider A holds ${vaultA.size} passkeys; Provider B holds ${vaultB.size}.\n`);

if (mode === "indirect") {
  const dir = join(process.cwd(), "out", "indirect");
  const requestPath = await importer.writeRequestFile(dir);
  console.log(`1. Provider B wrote the Export Request file:   ${requestPath}`);
  console.log("   (the user now carries this file to Provider A — nothing protects it: GAP-06)");
  const { responsePath, report } = await exporter.exportToFile(requestPath, dir);
  console.log("2. Provider A exported with NO approval step (GAP-29) and wrote:");
  console.log(`   ${responsePath}`);
  console.log("   export report:", report);
  const imported = await importer.importResponseFile(responsePath);
  console.log("3. Provider B imported the response file:", imported);
  console.log("   Both files are still on disk (GAP-31).");
} else {
  const service = await startExporterService(exporter);
  try {
    console.log(`1. Provider A serves direct-mode exports on ${service.url} (plain HTTP, GAP-19)`);
    const imported = await importDirect(importer, service.url);
    console.log("2. Provider B sent the request and imported the reply:", imported);
  } finally {
    await service.close();
  }
}

console.log(`\nProvider B now holds ${vaultB.size} passkeys (signature counters: ${vaultB.list().map((r) => r.signCount).join(", ")}).`);
console.log(`Provider A still holds ${vaultA.size}: the source copy is not destroyed (GAP-15).`);
