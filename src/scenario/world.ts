/**
 * The experimental world (README §4): demo RP + Provider A (exporter) +
 * Provider B (importer), wired together. Used by the end-to-end migration
 * (M5) and, later, by the attack scenarios (M6).
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Policy } from "../policy/index.js";
import { SoftwareAuthenticator } from "../provider/authenticator.js";
import { importDirect, startExporterService } from "../provider/direct.js";
import { ExportingProvider } from "../provider/exporter.js";
import { ImportingProvider, type ImportReport } from "../provider/importer.js";
import { Vault } from "../provider/vault.js";
import { RpHttpClient } from "../rp/client.js";
import { startDemoRp, type RunningRp } from "../rp/server.js";

export interface ProviderA {
  readonly vault: Vault;
  readonly authenticator: SoftwareAuthenticator;
  readonly exporter: ExportingProvider;
}

export interface ProviderB {
  readonly vault: Vault;
  readonly authenticator: SoftwareAuthenticator;
  readonly importer: ImportingProvider;
}

export interface World {
  readonly policy: Policy;
  readonly rp: RunningRp;
  /** Talks to the RP as a browser would, at the RP's WebAuthn origin. */
  readonly rpClient: RpHttpClient;
  readonly providerA: ProviderA;
  readonly providerB: ProviderB;
  close(): Promise<void>;
}

export async function createWorld(policy: Policy): Promise<World> {
  const rp = await startDemoRp();
  const vaultA = new Vault();
  const vaultB = new Vault();
  const providerA: ProviderA = {
    vault: vaultA,
    authenticator: new SoftwareAuthenticator(vaultA),
    exporter: new ExportingProvider({
      rpId: "provider-a.example",
      displayName: "Provider A",
      vault: vaultA,
      policy,
      account: { username: "alice", email: "alice@example.test" },
    }),
  };
  const providerB: ProviderB = {
    vault: vaultB,
    authenticator: new SoftwareAuthenticator(vaultB),
    importer: new ImportingProvider({ rpId: "provider-b.example", vault: vaultB, policy }),
  };
  return {
    policy,
    rp,
    rpClient: new RpHttpClient(rp.url, rp.rp.config.origin),
    providerA,
    providerB,
    close: () => rp.close(),
  };
}

export type MigrationMode = "direct" | "indirect";

/** Migrate everything Provider A holds to Provider B through a CXP response mode. */
export async function migrate(world: World, mode: MigrationMode, workDir?: string): Promise<ImportReport> {
  const { exporter } = world.providerA;
  const { importer } = world.providerB;
  if (mode === "direct") {
    const service = await startExporterService(exporter);
    try {
      return await importDirect(importer, service.url);
    } finally {
      await service.close();
    }
  }
  const dir = workDir ?? (await mkdtemp(join(tmpdir(), "cxp-indirect-")));
  try {
    const requestPath = await importer.writeRequestFile(dir);
    const { responsePath } = await exporter.exportToFile(requestPath, dir);
    return await importer.importResponseFile(responsePath);
  } finally {
    if (workDir === undefined) await rm(dir, { recursive: true, force: true });
  }
}
