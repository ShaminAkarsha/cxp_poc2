/**
 * M8: the demonstration walkthrough. Runs the complete story once and returns
 * structured steps for the CLI and the dashboard:
 * register at the RP with Provider A -> Export Request -> consent -> Export
 * Response -> import -> sign in with Provider B (and with A's retained copy).
 */
import { statSync, existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readZip } from "../crypto/archive.js";
import { createLoopbackTls } from "../crypto/test-ca.js";
import { parseExportRequestJson, parseExportResponseJson, requestFingerprint, type ExportRequest, type ExportResponse } from "../cxp/index.js";
import { decodeB64url } from "../cxf/index.js";
import { isEnabled, type Policy } from "../policy/index.js";
import { startExporterService, submitDirectRequest } from "../provider/direct.js";
import type { ImportReport } from "../provider/importer.js";
import { createWorld, type MigrationMode } from "./world.js";

export interface WalkthroughStep {
  readonly title: string;
  readonly ok: boolean;
  /** Short facts shown under the step. */
  readonly facts: readonly string[];
  /** GAP entries the step illustrates. */
  readonly gaps: readonly string[];
}

export interface WalkthroughResult {
  readonly profile: string;
  readonly mode: MigrationMode;
  readonly ok: boolean;
  readonly steps: readonly WalkthroughStep[];
  /** Prompts the simulated user saw (hardened). */
  readonly prompts: readonly string[];
}

const summariseRequest = (r: ExportRequest) => [
  `version ${r.version}, mode "${r.mode}", importer "${r.importer}" (claimed)`,
  `HPKE offered: ${r.hpke.map((h) => `${h.mode} kem=0x${h.kem.toString(16)} aead=0x${h.aead.toString(16)}`).join("; ")}`,
  r.challenge !== undefined ? "challenge: present (bound into HPKE info)" : "challenge: none",
  `request fingerprint: ${requestFingerprint(r)}`,
];

function summariseResponse(r: ExportResponse): string[] {
  const names = [...readZip(decodeB64url(r.payload)).keys()];
  return [
    `exporter "${r.exporter}", HPKE ${r.hpke.mode} kem=0x${r.hpke.kem.toString(16)} aead=0x${r.hpke.aead.toString(16)}`,
    `sender key: ${"senderKey" in r.hpke ? "present (auth mode)" : "none (base mode)"}`,
    `archive: ${names.length} files, e.g. ${names.filter((n) => n.includes("documents/"))[0] ?? "-"}`,
  ];
}

const mode8 = (path: string) => (statSync(path).mode & 0o777).toString(8).padStart(4, "0");

export async function runWalkthrough(policy: Policy, mode: MigrationMode): Promise<WalkthroughResult> {
  const world = await createWorld(policy);
  const steps: WalkthroughStep[] = [];
  const step = (title: string, ok: boolean, facts: string[], gaps: string[] = []) => steps.push({ title, ok, facts, gaps });
  const { exporter } = world.providerA;
  const { importer } = world.providerB;

  try {
    const reg = await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
    step("Alice registers a passkey at the RP with Provider A", reg.body.verified === true, [
      `RP ${world.rp.rp.config.rpId} at ${world.rpClient.origin}`,
      `credential ${String(reg.body.credentialId)}`,
    ]);
    const loginA = await world.rpClient.login(world.providerA.authenticator, "alice");
    step("Alice signs in with Provider A", loginA.body.verified === true, [`counter ${String(loginA.body.counter)}`], ["GAP-17"]);

    let request: ExportRequest | undefined;
    let response: ExportResponse | undefined;
    let report: ImportReport;
    const dir = await mkdtemp(join(tmpdir(), "cxp-walkthrough-"));
    try {
      if (mode === "indirect") {
        const requestPath = await importer.writeRequestFile(dir);
        request = parseExportRequestJson(await readFile(requestPath, "utf8"));
        step("Provider B writes the Export Request file", true, [...summariseRequest(request), `file mode ${mode8(requestPath)}`], [
          "GAP-01",
          "GAP-05",
          "GAP-06",
          "GAP-31",
        ]);
        const exported = await exporter.exportToFile(requestPath, dir);
        response = exported.response;
        step("Provider A exports", true, [
          isEnabled(policy, "requireExportConsent") ? "user was asked and approved (fingerprints matched)" : "no approval step",
          `${exported.report.exported} passkey(s) exported; file mode ${mode8(exported.responsePath)}`,
        ], ["GAP-29", "GAP-31"]);
        step("Export Response", true, summariseResponse(parseExportResponseJson(await readFile(exported.responsePath, "utf8"))), [
          "GAP-07",
          "GAP-08",
          "GAP-14",
        ]);
        report = await importer.importResponseFile(exported.responsePath);
        step("Provider B imports the response", report.imported.length > 0, [
          `imported ${report.imported.length}, skipped ${report.skipped.length}, replaced ${report.replaced.length}`,
          `files left on disk: ${existsSync(exported.responsePath) || existsSync(requestPath) ? "yes" : "no"}`,
        ], ["GAP-11", "GAP-31"]);
      } else {
        const tls = isEnabled(policy, "requireTls") ? await createLoopbackTls() : undefined;
        const service = await startExporterService(exporter, tls ? { tls } : {});
        try {
          request = await importer.createRequest("direct");
          step("Provider B creates the Export Request", true, summariseRequest(request), ["GAP-01", "GAP-05"]);
          step("Direct transport", true, [`${service.url} (${tls ? "TLS 1.3, pinned test CA" : "plain HTTP"})`], ["GAP-19"]);
          response = await submitDirectRequest(service.url, request, tls ? { caPem: tls.caPem } : {});
          step("Provider A exports and replies", true, [
            isEnabled(policy, "requireExportConsent") ? "user was asked and approved (fingerprints matched)" : "no approval step",
            ...summariseResponse(response),
          ], ["GAP-07", "GAP-14", "GAP-29"]);
          report = await importer.importResponse(response);
          step("Provider B imports the response", report.imported.length > 0, [
            `imported ${report.imported.length}, skipped ${report.skipped.length}, replaced ${report.replaced.length}`,
          ], ["GAP-11"]);
        } finally {
          await service.close();
        }
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }

    const loginB = await world.rpClient.login(world.providerB.authenticator, "alice");
    step("Alice signs in with Provider B (migrated passkey)", loginB.body.verified === true, [
      `same credential: ${String(loginB.body.credentialId === reg.body.credentialId)}`,
      `counter ${String(loginB.body.counter)} (CXF §3.3.12: zero, never incremented)`,
    ], ["GAP-17"]);
    const again = await world.rpClient.login(world.providerA.authenticator, "alice");
    step("Provider A's original copy still signs in", again.body.verified === true, [
      "the source copy is not destroyed and the RP cannot tell the two apart",
    ], ["GAP-15", "GAP-17", "GAP-25"]);

    return { profile: policy.profile, mode, ok: steps.every((s) => s.ok), steps, prompts: [...world.user.prompts] };
  } catch (err) {
    step("Walkthrough stopped", false, [err instanceof Error ? err.message : String(err)]);
    return { profile: policy.profile, mode, ok: false, steps, prompts: [...world.user.prompts] };
  } finally {
    await world.close();
  }
}
