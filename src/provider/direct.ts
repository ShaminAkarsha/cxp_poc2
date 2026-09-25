/**
 * `direct` response mode (CXP §3.2.2): the importer submits the Export
 * Request over a transport the exporter provides, and the exporter MUST
 * return the Export Response over the same transport or an error (GAP-23).
 *
 * CXP defines no transport. This PoC uses JSON over HTTP on loopback:
 * plain HTTP in spec-minimal (GAP-19); HTTPS with a pinned test CA when
 * `requireTls` is enabled.
 */
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import { createServer as createHttpsServer, request as httpsRequest } from "node:https";
import type { AddressInfo } from "node:net";
import express, { type NextFunction, type Request, type Response } from "express";
import type { LoopbackTls } from "../crypto/test-ca.js";
import { CxpError, parseExportRequest, type ExportResponse } from "../cxp/index.js";
import { isEnabled } from "../policy/index.js";
import type { ExportingProvider } from "./exporter.js";
import type { ImportingProvider, ImportReport } from "./importer.js";

export const DIRECT_EXPORT_PATH = "/cxp/export";
const LOOPBACK_HOST = "127.0.0.1";

export class DirectModeError extends Error {
  override name = "DirectModeError";
}

export function createExporterApp(exporter: ExportingProvider): express.Express {
  const app = express();
  app.use(express.json({ limit: "256kb" }));

  app.post(DIRECT_EXPORT_PATH, async (req, res) => {
    const request = parseExportRequest(req.body);
    // This transport serves direct mode only. An `indirect` request MUST be
    // answered on the filesystem and `self` is out of scope (README §5), so
    // both get an error over this transport.
    if (request.mode !== "direct") throw new DirectModeError(`mode "${request.mode}" is not served over direct transport`);
    const { response } = await exporter.respond(request, "direct");
    res.json(response);
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    void _next;
    const known = err instanceof CxpError || err instanceof DirectModeError || (err as { type?: string }).type === "entity.parse.failed";
    res.status(known ? 400 : 500).json({ error: err instanceof Error ? err.message : String(err) });
  });
  return app;
}

export interface RunningExporterService {
  readonly url: string;
  readonly server: Server;
  close(): Promise<void>;
}

export async function startExporterService(
  exporter: ExportingProvider,
  options: { port?: number; tls?: LoopbackTls } = {},
): Promise<RunningExporterService> {
  const app = createExporterApp(exporter);
  // GAP-19 (hardened): refuse to serve without TLS.
  if (isEnabled(exporter.config.policy, "requireTls") && options.tls === undefined) {
    throw new DirectModeError("TLS material is required for the direct transport (GAP-19)");
  }
  const server: Server = options.tls
    ? createHttpsServer({ cert: options.tls.certPem, key: options.tls.keyPem, minVersion: "TLSv1.3" }, app)
    : createServer(app);
  server.listen(options.port ?? 0, LOOPBACK_HOST);
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  return {
    url: `${options.tls ? "https" : "http"}://${LOOPBACK_HOST}:${port}`,
    server,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

export interface DirectClientOptions {
  /** PEM trust anchor for HTTPS; the system store is not used. */
  readonly caPem?: string;
}

function postHttps(url: URL, body: string, caPem: string): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      url,
      { method: "POST", ca: caPem, minVersion: "TLSv1.3", headers: { "content-type": "application/json" } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** Send an Export Request over the direct transport and return the raw response body. */
export async function submitDirectRequest(
  exporterUrl: string,
  request: unknown,
  options: DirectClientOptions = {},
): Promise<ExportResponse> {
  const url = new URL(DIRECT_EXPORT_PATH, exporterUrl);
  const body = JSON.stringify(request);
  let status: number;
  let text: string;
  if (url.protocol === "https:") {
    if (options.caPem === undefined) throw new DirectModeError("HTTPS needs a pinned CA");
    ({ status, text } = await postHttps(url, body, options.caPem));
  } else {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
    status = res.status;
    text = await res.text();
  }
  const parsed = JSON.parse(text) as unknown;
  if (status < 200 || status >= 300) throw new DirectModeError(`exporter returned ${status}: ${text}`);
  return parsed as ExportResponse;
}

/** Importer side of a whole direct-mode exchange. */
export async function importDirect(
  importer: ImportingProvider,
  exporterUrl: string,
  options: DirectClientOptions = {},
): Promise<ImportReport> {
  // GAP-19 (hardened): only over HTTPS with a pinned CA.
  if (isEnabled(importer.config.policy, "requireTls") && (!exporterUrl.startsWith("https:") || options.caPem === undefined)) {
    throw new DirectModeError("direct transport must use HTTPS with a pinned CA (GAP-19)");
  }
  const request = await importer.createRequest("direct");
  return importer.importResponse(await submitDirectRequest(exporterUrl, request, options));
}
