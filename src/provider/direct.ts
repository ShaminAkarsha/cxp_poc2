/**
 * `direct` response mode (CXP §3.2.2): the importer submits the Export
 * Request over a transport the exporter provides, and the exporter MUST
 * return the Export Response over the same transport or an error (GAP-23).
 *
 * CXP defines no transport. This PoC uses JSON over HTTP on loopback:
 * plain HTTP in spec-minimal (GAP-19); TLS for hardened arrives in M7.
 */
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express, { type NextFunction, type Request, type Response } from "express";
import { CxpError, parseExportRequest, type ExportResponse } from "../cxp/index.js";
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
    const { response } = await exporter.respond(request);
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
  options: { port?: number } = {},
): Promise<RunningExporterService> {
  const server = createServer(createExporterApp(exporter));
  server.listen(options.port ?? 0, LOOPBACK_HOST);
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://${LOOPBACK_HOST}:${port}`,
    server,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

/** Send an Export Request over the direct transport and return the raw response body. */
export async function submitDirectRequest(exporterUrl: string, request: unknown): Promise<ExportResponse> {
  const res = await fetch(new URL(DIRECT_EXPORT_PATH, exporterUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  const body = (await res.json()) as unknown;
  if (!res.ok) throw new DirectModeError(`exporter returned ${res.status}: ${JSON.stringify(body)}`);
  return body as ExportResponse;
}

/** Importer side of a whole direct-mode exchange. */
export async function importDirect(importer: ImportingProvider, exporterUrl: string): Promise<ImportReport> {
  const request = await importer.createRequest("direct");
  return importer.importResponse(await submitDirectRequest(exporterUrl, request));
}
