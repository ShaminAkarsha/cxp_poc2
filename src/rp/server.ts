/**
 * HTTP front end for the demo RP (Express 5). Binds to loopback only
 * (README §9 rule 6: no network egress beyond loopback).
 */
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express, { type NextFunction, type Request, type Response } from "express";
import { DemoRelyingParty, RelyingPartyError } from "./relying-party.js";

export const LOOPBACK_HOST = "127.0.0.1";

export function createRpApp(rp: DemoRelyingParty): express.Express {
  const app = express();
  app.use(express.json({ limit: "64kb" }));

  app.get("/healthz", (_req, res) => {
    res.json({ ok: true, rpId: rp.config.rpId, origin: rp.config.origin });
  });

  app.post("/webauthn/register/options", async (req, res) => {
    const { username, displayName } = req.body as { username?: unknown; displayName?: unknown };
    if (typeof username !== "string" || username === "") throw new RelyingPartyError("username required");
    res.json(await rp.registrationOptions(username, typeof displayName === "string" ? displayName : username));
  });

  app.post("/webauthn/register/verify", async (req, res) => {
    const { username, response } = req.body as { username?: unknown; response?: unknown };
    if (typeof username !== "string") throw new RelyingPartyError("username required");
    const credential = await rp.verifyRegistration(username, response as never);
    res.json({ verified: true, credentialId: credential.id, backedUp: credential.backedUp });
  });

  app.post("/webauthn/login/options", async (req, res) => {
    const { username } = (req.body ?? {}) as { username?: unknown };
    res.json(await rp.authenticationOptions(typeof username === "string" ? username : undefined));
  });

  app.post("/webauthn/login/verify", async (req, res) => {
    const { response } = req.body as { response?: unknown };
    const result = await rp.verifyAuthentication(response as never);
    res.json({
      verified: true,
      username: result.username,
      credentialId: result.credential.id,
      counter: result.credential.counter,
    });
  });

  // Express 5 forwards rejected promises from async handlers here.
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    void _next;
    const status = err instanceof RelyingPartyError ? 400 : 500;
    res.status(status).json({ verified: false, error: err instanceof Error ? err.message : String(err) });
  });

  return app;
}

export interface RunningRp {
  readonly rp: DemoRelyingParty;
  readonly server: Server;
  /** Base URL to send requests to (loopback address). */
  readonly url: string;
  close(): Promise<void>;
}

/**
 * Start the demo RP on 127.0.0.1. The WebAuthn origin is
 * `http://localhost:<port>` with RP ID `localhost` (a secure context).
 */
export async function startDemoRp(options: { port?: number; rpName?: string } = {}): Promise<RunningRp> {
  const server = createServer();
  server.listen(options.port ?? 0, LOOPBACK_HOST);
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;

  const rp = new DemoRelyingParty({
    rpId: "localhost",
    rpName: options.rpName ?? "CXP PoC Demo RP",
    origin: `http://localhost:${port}`,
  });
  server.on("request", createRpApp(rp));

  return {
    rp,
    server,
    url: `http://${LOOPBACK_HOST}:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
