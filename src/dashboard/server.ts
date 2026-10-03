/**
 * M8 dashboard: a single local page for supervisor demonstrations. Loopback
 * only, no external assets (README §9 rule 6).
 *
 *   GET  /            the page
 *   GET  /api/policy  profiles, flags and their GAP entries
 *   POST /api/run     { profile, mode } -> WalkthroughResult
 */
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { GAPS_WITHOUT_FLAG, getPolicy, isProfileName, POLICY_FLAG_NAMES, POLICY_FLAGS, PROFILE_NAMES } from "../policy/index.js";
import { runWalkthrough } from "../scenario/walkthrough.js";
import { DASHBOARD_HTML } from "./page.js";

export function createDashboardApp(): express.Express {
  const app = express();
  app.use(express.json({ limit: "4kb" }));

  app.get("/", (_req, res) => {
    res.type("html").set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'").send(DASHBOARD_HTML);
  });

  app.get("/api/policy", (_req, res) => {
    res.json({
      profiles: PROFILE_NAMES.map((p) => ({ name: p, flags: getPolicy(p).flags })),
      flags: POLICY_FLAG_NAMES.map((name) => ({ name, gap: POLICY_FLAGS[name].gap, hardened: POLICY_FLAGS[name].hardened })),
      flagless: Object.entries(GAPS_WITHOUT_FLAG).map(([gap, reason]) => ({ gap, reason })),
    });
  });

  // One walkthrough at a time: each run starts its own loopback services.
  let running: Promise<unknown> = Promise.resolve();
  app.post("/api/run", async (req, res) => {
    const { profile, mode } = (req.body ?? {}) as { profile?: unknown; mode?: unknown };
    if (typeof profile !== "string" || !isProfileName(profile) || (mode !== "direct" && mode !== "indirect")) {
      res.status(400).json({ error: "expected { profile: spec-minimal|hardened, mode: direct|indirect }" });
      return;
    }
    const run = running.then(() => runWalkthrough(getPolicy(profile), mode));
    running = run.catch(() => undefined);
    res.json(await run);
  });
  return app;
}

export interface RunningDashboard {
  readonly url: string;
  readonly server: Server;
  close(): Promise<void>;
}

export async function startDashboard(port = 0): Promise<RunningDashboard> {
  const server = createServer(createDashboardApp());
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${address.port}`,
    server,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
