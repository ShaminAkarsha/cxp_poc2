/**
 * Run the demo RP on its own: `pnpm rp` (default port 3000, loopback only).
 */
import { startDemoRp } from "./server.js";

const port = Number(process.env.RP_PORT ?? 3000);
const running = await startDemoRp({ port });
console.log(`demo RP on ${running.url} (WebAuthn origin ${running.rp.config.origin}); Ctrl+C to stop`);

process.on("SIGINT", () => {
  void running.close().then(() => process.exit(0));
});
