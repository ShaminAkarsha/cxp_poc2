/**
 * `pnpm dashboard` — serve the M8 dashboard on 127.0.0.1 (DASHBOARD_PORT, default 4000).
 */
import { startDashboard } from "./server.js";

const dashboard = await startDashboard(Number(process.env.DASHBOARD_PORT ?? 4000));
console.log(`CXP PoC dashboard: ${dashboard.url}  (loopback only; Ctrl+C to stop)`);
process.on("SIGINT", () => {
  void dashboard.close().then(() => process.exit(0));
});
