/** M8 dashboard page: self-contained (no external assets). Text is inserted with textContent only. */
export const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CXP Migration Testbed</title>
<style>
  :root {
    --bg: #f7f7f5; --panel: #ffffff; --ink: #1d1d1b; --muted: #6b6b66; --line: #e3e2de;
    --ok: #1f7a4d; --bad: #b3261e; --accent: #2f5bd3; --chip: #eef1fb; --chip-ink: #2f4aa0;
    --min: #8a5a00; --min-bg: #fff4dc; --hard: #1f7a4d; --hard-bg: #e3f4ea;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #151515; --panel: #1e1e1e; --ink: #ecebe7; --muted: #9d9c97; --line: #2f2f2d;
      --ok: #5fcf95; --bad: #ff8a80; --accent: #8fb0ff; --chip: #263048; --chip-ink: #bfd0ff;
      --min: #ffc766; --min-bg: #3a2d10; --hard: #5fcf95; --hard-bg: #173a27;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink);
         font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 1180px; margin: 0 auto; padding: 28px 16px 64px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 16px; margin: 32px 0 12px; }
  p.lead { color: var(--muted); margin: 0 0 20px; max-width: 760px; }
  .controls { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 20px; }
  select, button { font: inherit; padding: 7px 12px; border-radius: 8px; border: 1px solid var(--line);
                   background: var(--panel); color: var(--ink); }
  button { background: var(--accent); color: #fff; border-color: transparent; cursor: pointer; font-weight: 600; }
  button:disabled { opacity: .6; cursor: progress; }
  .status { color: var(--muted); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px; min-width: 0; }
  .panel header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; gap: 8px; }
  .badge { font-size: 12px; font-weight: 700; padding: 2px 8px; border-radius: 999px; }
  .badge.min { color: var(--min); background: var(--min-bg); }
  .badge.hard { color: var(--hard); background: var(--hard-bg); }
  .result { font-weight: 700; }
  .result.ok { color: var(--ok); } .result.bad { color: var(--bad); }
  ol.steps { list-style: none; margin: 0; padding: 0; }
  ol.steps li { border-top: 1px solid var(--line); padding: 10px 0; }
  .title { font-weight: 600; display: flex; gap: 8px; }
  .mark.ok { color: var(--ok); } .mark.bad { color: var(--bad); }
  .facts { margin: 4px 0 0 22px; padding: 0; color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }
  .facts li { border: 0; padding: 1px 0; }
  .chips { margin: 6px 0 0 22px; display: flex; gap: 4px; flex-wrap: wrap; }
  .chip { font-size: 11px; background: var(--chip); color: var(--chip-ink); padding: 1px 6px; border-radius: 6px; }
  .prompts { margin-top: 10px; font-size: 13px; }
  .prompts code { overflow-wrap: anywhere; }
  .empty { color: var(--muted); font-size: 14px; padding: 12px 0; }
  .table-wrap { overflow-x: auto; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; }
  td.on { color: var(--ok); font-weight: 700; } td.off { color: var(--muted); }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
</style>
</head>
<body>
<main>
  <h1>CXP Migration Testbed</h1>
  <p class="lead">A passkey registered at a demo relying party with Provider A is migrated to Provider B with the
  FIDO Credential Exchange Protocol, then used to sign in. The same run is shown under the
  <strong>spec-minimal</strong> profile (every MUST, permissive otherwise) and the <strong>hardened</strong> profile
  (gaps closed with standard practice). Everything runs locally on 127.0.0.1.</p>

  <div class="controls">
    <label>Response mode
      <select id="mode"><option value="indirect">indirect (files)</option><option value="direct">direct (HTTP/TLS)</option></select>
    </label>
    <button id="run">Run both profiles</button>
    <span class="status" id="status" role="status"></span>
  </div>

  <div class="grid">
    <section class="panel" id="panel-spec-minimal"><header><span class="badge min">spec-minimal</span><span class="result"></span></header>
      <div class="empty">Not run yet.</div></section>
    <section class="panel" id="panel-hardened"><header><span class="badge hard">hardened</span><span class="result"></span></header>
      <div class="empty">Not run yet.</div></section>
  </div>

  <h2>Policy flags (one flag per GAP)</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>GAP</th><th>Flag</th><th>Hardened behaviour</th><th>spec-minimal</th><th>hardened</th></tr></thead>
    <tbody id="flags"></tbody>
  </table></div>

  <h2>GAPs without a flag</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>GAP</th><th>Reason</th></tr></thead>
    <tbody id="flagless"></tbody>
  </table></div>
</main>
<script>
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

  async function loadPolicy() {
    const data = await (await fetch("/api/policy")).json();
    const byProfile = Object.fromEntries(data.profiles.map((p) => [p.name, p.flags]));
    const body = document.getElementById("flags");
    for (const f of data.flags) {
      const tr = el("tr");
      tr.append(el("td", "", f.gap));
      const code = el("td"); code.append(el("code", "", f.name)); tr.append(code);
      tr.append(el("td", "", f.hardened));
      for (const p of ["spec-minimal", "hardened"]) {
        const on = byProfile[p][f.name];
        tr.append(el("td", on ? "on" : "off", on ? "on" : "off"));
      }
      body.append(tr);
    }
    const fl = document.getElementById("flagless");
    for (const g of data.flagless) { const tr = el("tr"); tr.append(el("td", "", g.gap), el("td", "", g.reason)); fl.append(tr); }
  }

  function render(profile, result) {
    const panel = document.getElementById("panel-" + profile);
    const res = panel.querySelector(".result");
    res.textContent = result.ok ? "completed" : "stopped";
    res.className = "result " + (result.ok ? "ok" : "bad");
    panel.querySelectorAll(":scope > :not(header)").forEach((n) => n.remove());
    const ol = el("ol", "steps");
    for (const s of result.steps) {
      const li = el("li");
      const t = el("div", "title");
      t.append(el("span", "mark " + (s.ok ? "ok" : "bad"), s.ok ? "✔" : "✘"), el("span", "", s.title));
      li.append(t);
      const facts = el("ul", "facts");
      for (const f of s.facts) facts.append(el("li", "", f));
      li.append(facts);
      if (s.gaps.length) { const c = el("div", "chips"); for (const g of s.gaps) c.append(el("span", "chip", g)); li.append(c); }
      ol.append(li);
    }
    panel.append(ol);
    const prompts = el("div", "prompts");
    prompts.append(el("strong", "", "User prompts: "));
    if (result.prompts.length === 0) prompts.append(el("span", "", "none (no approval or key confirmation)"));
    for (const p of result.prompts) { const d = el("div"); d.append(el("code", "", p)); prompts.append(d); }
    panel.append(prompts);
  }

  document.getElementById("run").addEventListener("click", async (ev) => {
    const button = ev.currentTarget, status = document.getElementById("status");
    const mode = document.getElementById("mode").value;
    button.disabled = true;
    try {
      for (const profile of ["spec-minimal", "hardened"]) {
        status.textContent = "Running " + profile + " (" + mode + ")…";
        const r = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ profile, mode }) });
        render(profile, await r.json());
      }
      status.textContent = "Done.";
    } catch (e) {
      status.textContent = "Error: " + e.message;
    } finally {
      button.disabled = false;
    }
  });

  loadPolicy();
</script>
</body>
</html>
`;
