/**
 * `pnpm docs:traceability`: regenerate the Markdown and LaTeX views of
 * docs/standards-traceability.json.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { loadTraceability, MD_PATH, renderLatex, renderMarkdown, summaryCounts, TEX_PATH } from "./traceability.js";

const record = loadTraceability();
for (const [path, text] of [
  [MD_PATH, renderMarkdown(record)],
  [TEX_PATH, renderLatex(record)],
] as const) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  console.log(`wrote ${path}`);
}
const c = summaryCounts(record);
console.log(`${c.entries} entries, ${c.citations} citations (${c.sectionToVerify} section to verify)`);
