/**
 * Standards traceability record: loader and renderers.
 * docs/standards-traceability.json is the single source of truth; the
 * Markdown and LaTeX views are generated from it (scripts/build-traceability.ts)
 * and checked for drift by test/docs/standards-traceability.test.ts.
 */
import { readFileSync } from "node:fs";

export const JSON_PATH = "docs/standards-traceability.json";
export const MD_PATH = "docs/standards-traceability.md";
export const TEX_PATH = "report/standards-traceability.tex";

export const STANDARD_TYPES = [
  "IETF RFC",
  "NIST",
  "FIDO",
  "W3C",
  "OWASP guidance",
  "Industry specification",
  "Academic literature",
  "none",
] as const;
export type StandardType = (typeof STANDARD_TYPES)[number];

export const STATUSES = ["both-profiles", "closed-by-flag", "closed-via-other-flags", "not-closed"] as const;
export type Status = (typeof STATUSES)[number];

export interface StandardRef {
  readonly document: string;
  readonly section: string | null;
  readonly verify: boolean;
  readonly type: StandardType;
  readonly role: string;
}

export interface Entry {
  readonly id: string;
  readonly group: "completion" | "hardening";
  readonly gap: string | null;
  readonly flag: string | null;
  readonly status: Status;
  readonly viaFlags?: readonly string[];
  readonly notClosedReason?: string;
  readonly title: string;
  readonly clause: string;
  readonly quote: string | null;
  readonly specSays: string;
  readonly choice?: string;
  readonly specMinimal?: string;
  readonly hardened?: string;
  readonly summary: string;
  readonly standards: readonly StandardRef[];
  readonly designDecision: string | null;
  readonly code: readonly string[];
  readonly tests: readonly string[];
}

export interface Traceability {
  readonly title: string;
  readonly updated: string;
  readonly specifications: Readonly<Record<string, string>>;
  readonly entries: readonly Entry[];
}

export function loadTraceability(path = JSON_PATH): Traceability {
  return JSON.parse(readFileSync(path, "utf8")) as Traceability;
}

/** "RFC 9180 §5.1", "RFC 1951", "NIST SP 800-63B-4 (section to verify)". */
export function formatStandard(s: StandardRef): string {
  const where = s.section === null ? "" : s.section.startsWith("Appendix") ? ` ${s.section}` : ` §${s.section}`;
  return `${s.document}${where}${s.verify ? " (section to verify)" : ""}`;
}

const STATUS_TITLES: Readonly<Record<Status, string>> = {
  "both-profiles": "Completion choices (identical in both profiles)",
  "closed-by-flag": "Closed in `hardened` by a policy flag",
  "closed-via-other-flags": "Closed in `hardened` through other flags (no dedicated flag)",
  "not-closed": "Not closed in the PoC",
};

export function summaryCounts(t: Traceability) {
  const byStatus = Object.fromEntries(STATUSES.map((s) => [s, t.entries.filter((e) => e.status === s).length])) as Record<Status, number>;
  const citationsByType = Object.fromEntries(STANDARD_TYPES.map((ty) => [ty, 0])) as Record<StandardType, number>;
  const entriesByType = Object.fromEntries(STANDARD_TYPES.map((ty) => [ty, 0])) as Record<StandardType, number>;
  for (const e of t.entries) {
    for (const s of e.standards) citationsByType[s.type] += 1;
    const types = new Set(e.standards.map((s) => s.type));
    if (types.size === 0) entriesByType.none += 1;
    for (const ty of types) entriesByType[ty] += 1;
  }
  return {
    entries: t.entries.length,
    completion: t.entries.filter((e) => e.group === "completion").length,
    hardening: t.entries.filter((e) => e.group === "hardening").length,
    byStatus,
    citations: t.entries.reduce((n, e) => n + e.standards.length, 0),
    citationsByType,
    entriesByType,
    designDecisions: t.entries.filter((e) => e.designDecision !== null).length,
    noExternalStandard: t.entries.filter((e) => e.standards.length === 0).length,
    sectionToVerify: t.entries.reduce((n, e) => n + e.standards.filter((s) => s.verify).length, 0),
  };
}

// ---------------------------------------------------------------- Markdown

const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

function mdEntry(e: Entry): string {
  const lines = [`### ${e.id}${e.gap && e.gap !== e.id ? ` (${e.gap})` : ""}: ${e.title}`, ""];
  lines.push(`- **Specification clause:** ${e.clause}`);
  lines.push(e.quote ? `- **Specification text:** "${e.quote}"` : `- **Specification text:** none (silent).`);
  lines.push(`- **What the specification leaves open:** ${e.specSays}`);
  if (e.flag) lines.push(`- **Policy flag:** \`${e.flag}\``);
  if (e.viaFlags) lines.push(`- **Closed through flags:** ${e.viaFlags.map((f) => `\`${f}\``).join(", ")}`);
  if (e.choice) lines.push(`- **Choice (both profiles):** ${e.choice}`);
  if (e.specMinimal) lines.push(`- **spec-minimal:** ${e.specMinimal}`);
  if (e.hardened) lines.push(`- **hardened:** ${e.hardened}`);
  if (e.notClosedReason) lines.push(`- **Not closed because:** ${e.notClosedReason}`);
  if (e.standards.length > 0) {
    lines.push(`- **Standards relied on:**`);
    for (const s of e.standards) lines.push(`  - ${formatStandard(s)} [${s.type}]: ${s.role}`);
  } else {
    lines.push(`- **Standards relied on:** none (no external standard applies).`);
  }
  if (e.designDecision) lines.push(`- **Design decision:** ${e.designDecision}`);
  lines.push(`- **Code:** ${e.code.length ? e.code.map((c) => `\`${c}\``).join(", ") : "none (no control implemented)"}`);
  lines.push(`- **Tests:** ${e.tests.map((c) => `\`${c}\``).join(", ")}`);
  return lines.join("\n");
}

function mdTable(entries: readonly Entry[]): string {
  const rows = entries.map(
    (e) =>
      `| ${e.id} | ${e.gap ?? "-"} | ${e.flag ? `\`${e.flag}\`` : "-"} | ${cell(e.clause)} | ${cell(e.summary)} | ${cell(e.standards.map(formatStandard).join("; ") || "Design decision")} |`,
  );
  return ["| ID | Gap | Flag | Specification clause | Choice / control | Standard |", "|---|---|---|---|---|---|", ...rows].join("\n");
}

export function renderMarkdown(t: Traceability): string {
  const c = summaryCounts(t);
  const completion = t.entries.filter((e) => e.group === "completion");
  const hardening = t.entries.filter((e) => e.group === "hardening");
  const out: string[] = [
    `# ${t.title}`,
    "",
    `<!-- Generated from ${JSON_PATH} by \`pnpm docs:traceability\`. Do not edit by hand. -->`,
    "",
    `Last updated ${t.updated}. Specifications: ${Object.entries(t.specifications).map(([k, v]) => `**${k}**: ${v}`).join("; ")}.`,
    "",
    "A citation marked *(section to verify)* names the right document, but the exact section has not been confirmed; check it before citing.",
    "",
    "## Summary",
    "",
    `- Entries: **${c.entries}** (${c.completion} completion choices, ${c.hardening} hardening entries).`,
    `- Hardening status: ${c.byStatus["closed-by-flag"]} closed by a flag, ${c.byStatus["closed-via-other-flags"]} closed through other flags, ${c.byStatus["not-closed"]} not closed in the PoC.`,
    `- Citations: **${c.citations}**, of which ${c.sectionToVerify} are marked *section to verify*. Entries with no external standard: ${c.noExternalStandard}; entries with a design decision recorded: ${c.designDecisions}.`,
    "",
    "| Standard type | Citations | Entries citing it |",
    "|---|---|---|",
    ...STANDARD_TYPES.map((ty) => `| ${ty} | ${ty === "none" ? "-" : c.citationsByType[ty]} | ${c.entriesByType[ty]} |`),
    "",
    "## 1. Completion choices",
    "",
    "Points where CXP/CXF is silent, ambiguous or dangling and the PoC had to choose something to work at all. The choice is the same in both profiles.",
    "",
    mdTable(completion),
    "",
    ...completion.flatMap((e) => [mdEntry(e), ""]),
    "## 2. Hardening controls",
    "",
  ];
  for (const status of ["closed-by-flag", "closed-via-other-flags", "not-closed"] as const) {
    const group = hardening.filter((e) => e.status === status);
    out.push(`### 2.${["closed-by-flag", "closed-via-other-flags", "not-closed"].indexOf(status) + 1} ${STATUS_TITLES[status]}`, "", mdTable(group), "");
    for (const e of group) out.push(mdEntry(e).replace(/^### /, "#### "), "");
  }
  return `${out.join("\n").trimEnd()}\n`;
}

// ------------------------------------------------------------------- LaTeX

/** Single pass, so replacement text is never escaped again. */
const TEX_CHARS: Readonly<Record<string, string>> = {
  "\\": "\\textbackslash{}",
  "&": "\\&",
  "%": "\\%",
  $: "\\$",
  "#": "\\#",
  _: "\\_",
  "{": "\\{",
  "}": "\\}",
  "~": "\\textasciitilde{}",
  "^": "\\textasciicircum{}",
  "§": "\\S{}",
  "—": "---",
  "–": "--",
  "→": "$\\rightarrow$",
  "≤": "$\\leq$",
  "<": "\\textless{}",
  ">": "\\textgreater{}",
  '"': "''",
};

export function texEscape(s: string): string {
  return [...s].map((ch) => TEX_CHARS[ch] ?? ch).join("");
}

function texRow(e: Entry): string {
  const standard = e.standards.length ? e.standards.map(formatStandard).join("; ") : "Design decision";
  const gap = e.gap ?? "--";
  const control = texEscape(e.summary) + (e.flag ? ` (\\texttt{${texEscape(e.flag)}})` : "");
  return `${texEscape(e.id)} & ${texEscape(gap)} & ${texEscape(e.clause)} & ${control} & ${texEscape(standard)} \\\\`;
}

export function renderLatex(t: Traceability): string {
  const header = [
    "\\toprule",
    "\\textbf{ID} & \\textbf{Gap} & \\textbf{Specification clause} & \\textbf{Choice / control} & \\textbf{Standard} \\\\",
    "\\midrule",
  ];
  const section = (title: string, entries: readonly Entry[]) => [
    `\\multicolumn{5}{l}{\\textit{${texEscape(title)}}} \\\\`,
    "\\midrule",
    ...entries.map(texRow),
    "\\midrule",
  ];
  const hardening = t.entries.filter((e) => e.group === "hardening");
  const body = [
    ...section("Completion choices (identical in both profiles)", t.entries.filter((e) => e.group === "completion")),
    ...section("Hardening controls: closed by a policy flag", hardening.filter((e) => e.status === "closed-by-flag")),
    ...section("Hardening controls: closed through other flags", hardening.filter((e) => e.status === "closed-via-other-flags")),
    ...section("Not closed in the PoC", hardening.filter((e) => e.status === "not-closed")),
  ];
  body[body.length - 1] = "\\bottomrule";
  return [
    `% Generated from ${JSON_PATH} by \`pnpm docs:traceability\`. Do not edit by hand.`,
    "% Requires \\usepackage{longtable,booktabs,array} in the preamble.",
    "% Citations marked (section to verify) must be checked before submission.",
    "{\\footnotesize",
    "\\begin{longtable}{@{}>{\\raggedright\\arraybackslash}p{1.25cm}>{\\raggedright\\arraybackslash}p{1.15cm}>{\\raggedright\\arraybackslash}p{2.6cm}>{\\raggedright\\arraybackslash}p{4.6cm}>{\\raggedright\\arraybackslash}p{4.1cm}@{}}",
    "\\caption{Standards relied on to complete and harden the CXP/CXF implementation}\\label{tab:standards-traceability}\\\\",
    ...header,
    "\\endfirsthead",
    ...header,
    "\\endhead",
    "\\midrule",
    "\\multicolumn{5}{r}{\\textit{continued on next page}} \\\\",
    "\\endfoot",
    "\\endlastfoot",
    ...body,
    "\\end{longtable}",
    "}",
    "",
  ].join("\n");
}
