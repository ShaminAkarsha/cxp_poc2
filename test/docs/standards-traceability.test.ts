/**
 * The standards traceability record (docs/standards-traceability.json) must
 * cover every policy flag and every Gap Register entry, point at code and
 * tests that exist, and match its generated Markdown and LaTeX views.
 */
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { GAPS_WITHOUT_FLAG, POLICY_FLAG_NAMES, POLICY_FLAGS } from "../../src/policy/index.js";
import {
  loadTraceability,
  MD_PATH,
  renderLatex,
  renderMarkdown,
  STANDARD_TYPES,
  STATUSES,
  TEX_PATH,
  texEscape,
} from "../../scripts/traceability.js";

const record = loadTraceability();
const readme = readFileSync("README.md", "utf8");
const registerGaps = [...readme.matchAll(/^\| (GAP-\d{2}) \|/gm)].map((m) => m[1] ?? "");
const flagNames = new Set<string>(POLICY_FLAG_NAMES);

describe("standards traceability record", () => {
  it("has unique entry IDs", () => {
    const ids = record.entries.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("covers every policy flag exactly once, under the GAP the flag closes", () => {
    for (const flag of POLICY_FLAG_NAMES) {
      const entries = record.entries.filter((e) => e.flag === flag);
      expect(entries, `flag ${flag}`).toHaveLength(1);
      expect(entries[0]?.gap, `flag ${flag}`).toBe(POLICY_FLAGS[flag].gap);
      expect(entries[0]?.status).toBe("closed-by-flag");
    }
    for (const e of record.entries) if (e.flag !== null) expect(flagNames.has(e.flag), `${e.id} names unknown flag ${e.flag}`).toBe(true);
  });

  it("covers every Gap Register entry exactly once, and nothing else", () => {
    expect(registerGaps.length).toBeGreaterThan(0);
    for (const gap of registerGaps) expect(record.entries.filter((e) => e.gap === gap), gap).toHaveLength(1);
    for (const e of record.entries) if (e.gap !== null) expect(registerGaps, `${e.id}`).toContain(e.gap);
  });

  it("marks every flagless GAP as completion, closed through other flags, or not closed (with a reason)", () => {
    for (const gap of Object.keys(GAPS_WITHOUT_FLAG)) {
      const e = record.entries.find((x) => x.gap === gap);
      expect(e, gap).toBeDefined();
      expect(e?.flag, gap).toBeNull();
      expect(["both-profiles", "closed-via-other-flags", "not-closed"]).toContain(e?.status);
      if (e?.status === "not-closed") expect(e.notClosedReason, gap).toBeTruthy();
      if (e?.status === "closed-via-other-flags") {
        expect(e.viaFlags?.length, gap).toBeGreaterThan(0);
        for (const f of e.viaFlags ?? []) expect(flagNames.has(f), `${gap} via ${f}`).toBe(true);
      }
    }
  });

  it("records the required fields for each kind of entry", () => {
    for (const e of record.entries) {
      expect(STATUSES, e.id).toContain(e.status);
      expect(e.clause && e.specSays && e.summary, e.id).toBeTruthy();
      if (e.group === "completion") expect(e.choice, `${e.id} choice`).toBeTruthy();
      else expect(e.specMinimal && e.hardened, `${e.id} profiles`).toBeTruthy();
      // An entry without an external standard must say why (design decision).
      if (e.standards.length === 0) expect(e.designDecision, `${e.id} design decision`).toBeTruthy();
      for (const s of e.standards) {
        expect(STANDARD_TYPES, `${e.id} ${s.document}`).toContain(s.type);
        expect(s.document && s.role, e.id).toBeTruthy();
      }
    }
  });

  it("points at code lines and tests that exist", () => {
    for (const e of record.entries) {
      if (e.status !== "not-closed") expect(e.code.length, `${e.id} code`).toBeGreaterThan(0);
      expect(e.tests.length, `${e.id} tests`).toBeGreaterThan(0);
      for (const loc of e.code) {
        const [file, line] = [loc.slice(0, loc.lastIndexOf(":")), Number(loc.slice(loc.lastIndexOf(":") + 1))];
        expect(existsSync(file), `${e.id} ${loc}`).toBe(true);
        const text = readFileSync(file, "utf8").split("\n")[line - 1];
        expect(text?.trim(), `${e.id} ${loc} is blank or past EOF`).toBeTruthy();
      }
      for (const t of e.tests) expect(existsSync(t), `${e.id} ${t}`).toBe(true);
    }
  });

  it("matches its generated Markdown and LaTeX views (run pnpm docs:traceability)", () => {
    expect(readFileSync(MD_PATH, "utf8")).toBe(renderMarkdown(record));
    const tex = readFileSync(TEX_PATH, "utf8");
    expect(tex).toBe(renderLatex(record));
    const nonAscii = [...tex].filter((ch) => ch !== "\n" && ch !== "\t" && (ch < " " || ch > "~"));
    expect(nonAscii, "LaTeX output must be plain ASCII").toEqual([]);
  });
});

describe("LaTeX escaping", () => {
  it("escapes every LaTeX special character and the symbols the record uses", () => {
    expect(texEscape("a & b % c $ d # e _ f { g } h ~ i ^ j \\ k")).toBe(
      "a \\& b \\% c \\$ d \\# e \\_ f \\{ g \\} h \\textasciitilde{} i \\textasciicircum{} j \\textbackslash{} k",
    );
    expect(texEscape("§3.2 — x → y ≤ z <a>")).toBe("\\S{}3.2 --- x $\\rightarrow$ y $\\leq$ z \\textless{}a\\textgreater{}");
  });
});
