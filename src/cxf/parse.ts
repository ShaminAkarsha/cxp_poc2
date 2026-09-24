import { isEnabled, type Policy } from "../policy/index.js";
import { HeaderSchema, type Header } from "./schema.js";
import { collectStrictViolations } from "./strict.js";

export interface CxfIssue {
  readonly path: string;
  readonly message: string;
}

export class CxfValidationError extends Error {
  override name = "CxfValidationError";
  constructor(
    message: string,
    readonly issues: readonly CxfIssue[],
  ) {
    super(`${message}:\n${issues.map((i) => `  ${i.path}: ${i.message}`).join("\n")}`);
  }
}

function formatPath(path: readonly PropertyKey[]): string {
  return "$" + path.map((p) => (typeof p === "number" ? `[${p}]` : `.${String(p)}`)).join("");
}

/**
 * Parse a CXF Header (CXF §3.1) from already-decoded JSON.
 *
 * Both profiles: structural validation (HeaderSchema). Unknown members are
 * ignored for processing and preserved (CXF §3.1.1 MUST).
 * GAP-20 (`strictCxfValidation`): also reject producer-MUST violations.
 */
export function parseCxfHeader(input: unknown, policy: Policy): Header {
  const result = HeaderSchema.safeParse(input);
  if (!result.success) {
    throw new CxfValidationError(
      "Malformed CXF document",
      result.error.issues.map((i) => ({ path: formatPath(i.path), message: i.message })),
    );
  }
  const header = result.data;

  if (isEnabled(policy, "strictCxfValidation")) {
    // GAP-20
    const violations = collectStrictViolations(header);
    if (violations.length > 0) {
      throw new CxfValidationError(
        "CXF document violates producer requirements (GAP-20)",
        violations.map((v) => ({ path: v.path, message: v.rule })),
      );
    }
  }
  return header;
}

export function parseCxfHeaderJson(json: string, policy: Policy): Header {
  let decoded: unknown;
  try {
    decoded = JSON.parse(json);
  } catch (err) {
    throw new CxfValidationError("CXF document is not valid JSON", [
      { path: "$", message: err instanceof Error ? err.message : String(err) },
    ]);
  }
  return parseCxfHeader(decoded, policy);
}
