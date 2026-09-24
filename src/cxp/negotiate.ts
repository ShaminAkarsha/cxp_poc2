/**
 * Exporter-side selection of HPKE parameters and archive algorithm.
 * Both lists in the request are in the importer's order of preference
 * (CXP §3.2), and "it is up to the Exporting Provider to select" a mutually
 * supported entry. An honest exporter takes the importer's first usable entry.
 */
import { HPKE_MODES, isSupportedSuite, type HpkeModeName } from "../crypto/hpke.js";
import { jweEncForAead } from "../crypto/jwe.js";
import { ARCHIVE_DEFLATE, type HpkeParameters } from "./schema.js";

export interface ExporterCapabilities {
  readonly hpkeModes: readonly HpkeModeName[];
  readonly archives: readonly string[];
}

/** spec-minimal: `base` mode (README §5); `auth` is added for hardened in M7 (GAP-14). */
export const DEFAULT_EXPORTER_CAPABILITIES: ExporterCapabilities = {
  hpkeModes: ["base"],
  archives: [ARCHIVE_DEFLATE],
};

function isModeName(mode: string): mode is HpkeModeName {
  return Object.hasOwn(HPKE_MODES, mode);
}

/**
 * The first request entry the exporter can use. Entries with an unknown mode,
 * KEM, KDF or AEAD are skipped (CXP §3.5.1 SHOULD ignore); so are entries
 * without a key where one is needed (CXP §3.2 MUST have an associated public
 * key) and AEADs with no JWE mapping (GAP-07).
 */
export function selectHpkeParameters(
  offered: readonly HpkeParameters[],
  capabilities: ExporterCapabilities = DEFAULT_EXPORTER_CAPABILITIES,
): HpkeParameters | undefined {
  return offered.find(
    (p) =>
      isModeName(p.mode) &&
      capabilities.hpkeModes.includes(p.mode) &&
      isSupportedSuite(p) &&
      jweEncForAead(p.aead) !== undefined &&
      p.key !== undefined,
  );
}

/** CXP §3.2 (MUST) the exporter ignores unknown archive values. */
export function selectArchive(
  offered: readonly string[],
  capabilities: ExporterCapabilities = DEFAULT_EXPORTER_CAPABILITIES,
): string | undefined {
  return offered.find((a) => capabilities.archives.includes(a));
}

/** GAP-28: parameters correspond when mode, KEM, KDF and AEAD are equal. */
export function correspondingEntry(
  offered: readonly HpkeParameters[],
  selected: HpkeParameters,
): HpkeParameters | undefined {
  return offered.find(
    (p) => p.mode === selected.mode && p.kem === selected.kem && p.kdf === selected.kdf && p.aead === selected.aead,
  );
}
