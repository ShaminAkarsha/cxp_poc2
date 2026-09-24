/**
 * Policy flag registry. README §3: behavioural differences between profiles
 * are expressed only through these flags, and each flag maps to exactly one
 * GAP-xx entry in the README Gap Register (§6).
 *
 * A flag set to `true` means "close the gap" (hardened behaviour). The
 * `spec-minimal` profile sets every flag to `false`; see profiles.ts.
 */

export type GapId = `GAP-${string}`;

export interface PolicyFlagDefinition {
  readonly gap: GapId;
  /** What enabling the flag does (the hardened behaviour). */
  readonly hardened: string;
}

export const POLICY_FLAGS = {
  bindRequestChallenge: {
    gap: "GAP-01",
    hardened: "Random nonce + SHA-256(JCS(ExportRequest)) bound into HPKE info",
  },
  enforceMandatorySuite: {
    gap: "GAP-02",
    hardened: "Only DHKEM(X25519)/HKDF-SHA256/AES-256-GCM is accepted",
  },
  verifyNegotiatedSelection: {
    gap: "GAP-03",
    hardened: "Importer checks the exporter chose the first mutually supported entry",
  },
  rejectVersionDowngrade: {
    gap: "GAP-04",
    hardened: "Reject an ExportResponse version below the requested version",
  },
  requireSasConfirmation: {
    gap: "GAP-05",
    hardened: "User confirms a Short Authentication String over key fingerprints",
  },
  confirmRequestFileKey: {
    gap: "GAP-06",
    hardened: "Importer key in an indirect Export Request file is SAS-confirmed before export",
  },
  deriveFileKeysViaExport: {
    gap: "GAP-07",
    hardened: "Per-file keys from the HPKE secret export (label = file path), JWE dir/A256GCM",
  },
  randomizeFileNames: {
    gap: "GAP-08",
    hardened: "Random 128-bit archive file names; mapping only inside encrypted index",
  },
  bindFileAad: {
    gap: "GAP-09",
    hardened: "Per-file AAD = file path || request digest",
  },
  authenticateManifest: {
    gap: "GAP-10",
    hardened: "Archive carries an AEAD-bound manifest",
  },
  singleUseImporterKey: {
    gap: "GAP-11",
    hardened: "Ephemeral importer key per request, destroyed after first successful import",
  },
  enforceDecompressionLimits: {
    gap: "GAP-12",
    hardened: "Decompressed-size caps; uncompressedSize verified",
  },
  zeroizeKeyMaterial: {
    gap: "GAP-13",
    hardened: "Private keys kept in Uint8Array and zeroed after import (best effort)",
  },
  requireHpkeAuthMode: {
    gap: "GAP-14",
    hardened: "HPKE auth mode with an SAS-confirmed exporter key",
  },
  requireTls: {
    gap: "GAP-19",
    hardened: "Direct mode runs over TLS (loopback, test CA)",
  },
  strictCxfValidation: {
    gap: "GAP-20",
    hardened: "Importer rejects CXF documents that violate producer-side MUSTs",
  },
  enforceTimestampFreshness: {
    gap: "GAP-21",
    hardened: "Importer rejects CXF documents whose timestamp is outside a freshness window",
  },
  bindExporterIdentity: {
    gap: "GAP-22",
    hardened: "Header.exporterRpId must equal ExportResponse.exporter and the confirmed identity",
  },
  requireExportConsent: {
    gap: "GAP-29",
    hardened: "User sees importer, SAS, types and count, re-authenticates, and approves the exact request",
  },
  rejectConflictingImport: {
    gap: "GAP-30",
    hardened: "An imported credential never silently replaces an existing one",
  },
  secureExportFiles: {
    gap: "GAP-31",
    hardened: "Indirect-mode files are 0600 and removed after use",
  },
} as const satisfies Record<string, PolicyFlagDefinition>;

export type PolicyFlag = keyof typeof POLICY_FLAGS;

export const POLICY_FLAG_NAMES = Object.keys(POLICY_FLAGS) as readonly PolicyFlag[];

/**
 * Register entries that deliberately have no policy flag, with the reason.
 * Every GAP in the README must appear either in POLICY_FLAGS or here
 * (enforced by test/policy/policy.test.ts).
 */
export const GAPS_WITHOUT_FLAG: Readonly<Record<GapId, string>> = {
  "GAP-15": "Source-credential destruction is out of CXP scope; residual risk only",
  "GAP-16": "Spec-mandated (CXF §3.3.12.3 MUST); cannot be mitigated conformantly",
  "GAP-17": "Spec-mandated (CXF §3.3.12 MUST); cannot be mitigated conformantly",
  "GAP-18": "Hardened behaviour is realised by the GAP-08 flag (randomizeFileNames)",
  "GAP-23": "Editorial defect; both profiles use the only coherent reading",
  "GAP-24": "Both profiles use CXP version 0; affects A-05 design, not runtime behaviour",
  "GAP-25": "No conformant CXF field for BE/BS exists; both authenticators report BE=1, BS=1",
  "GAP-26": "CDDL/prose conflicts resolved by following the prose in both profiles",
  "GAP-27": "Both profiles apply DEFLATE to zip entries; inflation limits are GAP-12",
  "GAP-28": "Both profiles define correspondence as equal mode/kem/kdf/aead",
};
