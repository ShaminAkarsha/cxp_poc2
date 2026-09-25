/**
 * Hardened-profile bindings between the Export Request, the HPKE context and
 * what the user is shown.
 *
 * GAP-01: SHA-256 over the RFC 8785 canonical request is bound into HPKE
 *         `info` (RFC 9180 §5.1), so a response decrypts only for the exact
 *         request the importer sent.
 * GAP-05/06/14: keys are confirmed by the user through a 128-bit fingerprint.
 *         A short (e.g. 6-digit) code is not used: in indirect mode the
 *         request file is seen before it is substituted, so a matching short
 *         code could be searched for offline; short codes need a hash
 *         commitment (as ZRTP, RFC 6189, does), which a one-shot file cannot give.
 */
import { createHash, randomBytes } from "node:crypto";
import { calculateJwkThumbprint } from "jose";
import { canonicalize } from "../crypto/jcs.js";
import { encodeB64url } from "../cxf/b64url.js";
import { isEnabled, type Policy } from "../policy/index.js";
import type { ExportRequest } from "./schema.js";

/** Bytes of the request challenge (GAP-01). */
export const CHALLENGE_BYTES = 32;

export function newChallenge(): string {
  return encodeB64url(new Uint8Array(randomBytes(CHALLENGE_BYTES)));
}

/** SHA-256 of the RFC 8785 canonical form of the request. */
export function requestDigest(request: ExportRequest): Uint8Array<ArrayBuffer> {
  return new Uint8Array(createHash("sha256").update(canonicalize(request)).digest());
}

const INFO_LABEL = new TextEncoder().encode("CXP-v0 export request ");

/** HPKE `info`: empty in spec-minimal; label || request digest when GAP-01 is closed. */
export function hpkeInfo(policy: Policy, request: ExportRequest): Uint8Array {
  if (!isEnabled(policy, "bindRequestChallenge")) return new Uint8Array(0); // GAP-01 (spec-minimal)
  const digest = requestDigest(request);
  const info = new Uint8Array(INFO_LABEL.length + digest.length);
  info.set(INFO_LABEL);
  info.set(digest, INFO_LABEL.length);
  return info;
}

/** 128 bits as eight groups of four hex digits, e.g. "3f2a 9c01 …". */
function formatFingerprint(digest: Uint8Array): string {
  const hex = Buffer.from(digest.subarray(0, 16)).toString("hex");
  return (hex.match(/.{4}/g) ?? []).join(" ");
}

/**
 * Fingerprint of a whole request (its keys, importer, challenge, …). The
 * importer displays it for the request it created; the exporter displays it
 * for the request it received; the user checks that they match.
 */
export function requestFingerprint(request: ExportRequest): string {
  return formatFingerprint(requestDigest(request));
}

/** Fingerprint of a public key: RFC 7638 JWK thumbprint (SHA-256), 128 bits shown. */
export async function keyFingerprint(jwk: Record<string, unknown>): Promise<string> {
  const thumbprint = await calculateJwkThumbprint(jwk as Parameters<typeof calculateJwkThumbprint>[0], "sha256");
  return formatFingerprint(Buffer.from(thumbprint, "base64url"));
}
