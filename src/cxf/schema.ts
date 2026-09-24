/**
 * Structural zod schemas for the CXF data model (CXF PS 2026-03-09).
 *
 * These schemas are applied in BOTH profiles and encode only what makes the
 * input a CXF document at all: required members present, JSON types correct,
 * b64url alphabet valid. Producer-side MUSTs that an importer is not told to
 * enforce (id length/uniqueness, empty optional arrays, PKCS#8 form, ...) are
 * checked separately in strict.ts under GAP-20.
 *
 * Objects are loose: CXF §3.1.1 (MUST) — participants ignore unknown fields.
 * Unknown members are kept so that a parsed document serialises back intact.
 *
 * Optional arrays carry no `.default([])`: the parsed value mirrors the input
 * and serialize.ts applies the CXF §2.1.2 encoding rule on output.
 */
import { z } from "zod";
import { isB64url } from "./b64url.js";

/** CXF §2.1 b64url. */
export const B64url = z.string().refine(isB64url, { message: "not RFC 4648 base64url" });

/** CDDL `uint .size 1`. */
const Uint8 = z.int().min(0).max(0xff);

/**
 * CDDL `uint .size 8`. JSON numbers above 2^53 - 1 cannot round-trip through
 * JavaScript, so the representable range is used.
 */
const Uint64 = z.int().min(0).max(Number.MAX_SAFE_INTEGER);

/** CDDL `uint` (unsized). */
const Uint = z.int().min(0).max(Number.MAX_SAFE_INTEGER);

/** CXF §3.5 (Extension = $Extension .within { name: tstr }). */
export const ExtensionSchema = z.looseObject({
  name: z.string(),
});

/** CXF §3.2.4.1.1. */
export const AndroidAppCertificateFingerprintSchema = z.looseObject({
  fingerprint: B64url,
  hashAlg: z.string(), // "sha256" / "sha512" / tstr
});

/** CXF §3.2.4.1. */
export const AndroidAppIdSchema = z.looseObject({
  bundleId: z.string(),
  certificate: AndroidAppCertificateFingerprintSchema.optional(),
  name: z.string().optional(),
});

/** CXF §3.2.4. `urls` SHOULD be RFC 3986 URIs, so any string is accepted. */
export const CredentialScopeSchema = z.looseObject({
  urls: z.array(z.string()),
  androidApps: z.array(AndroidAppIdSchema),
});

/** CXF §3.3.12.3. The algorithm is `Fido2HmacCredentialAlgorithm / tstr`. */
export const Fido2HmacCredentialsSchema = z.looseObject({
  algorithm: z.string(),
  credWithUV: B64url,
  credWithoutUV: B64url,
});

/** CXF §3.3.12.5. `uncompressedSize` is a claim; see GAP-12. */
export const Fido2LargeBlobSchema = z.looseObject({
  uncompressedSize: Uint,
  data: B64url,
});

/** CXF §3.3.12.2. */
export const Fido2ExtensionsSchema = z.looseObject({
  hmacCredentials: Fido2HmacCredentialsSchema.optional(),
  credBlob: B64url.optional(),
  largeBlob: Fido2LargeBlobSchema.optional(),
  payments: z.boolean().optional(),
});

/** CXF §3.3.12. */
export const PasskeySchema = z.looseObject({
  type: z.literal("passkey"), // CXF §3.3.12 (MUST) type present and equal to "passkey"
  credentialId: B64url,
  rpId: z.string(),
  username: z.string(),
  userDisplayName: z.string(),
  userHandle: B64url,
  key: B64url, // CXF §3.3.12 (MUST) PKCS#8 DER — form checked under GAP-20
  fido2Extensions: Fido2ExtensionsSchema.optional(),
});

/**
 * CXF §3.3: any other credential type. The PoC does not model non-passkey
 * types (README §5); they are kept opaque. CXF §3.3 lets importers store
 * unknown types "as a best effort".
 */
export const OtherCredentialSchema = z.looseObject({
  type: z.string().refine((t) => t !== "passkey", { message: "passkey must match PasskeySchema" }),
});

/** CXF §3.3 Credential = $Credential .within { type: CredentialType / tstr }. */
export const CredentialSchema = z.union([PasskeySchema, OtherCredentialSchema]);

/** CXF §3.2.3. */
export const ItemSchema = z.looseObject({
  id: B64url,
  creationAt: Uint64.optional(),
  modifiedAt: Uint64.optional(),
  title: z.string(),
  subtitle: z.string().optional(),
  favorite: z.boolean().optional(),
  scope: CredentialScopeSchema.optional(),
  credentials: z.array(CredentialSchema), // required array (CXF §2.1.2)
  tags: z.array(z.string()).optional(),
  extensions: z.array(ExtensionSchema).optional(),
});

/** CXF §3.2.2.1. */
export const LinkedItemSchema = z.looseObject({
  item: B64url,
  account: B64url.optional(),
});

/** CXF §3.2.2 (recursive through subCollections). */
export interface CollectionShape {
  id: string;
  creationAt?: number | undefined;
  modifiedAt?: number | undefined;
  title: string;
  subtitle?: string | undefined;
  items: z.infer<typeof LinkedItemSchema>[];
  subCollections?: CollectionShape[] | undefined;
  extensions?: z.infer<typeof ExtensionSchema>[] | undefined;
  [unknown: string]: unknown;
}

export const CollectionSchema: z.ZodType<CollectionShape> = z.looseObject({
  id: B64url,
  creationAt: Uint64.optional(),
  modifiedAt: Uint64.optional(),
  title: z.string(),
  subtitle: z.string().optional(),
  items: z.array(LinkedItemSchema),
  get subCollections() {
    return z.array(CollectionSchema).optional();
  },
  extensions: z.array(ExtensionSchema).optional(),
});

/** CXF §3.2.1. */
export const AccountSchema = z.looseObject({
  id: B64url,
  username: z.string(),
  email: z.string(),
  fullName: z.string().optional(),
  collections: z.array(CollectionSchema),
  items: z.array(ItemSchema),
  extensions: z.array(ExtensionSchema).optional(),
});

/** CXF §3.1.1. */
export const VersionSchema = z.looseObject({
  major: Uint8,
  minor: Uint8,
});

/** CXF §3.1. */
export const HeaderSchema = z.looseObject({
  version: VersionSchema,
  exporterRpId: z.string(),
  exporterDisplayName: z.string(),
  timestamp: Uint64,
  accounts: z.array(AccountSchema),
});

export type Extension = z.infer<typeof ExtensionSchema>;
export type CredentialScope = z.infer<typeof CredentialScopeSchema>;
export type Fido2HmacCredentials = z.infer<typeof Fido2HmacCredentialsSchema>;
export type Fido2LargeBlob = z.infer<typeof Fido2LargeBlobSchema>;
export type Fido2Extensions = z.infer<typeof Fido2ExtensionsSchema>;
export type Passkey = z.infer<typeof PasskeySchema>;
export type OtherCredential = z.infer<typeof OtherCredentialSchema>;
export type Credential = z.infer<typeof CredentialSchema>;
export type Item = z.infer<typeof ItemSchema>;
export type LinkedItem = z.infer<typeof LinkedItemSchema>;
export type Collection = CollectionShape;
export type Account = z.infer<typeof AccountSchema>;
export type Version = z.infer<typeof VersionSchema>;
export type Header = z.infer<typeof HeaderSchema>;

export function isPasskey(credential: Credential): credential is Passkey {
  return credential.type === "passkey";
}
