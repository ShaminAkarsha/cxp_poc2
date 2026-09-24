import { POLICY_FLAG_NAMES, type PolicyFlag } from "./flags.js";

/** README §3: the two conformance profiles. */
export const PROFILE_NAMES = ["spec-minimal", "hardened"] as const;
export type ProfileName = (typeof PROFILE_NAMES)[number];

export type PolicyFlags = Readonly<Record<PolicyFlag, boolean>>;

export interface Policy {
  readonly profile: ProfileName;
  readonly flags: PolicyFlags;
}

function allFlags(value: boolean): PolicyFlags {
  return Object.freeze(
    Object.fromEntries(POLICY_FLAG_NAMES.map((flag) => [flag, value])) as Record<PolicyFlag, boolean>,
  );
}

/**
 * `spec-minimal`: every flag off — no mitigation beyond what a MUST requires.
 * `hardened`: every gap closed. The two profiles differ only in these flags.
 */
export const PROFILES: Readonly<Record<ProfileName, Policy>> = Object.freeze({
  "spec-minimal": Object.freeze({ profile: "spec-minimal", flags: allFlags(false) }),
  hardened: Object.freeze({ profile: "hardened", flags: allFlags(true) }),
});

export function isProfileName(value: string): value is ProfileName {
  return (PROFILE_NAMES as readonly string[]).includes(value);
}

export function getPolicy(profile: ProfileName): Policy {
  return PROFILES[profile];
}

export function isEnabled(policy: Policy, flag: PolicyFlag): boolean {
  return policy.flags[flag];
}
