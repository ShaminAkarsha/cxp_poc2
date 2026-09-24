import { getPolicy, isProfileName, PROFILE_NAMES, type Policy, type ProfileName } from "./profiles.js";

export const PROFILE_ENV_VAR = "CXP_PROFILE";
export const DEFAULT_PROFILE: ProfileName = "spec-minimal";

export class ProfileSelectionError extends Error {
  override name = "ProfileSelectionError";
}

function parseProfile(value: string, source: string): ProfileName {
  if (!isProfileName(value)) {
    throw new ProfileSelectionError(
      `Unknown profile "${value}" from ${source}; expected one of: ${PROFILE_NAMES.join(", ")}`,
    );
  }
  return value;
}

/**
 * README §3: the profile is selected at runtime by `--profile <name>`
 * (or `--profile=<name>`), falling back to CXP_PROFILE, then to
 * DEFAULT_PROFILE. The command-line flag takes precedence.
 */
export function resolveProfileName(
  argv: readonly string[] = process.argv.slice(2),
  env: Readonly<Record<string, string | undefined>> = process.env,
): ProfileName {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--profile") {
      const value = argv[i + 1];
      if (value === undefined) throw new ProfileSelectionError("--profile requires a value");
      return parseProfile(value, "--profile");
    }
    if (arg?.startsWith("--profile=")) {
      return parseProfile(arg.slice("--profile=".length), "--profile");
    }
  }
  const fromEnv = env[PROFILE_ENV_VAR];
  if (fromEnv !== undefined && fromEnv !== "") return parseProfile(fromEnv, PROFILE_ENV_VAR);
  return DEFAULT_PROFILE;
}

export function resolvePolicy(
  argv?: readonly string[],
  env?: Readonly<Record<string, string | undefined>>,
): Policy {
  return getPolicy(resolveProfileName(argv, env));
}
