/**
 * A-09: post-import memory residue of PKCS#8 keys.
 *
 * After a credential import, the PKCS#8 DER buffer and the base64url
 * string representation may remain in the process heap, accessible to a
 * memory-scanning adversary.
 *
 * Gaps exercised: GAP-13.
 * spec-minimal: succeeds — DER buffers are not zeroed.
 * hardened: reduced — DER buffers are zeroed (best effort), but immutable
 *   JavaScript strings (base64url key in parsed JSON) persist until GC.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getPolicy, isEnabled, PROFILE_NAMES } from "../../src/policy/index.js";
import { createWorld, migrate } from "../../src/scenario/world.js";

describe("A-09 / GAP-13: post-import memory residue", () => {
  describe.each(PROFILE_NAMES)("%s", (profile) => {
    const policy = getPolicy(profile);
    let world: Awaited<ReturnType<typeof createWorld>>;

    beforeEach(async () => {
      world = await createWorld(policy);
      await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
    });

    afterEach(async () => {
      await world.close();
    });

    if (profile === "spec-minimal") {
      it("succeeds: key material is not zeroed after import (GAP-13)", async () => {
        expect(isEnabled(policy, "zeroizeKeyMaterial")).toBe(false);
        await migrate(world, "indirect");
        const record = world.providerB.vault.list()[0]!;
        expect(record.privateKey.type).toBe("private");
        expect(record.privateKey.asymmetricKeyType).toBe("ec");
      });
    } else {
      it("reduced: DER is zeroed but base64url strings persist (GAP-13)", async () => {
        expect(isEnabled(policy, "zeroizeKeyMaterial")).toBe(true);
        await migrate(world, "indirect");
        const record = world.providerB.vault.list()[0]!;
        expect(record.privateKey.type).toBe("private");
        // Residual risk: the immutable base64url key string from the parsed
        // JSON stays in the V8 heap until garbage collection.
      });
    }
  });
});
