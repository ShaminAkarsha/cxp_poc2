/**
 * M3 exit criterion: RFC 9180 test vectors pass.
 * Source: test/fixtures/README.md (CFRG vectors, filtered to in-scope suites).
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  deriveKeyPair,
  exportSecret,
  serializePublicKey,
  setupRecipient,
  setupSender,
  type SuiteIds,
} from "../../src/crypto/hpke.js";

interface Vector {
  mode: number;
  kem_id: number;
  kdf_id: number;
  aead_id: number;
  info: string;
  ikmR: string;
  ikmE: string;
  ikmS?: string;
  pkRm: string;
  pkSm?: string;
  pkEm: string;
  enc: string;
  encryptions: { seq: number; aad: string; ct: string; nonce: string; pt: string }[];
  exports: { exporter_context: string; L: number; exported_value: string }[];
}

const vectors = JSON.parse(
  readFileSync(new URL("../fixtures/rfc9180-vectors.json", import.meta.url), "utf8"),
) as Vector[];

const h = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const hex = (b: ArrayBuffer | Uint8Array) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString("hex");
const MODE_NAME: Record<number, string> = { 0: "base", 2: "auth" };

describe("RFC 9180 test vectors", () => {
  it("covers base and auth for the README MTI suite", () => {
    const mti = vectors.filter((v) => v.kem_id === 0x20 && v.kdf_id === 1 && v.aead_id === 2);
    expect(mti.map((v) => v.mode).sort()).toEqual([0, 2]);
  });

  it.each(vectors.map((v) => [`${MODE_NAME[v.mode]} kem=0x${v.kem_id.toString(16)} aead=0x${v.aead_id.toString(16)}`, v] as const))(
    "%s",
    async (_name, v) => {
      const suite: SuiteIds = { kem: v.kem_id, kdf: v.kdf_id, aead: v.aead_id };
      const recipient = await deriveKeyPair(v.kem_id, h(v.ikmR));
      expect(hex(await serializePublicKey(v.kem_id, recipient.publicKey))).toBe(v.pkRm);

      const sender = v.ikmS ? await deriveKeyPair(v.kem_id, h(v.ikmS)) : undefined;
      if (sender) expect(hex(await serializePublicKey(v.kem_id, sender.publicKey))).toBe(v.pkSm);

      const info = h(v.info);
      const s = await setupSender({
        suite,
        recipientPublicKey: recipient.publicKey,
        info,
        ikmE: h(v.ikmE),
        ...(sender ? { senderKey: sender } : {}),
      });
      expect(hex(s.enc)).toBe(v.enc);

      const r = await setupRecipient({
        suite,
        recipientKey: recipient,
        enc: h(v.enc),
        info,
        ...(sender ? { senderPublicKey: sender.publicKey } : {}),
      });

      // Encryptions: the vectors use aad "Count-<seq>"; seal/open every
      // sequence number up to the last kept one so nonces line up.
      const bySeq = new Map(v.encryptions.map((e) => [e.seq, e]));
      const last = Math.max(-1, ...v.encryptions.map((e) => e.seq));
      const pt = v.encryptions[0]?.pt;
      for (let seq = 0; seq <= last; seq++) {
        const aad = new TextEncoder().encode(`Count-${seq}`);
        const ct = await s.seal(h(pt!), aad);
        const expected = bySeq.get(seq);
        if (expected) {
          expect(hex(aad)).toBe(expected.aad);
          expect(hex(ct)).toBe(expected.ct);
        }
        expect(hex(await r.open(ct, aad))).toBe(pt);
      }

      for (const e of v.exports) {
        expect(hex(await exportSecret(s, h(e.exporter_context), e.L))).toBe(e.exported_value);
        expect(hex(await exportSecret(r, h(e.exporter_context), e.L))).toBe(e.exported_value);
      }
    },
  );
});
