import {
  CONTRACT_BODY_ASM,
  CONTRACT_BODY_BYTES,
  CONTRACT_BODY_SECTION_SIZES,
  CONTRACT_BODY_SIZE,
} from "../src/bntp/v2/templates/contract-body";
import { NORMAL_BODY_BYTES } from "../src/bntp/v2/templates/normal-body";
import { asmToBytes } from "../src/script/build/asm-template-builder";

/**
 * BNTP v2 Contract template — body size gate (Phase 1A.3, post-user-decision gate).
 *
 * Gate bands (decision #49 ratified post-Phase-1A.3 — honest post-measurement
 * revision from pre-audit ~3100b projection, because Normal is actually 2620b
 * and Contract's own PREFIX + path-6 logic is dominated by Step C + A.3 fixes):
 *   - PASS   ≤ 4100b
 *   - PIVOT  4100-4300b
 *   - ABORT  > 4300b
 *
 * Current measurement: 3971b = PASS (129b margin to PASS ceiling).
 *
 * Contract is a one-shot mint UTXO (§9.9.2 fixed supply, consumed at first
 * issue), so body size does not cascade per-token-transfer. Alternative
 * (unlocking-push Normal body on issue) would cost N×2620b per issue tx
 * (~11 KB for N=4) vs current 3971b mint + ~500b issue = ~4.6 KB. Inline
 * wins ~7 KB per token lifecycle.
 *
 * Sanity floor ≥ 2800b protects against regression where the Normal-body
 * inline would be accidentally dropped (2620b alone is ~66% of the budget).
 */
describe("BNTP v2 Contract template — body size (A.3)", () => {
  test("body compiles to deterministic bytes", () => {
    const firstPass = CONTRACT_BODY_BYTES;
    const secondPass = (() => {
      const prefix = new Uint8Array([0x4c, 0x02, 0xc0, 0xff, 0x75]);
      const tail = asmToBytes(CONTRACT_BODY_ASM);
      const out = new Uint8Array(prefix.length + tail.length);
      out.set(prefix, 0);
      out.set(tail, prefix.length);
      return out;
    })();

    expect(secondPass.length).toBe(firstPass.length);
    for (let i = 0; i < firstPass.length; i++) {
      expect(secondPass[i]).toBe(firstPass[i]);
    }
  });

  test("body starts with canonical Contract marker 4c 02 c0 ff 75", () => {
    expect(CONTRACT_BODY_BYTES[0]).toBe(0x4c);
    expect(CONTRACT_BODY_BYTES[1]).toBe(0x02);
    expect(CONTRACT_BODY_BYTES[2]).toBe(0xc0);
    expect(CONTRACT_BODY_BYTES[3]).toBe(0xff);
    expect(CONTRACT_BODY_BYTES[4]).toBe(0x75);
  });

  test("inlined Normal body appears in compiled Contract bytes", () => {
    // Decision #28 / §5.5.2: Contract inlines full Normal body as a constant.
    // We verify by substring-match on the first 64 bytes of NORMAL_BODY_BYTES
    // (the body marker `4c 02 01 ff 75` followed by the covenant preamble's
    // opening opcodes — a distinctive signature).
    const haystack = Buffer.from(CONTRACT_BODY_BYTES).toString("hex");
    const needle = Buffer.from(NORMAL_BODY_BYTES.slice(0, 64)).toString("hex");
    expect(haystack.includes(needle)).toBe(true);
  });

  test("body size is within ABORT ceiling (≤ 4300b revised gate, decision #49)", () => {
    expect(CONTRACT_BODY_SIZE).toBeLessThanOrEqual(4300);
  });

  test("body size is within PASS ceiling (≤ 4100b revised gate, decision #49)", () => {
    expect(CONTRACT_BODY_SIZE).toBeLessThanOrEqual(4100);
  });

  test("body size is above sanity floor (≥ 2800b — inlined Normal body alone is ~2620b)", () => {
    // Regression guard: if the Normal-body inline was accidentally elided or
    // replaced with a 32b placeholder push, the body would drop well below
    // 2800b — catch that via this assertion.
    expect(CONTRACT_BODY_SIZE).toBeGreaterThanOrEqual(2800);
  });

  test("per-section sizes sum to total body size", () => {
    const sum = Object.values(CONTRACT_BODY_SECTION_SIZES).reduce(
      (a, b) => a + b,
      0,
    );
    expect(sum).toBe(CONTRACT_BODY_SIZE);
  });

  test("inlinedNormalBody section is ≥ 2620b (full Normal body + push overhead)", () => {
    expect(
      CONTRACT_BODY_SECTION_SIZES.inlinedNormalBody,
    ).toBeGreaterThanOrEqual(2620);
  });

  test("informational: Contract body size + section breakdown + verdict", () => {
    let verdict: "PASS" | "PIVOT" | "ABORT";
    if (CONTRACT_BODY_SIZE <= 4100) verdict = "PASS";
    else if (CONTRACT_BODY_SIZE <= 4300) verdict = "PIVOT";
    else verdict = "ABORT";

    const report = [
      `CONTRACT_BODY_SIZE = ${CONTRACT_BODY_SIZE} bytes`,
      `Gate verdict (decision #49: PASS ≤4100 / PIVOT ≤4300 / ABORT >4300): ${verdict}`,
      "per-section sizes:",
      ...Object.entries(CONTRACT_BODY_SECTION_SIZES).map(
        ([k, v]) => `  ${k}: ${v}`,
      ),
    ].join("\n");

    // Always-pass diagnostic.

    console.log(report);
    expect(CONTRACT_BODY_SIZE).toBeGreaterThan(0);
  });
});
