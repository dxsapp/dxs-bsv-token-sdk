import {
  NORMAL_BODY_ASM,
  NORMAL_BODY_BYTES,
  NORMAL_BODY_SECTION_SIZES,
  NORMAL_BODY_SIZE,
  PATH2_REFRESH_ASM,
  PATH3_FREEZE_ASM,
  PATH4_CONFISCATE_ASM,
} from "../src/bntp/v2/templates/normal-body";
import { asmToBytes } from "../src/script/build/asm-template-builder";

/**
 * BNTP v2 Normal template — body size gate (Phase 1 A.1.1 + A.2 + A.2.5 + A.3).
 *
 * Measures the compiled body and asserts the G5 gate bands:
 *   - PASS   ≤ 2600b
 *   - PIVOT  2600-2700b   ← current state (2620b, see A.3 report)
 *   - ABORT  > 2700b
 *
 * A.3 applied three Step C adversarial-review fixes: (#39 critical) confiscate
 * preserves depth (swap hardcoded 0000 push for altstack pull — 0b); (#41
 * moderate) on-chain `m ≥ 1` defensive check at every MPKH branch
 * (OWNER_IDENTITY, authorityIdentityAsm helper, path 2 inline — +16b);
 * (#43 moderate) output-tuple owner `OP_SIZE == 20` assertion at every output
 * reconstruction site (path 1 × 4 iterations + path 4 × 1 — +30b). Net:
 * 2574 → 2620b, PIVOT (20b over strict PASS, 80b under ABORT). PIVOT is the
 * accepted post-Step-C disposition per spec §15 decision #41 projection.
 *
 * A.2.5 applied three targeted ASM edits: (1) MPKH issuer branch on path 2
 * (decision #34); (2) optional change output at index 3 of refresh tx
 * (decision #37); (3) retroactive FD-only varint optimization on path 1
 * output reconstruction (decision #38). Net effect: +123b path 2, −136b
 * path 1 recon, total body 2587 → 2574b PASS (26b margin under G5).
 *
 * Also asserts sanity: the body starts with the canonical marker
 * `4c 02 01 ff 75` (OP_PUSHDATA1 0x02 0x01 0xff OP_DROP) per spec §5.
 *
 * Lower bound is intentionally relaxed to 1500b — A.1.1 measurement came in
 * below the pseudo-ASM's claimed 2461b and the audit's revised 2363-2693b
 * range. See docs/BNTP_V2_NORMAL_TEMPLATE_A1_1_REPORT.md,
 * docs/BNTP_V2_NORMAL_TEMPLATE_A2_REPORT.md,
 * docs/BNTP_V2_NORMAL_TEMPLATE_A2_5_REPORT.md, and
 * docs/BNTP_V2_NORMAL_TEMPLATE_A3_REPORT.md for measurement discussion.
 * The tight lower bound is kept as a regression guard; a measurement below
 * 1500b would indicate a missing major section (e.g. output reconstruction
 * omitted).
 */
describe("BNTP v2 Normal template — body size (A.1.1 + A.2 + A.2.5 + A.3)", () => {
  test("body compiles to deterministic bytes", () => {
    const firstPass = NORMAL_BODY_BYTES;
    const secondPass = (() => {
      const prefix = new Uint8Array([0x4c, 0x02, 0x01, 0xff, 0x75]);
      const tail = asmToBytes(NORMAL_BODY_ASM);
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

  test("body starts with canonical marker 4c 02 01 ff 75", () => {
    expect(NORMAL_BODY_BYTES[0]).toBe(0x4c);
    expect(NORMAL_BODY_BYTES[1]).toBe(0x02);
    expect(NORMAL_BODY_BYTES[2]).toBe(0x01);
    expect(NORMAL_BODY_BYTES[3]).toBe(0xff);
    expect(NORMAL_BODY_BYTES[4]).toBe(0x75);
  });

  test("body size is within ABORT ceiling (≤ 2700b)", () => {
    // Phase 1A G5 gate: PASS ≤ 2600, PIVOT 2600-2700, ABORT > 2700.
    // Phase 1B temporarily relaxed to 4500 during D.2c (working-bytes-first
    // posture); restored here as part of the optimization wave now that
    // paths 1/3/4 are implemented end-to-end and a shared
    // OUTPUT_BYTES_WRAP_ASM helper has consolidated the per-path output
    // serialization. Path 2 (D.3.3) currently inlined as legacy dead code
    // — it'll be rewritten in the next wave; the body has ample headroom.
    expect(NORMAL_BODY_SIZE).toBeLessThanOrEqual(2700);
  });

  test("G5 verdict helper — PASS / PIVOT / ABORT band classification", () => {
    // Phase 1A G5 gate restored.
    let verdict: "PASS" | "PIVOT" | "ABORT";
    if (NORMAL_BODY_SIZE <= 2600) verdict = "PASS";
    else if (NORMAL_BODY_SIZE <= 2700) verdict = "PIVOT";
    else verdict = "ABORT";

    expect(verdict).not.toBe("ABORT");
  });

  test("body size is above regression floor (≥ 1850b)", () => {
    // Sanity lower bound. A value below this indicates a major section
    // (covenant, preimage parse, dispatcher, any path SUFFIX) was elided.
    //
    // History:
    //   - Phase 1A: 2620b (PIVOT band).
    //   - Wave D.1 (PREFIX rewrite, path-1 stubbed): 1442b.
    //   - Wave D.2c.1 (path-1 conservation half): 1767b.
    //   - Wave D.2c.2 (path-1 reconstruction + hashOutputs): 2098b.
    //   - Wave D.2c.3: floor bumped 1200 → 1900 (post-D.2c.2 baseline).
    //   - Wave D.3.1 (path-4 confiscate, D.1 zone-aware): 1976b (path-4
    //     section -111b vs legacy).
    //   - Wave D.3.2 (this commit; path-3 freeze, D.1 zone-aware):
    //     1878b (path-3 section -98b vs legacy). Floor lowered to
    //     1850b to accommodate; the optimization wave will revisit
    //     once paths 2/3/4 are all D.1-rewritten.
    expect(NORMAL_BODY_SIZE).toBeGreaterThanOrEqual(1850);
  });

  test("per-section sizes sum to total body size", () => {
    const sum = Object.values(NORMAL_BODY_SECTION_SIZES).reduce(
      (a, b) => a + b,
      0,
    );
    expect(sum).toBe(NORMAL_BODY_SIZE);
  });

  test("informational: opcode-count + section breakdown", () => {
    // This test always passes; it prints diagnostic info into the test log.
    const nonPushOpcodeCount = Array.from(NORMAL_BODY_BYTES).filter(
      (b) => b >= 0x50, // opcodes ≥ OP_RESERVED (0x50) are real opcodes (not push-data length prefixes or raw push data bytes)
    ).length;

    const report = [
      `NORMAL_BODY_SIZE = ${NORMAL_BODY_SIZE} bytes`,
      `non-push opcode bytes (≥0x50, approximate): ${nonPushOpcodeCount}`,
      "per-section sizes:",
      ...Object.entries(NORMAL_BODY_SECTION_SIZES).map(
        ([k, v]) => `  ${k}: ${v}`,
      ),
    ].join("\n");

    // Always passes; output is visible with jest --verbose.

    console.log(report);
    expect(NORMAL_BODY_SIZE).toBeGreaterThan(0);
  });

  test("paths 2, 3, 4 are non-stub (byte counts > 50)", () => {
    // A.2 sanity: each path SUFFIX has real, non-trivial ASM replacing the
    // A.1.1 `OP_FALSE OP_VERIFY` stubs (which compiled to exactly 2b each).
    // A path measuring ≤ 50b would indicate accidental regression to a stub.
    const path2Size = asmToBytes(PATH2_REFRESH_ASM).length;
    const path3Size = asmToBytes(PATH3_FREEZE_ASM).length;
    const path4Size = asmToBytes(PATH4_CONFISCATE_ASM).length;

    expect(path2Size).toBeGreaterThan(50);
    expect(path3Size).toBeGreaterThan(50);
    expect(path4Size).toBeGreaterThan(50);

    // Also sanity: each path landed in a plausible band per A.2 audit
    // estimates (path 2 320-380, path 3 280-310, path 4 210-230). We use
    // loose ceilings since A.2 measured under-audit for paths 2 and 3 via
    // varint-simplification optimization (see A.2 report §3).
    expect(path2Size).toBeLessThan(400);
    expect(path3Size).toBeLessThan(400);
    expect(path4Size).toBeLessThan(400);
  });

  test("G5 gate verdict", () => {
    // Phase 1A G5 gate: PASS ≤ 2600 | PIVOT 2600-2700 | ABORT > 2700.
    let verdict: "PASS" | "PIVOT" | "ABORT";
    if (NORMAL_BODY_SIZE <= 2600) verdict = "PASS";
    else if (NORMAL_BODY_SIZE <= 2700) verdict = "PIVOT";
    else verdict = "ABORT";

    console.log(`G5 verdict: ${verdict} (${NORMAL_BODY_SIZE} bytes)`);

    expect(verdict).not.toBe("ABORT");
  });
});
