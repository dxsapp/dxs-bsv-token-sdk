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
 * BNTP v2 Normal template — body size gate (Phase 1 A.1.1 + A.2).
 *
 * Measures the compiled body and asserts the G5 gate bands:
 *   - PASS   ≤ 2600b
 *   - PIVOT  2600-2700b
 *   - ABORT  > 2700b
 *
 * Also asserts sanity: the body starts with the canonical marker
 * `4c 02 01 ff 75` (OP_PUSHDATA1 0x02 0x01 0xff OP_DROP) per spec §5.
 *
 * Lower bound is intentionally relaxed to 1500b — A.1.1 measurement came in
 * below the pseudo-ASM's claimed 2461b and the audit's revised 2363-2693b
 * range. A.2 (paths 2, 3, 4) added ~686b bringing total to ~2587b, still
 * within PASS band. See docs/BNTP_V2_NORMAL_TEMPLATE_A1_1_REPORT.md and
 * docs/BNTP_V2_NORMAL_TEMPLATE_A2_REPORT.md for measurement discussion.
 * The tight lower bound is kept as a regression guard; a measurement below
 * 1500b would indicate a missing major section (e.g. output reconstruction
 * omitted).
 */
describe("BNTP v2 Normal template — body size (A.1.1 + A.2)", () => {
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
    expect(NORMAL_BODY_SIZE).toBeLessThanOrEqual(2700);
  });

  test("body size is above regression floor (≥ 1500b)", () => {
    // Sanity lower bound. A value below this indicates a major section was
    // elided (output reconstruction, covenant, etc.).
    expect(NORMAL_BODY_SIZE).toBeGreaterThanOrEqual(1500);
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
    // PASS ≤ 2600 | PIVOT 2600-2700 | ABORT > 2700
    let verdict: "PASS" | "PIVOT" | "ABORT";
    if (NORMAL_BODY_SIZE <= 2600) verdict = "PASS";
    else if (NORMAL_BODY_SIZE <= 2700) verdict = "PIVOT";
    else verdict = "ABORT";

    console.log(`G5 verdict: ${verdict} (${NORMAL_BODY_SIZE} bytes)`);

    expect(verdict).not.toBe("ABORT");
  });
});
