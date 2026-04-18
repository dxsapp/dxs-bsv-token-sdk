import {
  FROZEN_BODY_ASM,
  FROZEN_BODY_BYTES,
  FROZEN_BODY_SECTION_SIZES,
  FROZEN_BODY_SIZE,
  H_NORMAL_PLACEHOLDER_HEX,
  PATH3_UNFREEZE_ASM_EXPORT,
  PATH4_CONFISC_FROM_FROZEN_ASM_EXPORT,
  compileFrozenBody,
} from "../src/bntp/v2/templates/frozen-body";
import { asmToBytes } from "../src/script/build/asm-template-builder";

/**
 * BNTP v2 Frozen template — body size gate (Phase 1 A.3 Frozen scope).
 *
 * Frozen body covers the two authority-gated spend paths retained on the
 * compliance-hold template:
 *
 *   - Path 3 unfreeze (§9.7): freezeAuth reverses the freeze. Target is
 *     Normal — unlocking pushes NORMAL_BODY_BYTES; locking SHA256-verifies
 *     against the embedded h_Normal placeholder (patched by the SDK deploy
 *     tool in Phase 1B).
 *   - Path 4 confiscate-from-frozen (§9.8): confiscAuth seizes the UTXO.
 *     Target is Normal. Depth PRESERVED per decision #39 (Step C Critical
 *     #1), overriding stale §9.8 prose which reads "new_depth = 0".
 *
 * Gate bands (recalibrated — see docs/BNTP_V2_FROZEN_TEMPLATE_REPORT.md §1
 * for the rationale):
 *   - PASS   ≤ 1200b
 *   - PIVOT  1200-1400b
 *   - ABORT  > 1400b
 *
 * Spec §11.1 projection is ~700b — pre-audit, before the Step C fixes
 * (#39 / #41 / #43) and the explicit decision #29 PKH CHECKSIGVERIFY pattern
 * landed. Honest post-audit accounting lands in the 1200-1300b band.
 *
 * Lower bound is a regression floor at 500b: anything below that would
 * indicate the SHA256 hash-verify / pushed-body output reconstruction was
 * elided from at least one path.
 */
describe("BNTP v2 Frozen template — body size (Phase 1 A.3)", () => {
  test("body compiles to deterministic bytes", () => {
    const firstPass = FROZEN_BODY_BYTES;
    const secondPass = compileFrozenBody();

    expect(secondPass.length).toBe(firstPass.length);
    for (let i = 0; i < firstPass.length; i++) {
      expect(secondPass[i]).toBe(firstPass[i]);
    }
  });

  test("body starts with canonical Frozen marker 4c 02 fe ff 75", () => {
    expect(FROZEN_BODY_BYTES[0]).toBe(0x4c);
    expect(FROZEN_BODY_BYTES[1]).toBe(0x02);
    expect(FROZEN_BODY_BYTES[2]).toBe(0xfe);
    expect(FROZEN_BODY_BYTES[3]).toBe(0xff);
    expect(FROZEN_BODY_BYTES[4]).toBe(0x75);
  });

  test("body size is within ABORT ceiling (≤ 1400b)", () => {
    expect(FROZEN_BODY_SIZE).toBeLessThanOrEqual(1400);
  });

  test("body size is above regression floor (≥ 500b)", () => {
    // A size below this would indicate the pushed-body SHA256 verify or the
    // output reconstruction for path 3 and/or path 4 was elided.
    expect(FROZEN_BODY_SIZE).toBeGreaterThanOrEqual(500);
  });

  test("per-section sizes sum to total body size", () => {
    const sum = Object.values(FROZEN_BODY_SECTION_SIZES).reduce(
      (a, b) => a + b,
      0,
    );
    expect(sum).toBe(FROZEN_BODY_SIZE);
  });

  test("informational: opcode-count + section breakdown", () => {
    // This test always passes; it prints diagnostic info into the test log.
    const nonPushOpcodeCount = Array.from(FROZEN_BODY_BYTES).filter(
      (b) => b >= 0x50,
    ).length;

    const report = [
      `FROZEN_BODY_SIZE = ${FROZEN_BODY_SIZE} bytes`,
      `non-push opcode bytes (≥0x50, approximate): ${nonPushOpcodeCount}`,
      "per-section sizes:",
      ...Object.entries(FROZEN_BODY_SECTION_SIZES).map(
        ([k, v]) => `  ${k}: ${v}`,
      ),
    ].join("\n");

    console.log(report);
    expect(FROZEN_BODY_SIZE).toBeGreaterThan(0);
  });

  test("paths 3 and 4 are non-stub (byte counts > 100)", () => {
    const path3Size = asmToBytes(PATH3_UNFREEZE_ASM_EXPORT).length;
    const path4Size = asmToBytes(PATH4_CONFISC_FROM_FROZEN_ASM_EXPORT).length;

    // Both paths carry the ~110b authority-identity helper + ~30b hash verify
    // + ~100b output reconstruction, so each should sit in the 200-350b band.
    expect(path3Size).toBeGreaterThan(100);
    expect(path4Size).toBeGreaterThan(100);
    expect(path3Size).toBeLessThan(400);
    expect(path4Size).toBeLessThan(400);
  });

  test("h_Normal placeholder is embedded as 32b zero-push in both paths", () => {
    // Decision #27: Frozen embeds a 32-byte constant `h_Normal`. We use
    // 32 zero bytes as placeholder (H_NORMAL_PLACEHOLDER_HEX). The ASM
    // builder emits this as a direct push (length byte 0x20 followed by 32
    // zeros). It should appear exactly twice in the compiled body — once in
    // path 3 (unfreeze) and once in path 4 (confiscate-from-frozen).
    expect(H_NORMAL_PLACEHOLDER_HEX).toBe("00".repeat(32));

    const bodyArr = Array.from(FROZEN_BODY_BYTES);
    let found = 0;
    for (let i = 0; i + 33 <= bodyArr.length; i++) {
      if (bodyArr[i] !== 0x20) continue;
      let ok = true;
      for (let j = 1; j < 33; j++) {
        if (bodyArr[i + j] !== 0x00) {
          ok = false;
          break;
        }
      }
      if (ok) found++;
    }
    expect(found).toBe(2);
  });

  test("G5 verdict helper — PASS / PIVOT / ABORT band classification", () => {
    let verdict: "PASS" | "PIVOT" | "ABORT";
    if (FROZEN_BODY_SIZE <= 1200) verdict = "PASS";
    else if (FROZEN_BODY_SIZE <= 1400) verdict = "PIVOT";
    else verdict = "ABORT";

    console.log(`Frozen verdict: ${verdict} (${FROZEN_BODY_SIZE} bytes)`);

    expect(verdict).not.toBe("ABORT");
    // PIVOT is accepted (spec §11.1 projection of 700b is pre-audit; post-audit
    // realistic is 1100-1300b). See report §1 for gate recalibration rationale.
  });
});
