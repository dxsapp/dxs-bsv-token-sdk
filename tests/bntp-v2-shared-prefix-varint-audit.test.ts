/**
 * BNTP v2 — VARINT_SERIALIZE_ASM correctness audit (pre-D.3).
 *
 * Background:
 *   `VARINT_SERIALIZE_ASM` lives in src/bntp/v2/templates/shared-prefix.ts
 *   and is the closing helper for paths 2/3/4 candidate-output serialization
 *   (compute hashOutputs commitment over `sats(8) ‖ varint(3) ‖ candidate`).
 *   It was authored in Phase 1A as part of the byte-budget falsification
 *   exercise — explicitly NOT execution-verified at the time (see comment
 *   block in normal-body.ts:52-57). Phase 1B Wave D.1 redesigned the §2
 *   zone contract; in the current dispatcher only `path_id=1` is exercised
 *   end-to-end (D.2c pipeline). Paths 2/3/4 SUFFIXes are dead code pending
 *   D.3 rewrite, so the helper has not been hit by any execution-level
 *   assertion in production tests.
 *
 *   D.3 is about to begin and will exercise this helper for real (path 2/3/4
 *   reconstruction → HASH256 → EQUALVERIFY against zone.hashOutputs). A
 *   buggy helper here would surface as "EQUALVERIFY failed" at the very
 *   end of the path script — opaque, with hundreds of trace steps separating
 *   cause from effect. Auditing the helper standalone (this file) lets D.3
 *   start from a known-good substrate.
 *
 * What this test does:
 *   Constructs a minimal locking script of the form:
 *     <push_acc_below> <push_C> ${VARINT_SERIALIZE_ASM} OP_RETURN_VERIFY_NOOP
 *   evaluates it, and compares the final top-of-stack item byte-for-byte
 *   against the BSV-spec serialized-output prefix encoding:
 *     acc_below ‖ sats(8) ‖ varint(3) ‖ C
 *   where varint = 0xFD ‖ size_C_le_2b and sats = `0100000000000000`
 *   (1 satoshi LE, hardcoded per BNTP v2 dust convention).
 *
 *   `acc_below` lets the helper be used in multi-output accumulation
 *   (path 2 emits 2 outputs, CATting into a running accumulator). For
 *   the audit, we test both empty acc (single-output case, path 3/4)
 *   and non-empty acc (multi-output case, path 2).
 *
 * Expected result (with current helper, per pre-audit byte-trace):
 *   FAIL — helper produces `acc ‖ C ‖ FD ‖ 0100 ‖ sizeC_scriptnum` instead
 *   of `acc ‖ sats(8) ‖ FD ‖ size_le_2b ‖ C`. Order is shuffled and sats
 *   prefix is truncated to its first 2 bytes (which happen to coincide
 *   with the value `0x0100` = scriptnum 1, but that's not size).
 *
 *   If this test passes against the unmodified helper, my pre-audit trace
 *   was wrong and the helper is correct — in that case the test serves as
 *   a canonical-state contract document for future readers.
 *
 *   If it fails, the helper is rewritten in this commit (mirroring the
 *   D.2c.2 inline reconstruction in normal-body.ts:493-507 which IS
 *   execution-verified).
 */

import {
  evaluateScripts,
  PrevOutput,
  SCRIPT_ENABLE_MAGNETIC_OPCODES,
  SCRIPT_ENABLE_MONOLITH_OPCODES,
  SCRIPT_ENABLE_SIGHASH_FORKID,
} from "../src/script";
import { asmToBytes } from "../src/script/build/asm-template-builder";
import { Transaction } from "../src/bitcoin/transaction";
import { TransactionInput } from "../src/bitcoin/transaction-input";
import { TransactionOutput } from "../src/bitcoin/transaction-output";
import { VARINT_SERIALIZE_ASM } from "../src/bntp/v2/templates/shared-prefix";
import { toHex } from "../src/bytes";

const FLAGS =
  SCRIPT_ENABLE_SIGHASH_FORKID |
  SCRIPT_ENABLE_MAGNETIC_OPCODES |
  SCRIPT_ENABLE_MONOLITH_OPCODES;

const SATS_1_LE_8 = new Uint8Array([0x01, 0, 0, 0, 0, 0, 0, 0]);

const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

/** Encode `n` as a 1-byte data push opcode + the byte itself, OR multi-byte
 *  push for n > 0xff. For our test we only need lengths in [1, 2^16). */
const dataPush = (data: Uint8Array): Uint8Array => {
  if (data.length === 0) return new Uint8Array([0x00]); // OP_0 = empty push
  if (data.length <= 75) {
    const out = new Uint8Array(1 + data.length);
    out[0] = data.length;
    out.set(data, 1);
    return out;
  }
  if (data.length <= 0xff) {
    // OP_PUSHDATA1
    const out = new Uint8Array(2 + data.length);
    out[0] = 0x4c;
    out[1] = data.length;
    out.set(data, 2);
    return out;
  }
  if (data.length <= 0xffff) {
    // OP_PUSHDATA2
    const out = new Uint8Array(3 + data.length);
    out[0] = 0x4d;
    out[1] = data.length & 0xff;
    out[2] = (data.length >> 8) & 0xff;
    out.set(data, 3);
    return out;
  }
  throw new Error("data too large");
};

const expectedSerialized = (
  acc: Uint8Array,
  candidate: Uint8Array,
): Uint8Array => {
  const len = candidate.length;
  if (len > 0xffff) throw new Error("candidate too large for FD-varint");
  const varint = new Uint8Array([0xfd, len & 0xff, (len >> 8) & 0xff]);
  return concatBytes([acc, SATS_1_LE_8, varint, candidate]);
};

/**
 * Build a self-contained locking script that:
 *   1. Pushes `acc` (potentially empty).
 *   2. Pushes `candidate` (the script bytes whose serialized form we want).
 *   3. Runs VARINT_SERIALIZE_ASM (consumes top + below, leaves serialized
 *      form on top).
 *   4. Appends OP_1 (truthy) so the script's success isn't gated on the
 *      reconstructed bytes being numerically truthy.
 *
 * Then evaluates and returns the final top-of-stack item below the OP_1
 * (which is the helper's actual output).
 */
const runHelper = (
  acc: Uint8Array,
  candidate: Uint8Array,
): { success: boolean; error?: string; helperOutput?: Uint8Array } => {
  const lockingScript = concatBytes([
    dataPush(acc),
    dataPush(candidate),
    asmToBytes(VARINT_SERIALIZE_ASM),
    new Uint8Array([0x51]), // OP_1 — keeps the script truthy after helper
  ]);

  // Build a minimal tx context (helper doesn't reference tx).
  const dummyTx = new Transaction(
    new Uint8Array(),
    [new TransactionInput("00".repeat(32), 0, new Uint8Array(), 0xffffffff)],
    [new TransactionOutput(0, new Uint8Array())],
    1,
    0,
  );
  const prevOutputs: PrevOutput[] = [
    { lockingScript: new Uint8Array(), satoshis: 0 },
  ];

  const r = evaluateScripts(
    new Uint8Array(),
    lockingScript,
    { tx: dummyTx, inputIndex: 0, prevOutputs },
    {
      allowOpReturn: true,
      scriptFlags: FLAGS,
      strict: false,
      maxScriptSizeBytes: 2_000_000,
      maxOps: 100_000,
      maxStackDepth: 10_000,
      maxElementSizeBytes: 2_000_000,
    },
  );

  if (!r.success) return { success: false, error: r.error };
  // The OP_1 sentinel is the top item; the helper's real output is at d1.
  const helperOutput =
    r.stack.length >= 2 ? r.stack[r.stack.length - 2] : undefined;
  return { success: true, helperOutput };
};

describe("VARINT_SERIALIZE_ASM correctness audit", () => {
  test("single-output case (empty acc): produces sats(8) ‖ FD ‖ size_le_2b ‖ C", () => {
    const candidate = new Uint8Array(1902).map((_, i) => (i * 7 + 3) & 0xff);
    const acc = new Uint8Array();

    const r = runHelper(acc, candidate);
    expect(r.success).toBe(true);
    if (!r.helperOutput) throw new Error("no helper output");

    const expected = expectedSerialized(acc, candidate);
    expect(r.helperOutput.length).toBe(expected.length);
    expect(toHex(r.helperOutput)).toBe(toHex(expected));
  });

  test("multi-output case (non-empty acc): produces acc ‖ sats(8) ‖ FD ‖ size_le_2b ‖ C", () => {
    // acc represents an existing accumulator from a previous output.
    const acc = new Uint8Array(50).map((_, i) => (i * 13 + 5) & 0xff);
    const candidate = new Uint8Array(2400).map((_, i) => (i * 11 + 9) & 0xff);

    const r = runHelper(acc, candidate);
    expect(r.success).toBe(true);
    if (!r.helperOutput) throw new Error("no helper output");

    const expected = expectedSerialized(acc, candidate);
    expect(r.helperOutput.length).toBe(expected.length);
    expect(toHex(r.helperOutput)).toBe(toHex(expected));
  });

  test("small candidate (size ∈ [128..255]): scriptnum/le-2b boundary case", () => {
    // sizes in this range are where scriptnum encoding requires explicit
    // sign byte (because high bit of single-byte rep would indicate negative).
    // OP_NUM2BIN(2) should produce exactly the LE 2-byte encoding regardless.
    const candidate = new Uint8Array(200).fill(0xab);
    const r = runHelper(new Uint8Array(), candidate);
    expect(r.success).toBe(true);
    if (!r.helperOutput) throw new Error("no helper output");

    const expected = expectedSerialized(new Uint8Array(), candidate);
    expect(toHex(r.helperOutput)).toBe(toHex(expected));
  });
});
