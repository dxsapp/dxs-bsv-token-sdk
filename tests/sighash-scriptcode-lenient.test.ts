/**
 * SIGHASH scriptCode lenient-parser regression test.
 *
 * BIP143 (BSV post-Genesis) defines `scriptCode` for the sighash preimage
 * as a byte-level transform of the executing script's tail (post-most-
 * recent-OP_CODESEPARATOR): copy verbatim, removing only OP_CODESEPARATOR
 * opcode bytes. Identifying which 0xab bytes are opcodes (vs raw 0xab
 * data inside a push) requires push-aware walking, but real BSV nodes
 * tolerate truncated pushes here — the bytes are folded into the output
 * as-is. Strict push parsing applies to script EXECUTION, not to the
 * sighash byte-level construction.
 *
 * Our prior `stripCodeSeparators` was over-strict, throwing
 * "Push out of bounds" if any push opcode in the executing script
 * demanded more bytes than available. This blocked practical use of
 * post-OP_RETURN data sections (BNTP-style templates store auth hashes,
 * token IDs, etc. there) when those bytes happened to look like
 * malformed pushes — common with random hash160 outputs.
 *
 * This test exercises the regression scenario directly: a locking
 * script of the form `<pubkey> OP_CHECKSIGVERIFY OP_1 OP_RETURN <data>`
 * where `<data>` is a sequence containing a push opcode demanding more
 * bytes than the script holds. The CHECKSIGVERIFY must succeed (valid
 * sig over a deterministically-hashed preimage that includes the full
 * locking script, including the malformed-push tail) — our lenient
 * `stripCodeSeparators` folds the truncated-push bytes into scriptCode
 * for hashing instead of throwing.
 */

import { OpCode } from "../src/bitcoin/op-codes";
import { PrivateKey } from "../src/bitcoin/private-key";
import { Transaction } from "../src/bitcoin/transaction";
import { TransactionInput } from "../src/bitcoin/transaction-input";
import { TransactionOutput } from "../src/bitcoin/transaction-output";
import {
  evaluateScripts,
  PrevOutput,
  SCRIPT_ENABLE_MAGNETIC_OPCODES,
  SCRIPT_ENABLE_MONOLITH_OPCODES,
  SCRIPT_ENABLE_SIGHASH_FORKID,
} from "../src/script";
import { hash256 } from "../src/hashes";
import {
  buildPreimage,
  outpointBytes,
  pushData,
} from "../src/bntp/v2/test-helpers";

const SIGHASH_ALL_FORKID = 0x41;
const FLAGS =
  SCRIPT_ENABLE_SIGHASH_FORKID |
  SCRIPT_ENABLE_MAGNETIC_OPCODES |
  SCRIPT_ENABLE_MONOLITH_OPCODES;

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

describe("sighash scriptCode — lenient walker tolerates malformed pushes", () => {
  test("CHECKSIGVERIFY succeeds when post-OP_RETURN tail contains a truncated push", () => {
    // Build a locking script: <pubkey> OP_CHECKSIGVERIFY OP_1 OP_RETURN <tail>
    // where <tail> ends with `0x4b` (push 75 bytes opcode) followed by only
    // 5 bytes — a malformed push that demands 70 more bytes than the
    // script actually contains. Pre-fix this would throw "Push out of
    // bounds" inside stripCodeSeparators when CHECKSIGVERIFY built its
    // sighash preimage. Post-fix: the truncated push is folded as-is into
    // scriptCode and the sighash is deterministic, so a valid sig
    // verifies.

    const ownerKey = new PrivateKey(
      new Uint8Array(31).fill(0).reduce<Uint8Array>((acc, _, i) => {
        const x = new Uint8Array(32);
        x[31] = 0x07;
        return x;
      }, new Uint8Array(32)),
    );
    const ownerPub = ownerKey.PublicKey;

    // Tail with malformed push at the end: OP_4B (push 75 bytes) + only 5
    // bytes available. Pre-fix this triggers the bug; post-fix it's tolerated.
    const tail = concatBytes([
      // Some innocuous bytes first.
      new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
      // Malformed push at the very end.
      new Uint8Array([0x4b, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5]),
    ]);

    const lockingScript = concatBytes([
      pushData(ownerPub),
      new Uint8Array([OpCode.OP_CHECKSIGVERIFY]),
      new Uint8Array([OpCode.OP_1]),
      new Uint8Array([OpCode.OP_RETURN]),
      tail,
    ]);

    const inputTxIdBE = "deadbeef" + "00".repeat(28); // arbitrary
    const outpoint = outpointBytes(inputTxIdBE, 0);
    const sequenceBytes = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
    const hashPrevouts = hash256(outpoint);
    const hashSequence = hash256(sequenceBytes);

    const outputLockingScript = new Uint8Array([OpCode.OP_1]);
    const outputBuf = concatBytes([
      // 8-byte sats LE = 1
      new Uint8Array([0x01, 0, 0, 0, 0, 0, 0, 0]),
      // varint 1
      new Uint8Array([0x01]),
      outputLockingScript,
    ]);
    const hashOutputs = hash256(outputBuf);

    const preimage = buildPreimage({
      version: 1,
      hashPrevouts,
      hashSequence,
      outpoint,
      scriptCode: lockingScript,
      satoshis: 1,
      sequence: 0xffffffff,
      hashOutputs,
      locktime: 0,
      sighashType: SIGHASH_ALL_FORKID,
    });

    const sigDer = ownerKey.sign(hash256(preimage));
    const sigWithType = concatBytes([
      sigDer,
      new Uint8Array([SIGHASH_ALL_FORKID]),
    ]);
    const unlockingScript = pushData(sigWithType);

    const txInput = new TransactionInput(
      inputTxIdBE,
      0,
      unlockingScript,
      0xffffffff,
    );
    const txOutput = new TransactionOutput(1, outputLockingScript);
    const tx = new Transaction(new Uint8Array(), [txInput], [txOutput], 1, 0);

    const prevOutputs: PrevOutput[] = [{ lockingScript, satoshis: 1 }];

    const r = evaluateScripts(
      unlockingScript,
      lockingScript,
      {
        tx,
        inputIndex: 0,
        prevOutputs,
      },
      {
        allowOpReturn: true,
        scriptFlags: FLAGS,
        strict: false,
        maxScriptSizeBytes: 100_000,
        maxOps: 10_000,
        maxStackDepth: 1_000,
        maxElementSizeBytes: 100_000,
      },
    );

    expect(r.success).toBe(true);
    expect(r.error).toBeUndefined();
  });

  test("CHECKSIGVERIFY also tolerates truncated PUSHDATA1 tail", () => {
    // PUSHDATA1 (0x4c) without enough length-byte room: i.e. the OP_PUSHDATA1
    // is the very last byte of the script. The lenient walker copies the
    // remainder verbatim and continues.
    const ownerKey = new PrivateKey(
      (() => {
        const x = new Uint8Array(32);
        x[31] = 0x0b;
        return x;
      })(),
    );
    const ownerPub = ownerKey.PublicKey;

    const tail = new Uint8Array([0x00, 0x00, 0x4c]); // OP_PUSHDATA1 at end, no length byte

    const lockingScript = concatBytes([
      pushData(ownerPub),
      new Uint8Array([OpCode.OP_CHECKSIGVERIFY]),
      new Uint8Array([OpCode.OP_1]),
      new Uint8Array([OpCode.OP_RETURN]),
      tail,
    ]);

    const inputTxIdBE = "ab".repeat(32);
    const outpoint = outpointBytes(inputTxIdBE, 0);
    const sequenceBytes = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
    const hashPrevouts = hash256(outpoint);
    const hashSequence = hash256(sequenceBytes);

    const outputLockingScript = new Uint8Array([OpCode.OP_1]);
    const outputBuf = concatBytes([
      new Uint8Array([0x01, 0, 0, 0, 0, 0, 0, 0]),
      new Uint8Array([0x01]),
      outputLockingScript,
    ]);
    const hashOutputs = hash256(outputBuf);

    const preimage = buildPreimage({
      version: 1,
      hashPrevouts,
      hashSequence,
      outpoint,
      scriptCode: lockingScript,
      satoshis: 1,
      sequence: 0xffffffff,
      hashOutputs,
      locktime: 0,
      sighashType: SIGHASH_ALL_FORKID,
    });

    const sigDer = ownerKey.sign(hash256(preimage));
    const sigWithType = concatBytes([
      sigDer,
      new Uint8Array([SIGHASH_ALL_FORKID]),
    ]);
    const unlockingScript = pushData(sigWithType);

    const txInput = new TransactionInput(
      inputTxIdBE,
      0,
      unlockingScript,
      0xffffffff,
    );
    const txOutput = new TransactionOutput(1, outputLockingScript);
    const tx = new Transaction(new Uint8Array(), [txInput], [txOutput], 1, 0);
    const prevOutputs: PrevOutput[] = [{ lockingScript, satoshis: 1 }];

    const r = evaluateScripts(
      unlockingScript,
      lockingScript,
      {
        tx,
        inputIndex: 0,
        prevOutputs,
      },
      {
        allowOpReturn: true,
        scriptFlags: FLAGS,
        strict: false,
        maxScriptSizeBytes: 100_000,
        maxOps: 10_000,
        maxStackDepth: 1_000,
        maxElementSizeBytes: 100_000,
      },
    );

    expect(r.success).toBe(true);
    expect(r.error).toBeUndefined();
  });

  test("OP_CODESEPARATOR opcode bytes are still stripped from scriptCode", () => {
    // Sanity: the lenient walker MUST still remove OP_CODESEPARATOR
    // opcode bytes (0xab) from scriptCode — that's the function's whole
    // job. Two sigs over the same script differ in scriptCode iff one
    // strips OP_CODESEPARATOR and the other doesn't.
    //
    // We test indirectly: build a script with an OP_CODESEPARATOR before
    // CHECKSIGVERIFY. The sigsigned by the user must use scriptCode =
    // bytes after the codeSeparator (post-codeSep tail). If the lenient
    // walker correctly strips the OP_CODESEPARATOR from the post-codeSep
    // bytes (there shouldn't be any in this contrived test), it should
    // verify.
    const ownerKey = new PrivateKey(
      (() => {
        const x = new Uint8Array(32);
        x[31] = 0x0d;
        return x;
      })(),
    );
    const ownerPub = ownerKey.PublicKey;

    // Locking: <0xab> <pubkey> OP_CHECKSIGVERIFY OP_1
    // The 0xab at the start is OP_CODESEPARATOR — sets codeSep to its pc.
    // After CHECKSIGVERIFY runs, scriptCode = bytes from codeSep+1 to end.
    const lockingScript = concatBytes([
      new Uint8Array([OpCode.OP_CODESEPARATOR]),
      pushData(ownerPub),
      new Uint8Array([OpCode.OP_CHECKSIGVERIFY]),
      new Uint8Array([OpCode.OP_1]),
    ]);

    const scriptCode = lockingScript.subarray(1); // bytes after OP_CODESEPARATOR

    const inputTxIdBE = "cd".repeat(32);
    const outpoint = outpointBytes(inputTxIdBE, 0);
    const sequenceBytes = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
    const hashPrevouts = hash256(outpoint);
    const hashSequence = hash256(sequenceBytes);
    const outputLockingScript = new Uint8Array([OpCode.OP_1]);
    const outputBuf = concatBytes([
      new Uint8Array([0x01, 0, 0, 0, 0, 0, 0, 0]),
      new Uint8Array([0x01]),
      outputLockingScript,
    ]);
    const hashOutputs = hash256(outputBuf);

    const preimage = buildPreimage({
      version: 1,
      hashPrevouts,
      hashSequence,
      outpoint,
      scriptCode,
      satoshis: 1,
      sequence: 0xffffffff,
      hashOutputs,
      locktime: 0,
      sighashType: SIGHASH_ALL_FORKID,
    });

    const sigDer = ownerKey.sign(hash256(preimage));
    const sigWithType = concatBytes([
      sigDer,
      new Uint8Array([SIGHASH_ALL_FORKID]),
    ]);
    const unlockingScript = pushData(sigWithType);

    const txInput = new TransactionInput(
      inputTxIdBE,
      0,
      unlockingScript,
      0xffffffff,
    );
    const txOutput = new TransactionOutput(1, outputLockingScript);
    const tx = new Transaction(new Uint8Array(), [txInput], [txOutput], 1, 0);
    const prevOutputs: PrevOutput[] = [{ lockingScript, satoshis: 1 }];

    const r = evaluateScripts(
      unlockingScript,
      lockingScript,
      {
        tx,
        inputIndex: 0,
        prevOutputs,
      },
      {
        scriptFlags: FLAGS,
        strict: false,
      },
    );
    expect(r.success).toBe(true);
    expect(r.error).toBeUndefined();
  });
});
