/**
 * BNTP v2 Normal template — Phase 1B Wave D.2c.2 adversarial coverage.
 *
 * D.2c.2 ships per-iter output reconstruction + closing
 * HASH256+EQUALVERIFY against zone.hashOutputs (slot 3, signed via the
 * SIGHASH preimage). The natural D.2c.2-specific failure mode is a
 * RECONSTRUCTION/COMMITMENT mismatch: the tuple+zone produce bytes that
 * pass all D.2c.1 invariants but whose HASH256 differs from the preimage-
 * committed hashOutputs.
 *
 * This test crafts such a scenario by setting the canonical scenario's
 * `outputAttestationDepth` to 2 (so preimage.hashOutputs commits to an
 * output whose tail-depth is `0200`) while pushing a malformed tuple with
 * `newDepth = 1` (which still satisfies the per-iter depth check
 * `tuple.depth == max_input_depth + 1`, since max_input_depth = 0). The
 * reconstruction produces output bytes containing tail-depth `0100`, and
 * HASH256(reconstructed) ≠ zone.hashOutputs → closing aborts.
 *
 * D.2c.1 negatives (sum mismatch, depth skip, bad pkh size) live in
 * tests/bntp-v2-normal-d2c1-negative.test.ts and continue to apply on
 * top of D.2c.2 (they fire EARLIER than the closing hashOutputs check).
 * D.2c.3 will add N-/M-out-of-range coverage.
 */

import {
  assembleFlexTransferScenario,
  buildFlexTransferUnlocking,
  FlexTransferScenario,
  OutputTuple,
  outpointBytes,
  uint128LE,
} from "../src/bntp/v2/test-helpers";
import { hash256 } from "../src/hashes";
import {
  evaluateScripts,
  PrevOutput,
  SCRIPT_ENABLE_MAGNETIC_OPCODES,
  SCRIPT_ENABLE_MONOLITH_OPCODES,
  SCRIPT_ENABLE_SIGHASH_FORKID,
} from "../src/script";
import { PrivateKey } from "../src/bitcoin/private-key";
import { TransactionInput } from "../src/bitcoin/transaction-input";
import { TransactionOutput } from "../src/bitcoin/transaction-output";
import { Transaction } from "../src/bitcoin/transaction";

const TEST_PRIVATE_KEY_HEX =
  "0000000000000000000000000000000000000000000000000000000000000042";

const SIGHASH_ALL_FORKID = 0x41;

const FLAGS =
  SCRIPT_ENABLE_SIGHASH_FORKID |
  SCRIPT_ENABLE_MAGNETIC_OPCODES |
  SCRIPT_ENABLE_MONOLITH_OPCODES;

const hexBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

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

describe("BNTP v2 Normal — D.2c.2 adversarial coverage (hashOutputs commitment)", () => {
  test("hashOutputs mismatch: tuple.newDepth = 1 but actual output's tail-depth = 2 → closing OP_EQUALVERIFY aborts", () => {
    // Scenario: max_input_depth = 0, so tuple.newDepth = 1 satisfies the
    // per-iter rolling-freshness check. But the canonical tx output's tail
    // attestationDepth is set to 2, so preimage.hashOutputs commits to an
    // output whose tail-depth bytes are `0200`. Reconstruction uses the
    // tuple's newDepth (= 1, bytes `0100`) → byte-exact mismatch at the
    // closing HASH256+EQUALVERIFY against zone.hashOutputs.
    const scenario: FlexTransferScenario = {
      ownerKey: new PrivateKey(hexBytes(TEST_PRIVATE_KEY_HEX)),
      amount: BigInt(100),
      tokenId: new Uint8Array(32),
      issuerPkh: new Uint8Array(20).fill(0x11),
      authorityFlags: 0x00,
      freezeAuthHash: new Uint8Array(20),
      confiscAuthHash: new Uint8Array(20),
      inputAttestationDepth: 0,
      outputAttestationDepth: 2, // <-- preimage commits to depth=2
      optionalData: new Uint8Array(),
      inputTxIdBE:
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      inputVout: 0,
      inputSatoshis: 1,
      outputSatoshis: 1,
      selfPosition: 0,
      maxInputDepth: 0,
      sequence: 0xffffffff,
      version: 1,
      locktime: 0,
    };

    const a = assembleFlexTransferScenario(scenario);

    // Sign over the canonical preimage (commits to depth=2 hashOutputs).
    const ownerPubkey = scenario.ownerKey.PublicKey;
    const sigDer = scenario.ownerKey.sign(hash256(a.preimage));
    const ownerSigWithType = concatBytes([
      sigDer,
      new Uint8Array([SIGHASH_ALL_FORKID]),
    ]);

    // Build unlocking with tuple.newDepth = 1 (passes D.2c.1 depth check).
    const malformedTuple: OutputTuple = {
      amount: scenario.amount,
      owner: a.ownerPkh,
      newDepth: 1, // <-- mismatch: actual output tail depth is 2
      bodyMarker: new Uint8Array([0x01, 0xff]),
    };
    const unlockingScript = buildFlexTransferUnlocking({
      m: 1,
      outputTuples: [malformedTuple],
      amountsInArray: uint128LE(scenario.amount),
      allInputOutpoints: outpointBytes(
        scenario.inputTxIdBE,
        scenario.inputVout,
      ),
      selfPosition: scenario.selfPosition,
      maxInputDepth: scenario.maxInputDepth,
      nullData: new Uint8Array(),
      fundingOutpoint: new Uint8Array(),
      preimage: a.preimage,
      pathId: 1,
      ownerSigWithType,
      ownerPubkey,
    });

    const txInput = new TransactionInput(
      scenario.inputTxIdBE,
      scenario.inputVout,
      unlockingScript,
      scenario.sequence,
    );
    const txOutput = new TransactionOutput(
      scenario.outputSatoshis,
      a.outputLockingScript,
    );
    const tx = new Transaction(
      new Uint8Array(),
      [txInput],
      [txOutput],
      scenario.version,
      scenario.locktime,
    );
    const prevOutputs: PrevOutput[] = [
      { lockingScript: a.inputLockingScript, satoshis: scenario.inputSatoshis },
    ];

    const r = evaluateScripts(
      unlockingScript,
      a.inputLockingScript,
      {
        tx,
        inputIndex: 0,
        prevOutputs,
      },
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
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });
});
