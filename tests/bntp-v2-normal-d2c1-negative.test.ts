/**
 * BNTP v2 Normal template — Phase 1B Wave D.2c.1 adversarial coverage.
 *
 * The D.2c.1 unified loop ships three non-trivial path-1 invariants:
 *   - per-tuple `marker == 0x01FF` (Normal-output marker)
 *   - per-tuple `depth == max_input_depth + 1` (rolling-freshness rule)
 *   - closing `Σ_in == Σ_out` (amount conservation)
 *
 * Each test crafts a malformed unlocking witness that violates exactly one
 * of these and asserts the script aborts. Reconstruction + hashOutputs
 * closure land in D.2c.2; M-/N-out-of-range coverage lands in D.2c.3.
 *
 * Test structure: build a canonical scenario via `assembleFlexTransferScenario`,
 * then re-emit the unlocking script with a single OutputTuple field mutated
 * (amount, newDepth, or owner-length). The preimage and owner sig from the
 * canonical assembly are reused as-is — the preimage's `hashOutputs` commits
 * to the canonical output, but D.2c.1 does not yet check hashOutputs against
 * the reconstructed candidate, so the stale commitment is irrelevant for
 * these tests.
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

const buildScenario = (): FlexTransferScenario => ({
  ownerKey: new PrivateKey(hexBytes(TEST_PRIVATE_KEY_HEX)),
  amount: BigInt(100),
  tokenId: new Uint8Array(32),
  issuerPkh: new Uint8Array(20).fill(0x11),
  authorityFlags: 0x00,
  freezeAuthHash: new Uint8Array(20),
  confiscAuthHash: new Uint8Array(20),
  inputAttestationDepth: 0,
  outputAttestationDepth: 1,
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
});

/**
 * Re-emit the unlocking script with a custom OutputTuple, reusing the
 * canonical preimage + owner sig from `assembleFlexTransferScenario`.
 * Returns the artifacts needed to drive `evaluateScripts`.
 */
const buildAdversarialAssembly = (
  scenario: FlexTransferScenario,
  customTuple: OutputTuple,
) => {
  const a = assembleFlexTransferScenario(scenario);
  const ownerPubkey = scenario.ownerKey.PublicKey;
  const sigDer = scenario.ownerKey.sign(hash256(a.preimage));
  const ownerSigWithType = concatBytes([
    sigDer,
    new Uint8Array([SIGHASH_ALL_FORKID]),
  ]);

  const unlockingScript = buildFlexTransferUnlocking({
    m: 1,
    outputTuples: [customTuple],
    amountsInArray: uint128LE(scenario.amount),
    allInputOutpoints: outpointBytes(scenario.inputTxIdBE, scenario.inputVout),
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

  return { unlockingScript, inputLockingScript: a.inputLockingScript, tx };
};

const evalAdversarial = (
  scenario: FlexTransferScenario,
  customTuple: OutputTuple,
) => {
  const { unlockingScript, inputLockingScript, tx } = buildAdversarialAssembly(
    scenario,
    customTuple,
  );
  const prevOutputs: PrevOutput[] = [
    { lockingScript: inputLockingScript, satoshis: scenario.inputSatoshis },
  ];
  return evaluateScripts(unlockingScript, inputLockingScript, {
    tx,
    inputIndex: 0,
    prevOutputs,
  }, {
    allowOpReturn: true,
    scriptFlags: FLAGS,
    strict: false,
    maxScriptSizeBytes: 2_000_000,
    maxOps: 100_000,
    maxStackDepth: 10_000,
    maxElementSizeBytes: 2_000_000,
  });
};

describe("BNTP v2 Normal — D.2c.1 adversarial coverage (path 1 conservation half)", () => {
  test("sum mismatch: tuple.amount != Σ(amounts_in_array) → closing NUMEQUALVERIFY aborts", () => {
    const scenario = buildScenario();
    const ownerPkh = (() => {
      const a = assembleFlexTransferScenario(scenario);
      return a.ownerPkh;
    })();
    // Canonical input amount is 100; tuple claims 99 → Σ_out = 99 ≠ Σ_in = 100.
    const malformedTuple: OutputTuple = {
      amount: BigInt(99),
      owner: ownerPkh,
      newDepth: 1,
      bodyMarker: new Uint8Array([0x01, 0xff]),
    };
    const r = evalAdversarial(scenario, malformedTuple);
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("depth skip: tuple.depth != max_input_depth + 1 → per-iter NUMEQUALVERIFY aborts", () => {
    const scenario = buildScenario();
    const ownerPkh = (() => {
      const a = assembleFlexTransferScenario(scenario);
      return a.ownerPkh;
    })();
    // max_input_depth = 0 → expected new_depth = 1; tuple skips to 2.
    const malformedTuple: OutputTuple = {
      amount: scenario.amount,
      owner: ownerPkh,
      newDepth: 2,
      bodyMarker: new Uint8Array([0x01, 0xff]),
    };
    const r = evalAdversarial(scenario, malformedTuple);
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("bad pkh size: tuple.owner = 19b → tuple parse misaligns marker; EQUALVERIFY aborts", () => {
    const scenario = buildScenario();
    // 19-byte owner instead of 20 — tuple total = 39b. SPLIT chain still
    // produces output but the final 2-byte marker slot ends up reading
    // a 1-byte trailing fragment, mismatching `01FF`.
    const malformedOwner = new Uint8Array(19).fill(0x42);
    const malformedTuple: OutputTuple = {
      amount: scenario.amount,
      owner: malformedOwner,
      newDepth: 1,
      bodyMarker: new Uint8Array([0x01, 0xff]),
    };
    const r = evalAdversarial(scenario, malformedTuple);
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });
});
