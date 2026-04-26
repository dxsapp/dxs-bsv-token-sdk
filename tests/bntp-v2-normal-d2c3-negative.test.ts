/**
 * BNTP v2 Normal template — Phase 1B Wave D.2c.3 adversarial coverage:
 * N-out-of-range and M-out-of-range witness coverage.
 *
 * These tests round out the D.2c invariant set by checking that the
 * pre-loop validation rejects malformed witness shape (D.2a P2 / P7):
 *   - N must be in [1, 4] (derived from |all_input_outpoints| / 36).
 *   - M must be in [1, N] (signature-set authority count).
 *
 * Both witness shapes also fail the canonical hashPrevouts binding
 * (`HASH256(all_input_outpoints ‖ funding) == zone.hashPrevouts`) when
 * the input-outpoints array is mutated; the script aborts somewhere in
 * the path-1 pipeline regardless. The assertion target is
 * `success === false` — exact failure point may be HASH_PREVOUTS_BIND
 * (P1), N range (P2), amounts-length (P3), or M range (P7), depending
 * on which check fires first for the specific malformation.
 *
 * D.2c.1 negatives: sum mismatch, depth skip, bad pkh size.
 * D.2c.2 negative:  hashOutputs commitment mismatch.
 * D.2c.3 negatives: this file — N-out-of-range, M-out-of-range.
 */

import {
  assembleFlexTransferScenario,
  buildFlexTransferUnlocking,
  FlexTransferScenario,
  outpointBytes,
  uint128LE,
  scriptNumPush,
  pushData,
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
 * Build an adversarial assembly with overrides for `m` (= claimed M
 * count) and a custom `allInputOutpointsBytes` (raw bytes for the
 * outpoints array; canonical is 1×36b for our N=1 scenario). Reuses
 * the canonical preimage + owner sig (preimage commits to the canonical
 * hashPrevouts; mutating allInputOutpoints will surface as either an
 * upstream HASH_PREVOUTS abort or a downstream N/M range abort
 * depending on which path-1 check fires first).
 */
const buildAdversarialAssembly = (
  scenario: FlexTransferScenario,
  overrides: { m?: number; allInputOutpointsBytes?: Uint8Array },
) => {
  const a = assembleFlexTransferScenario(scenario);
  const ownerPubkey = scenario.ownerKey.PublicKey;
  const sigDer = scenario.ownerKey.sign(hash256(a.preimage));
  const ownerSigWithType = concatBytes([
    sigDer,
    new Uint8Array([SIGHASH_ALL_FORKID]),
  ]);

  const canonicalOutpoints = outpointBytes(
    scenario.inputTxIdBE,
    scenario.inputVout,
  );
  const canonicalTuple = {
    amount: scenario.amount,
    owner: a.ownerPkh,
    newDepth: scenario.outputAttestationDepth,
    bodyMarker: new Uint8Array([0x01, 0xff]),
  };

  // We bypass `buildFlexTransferUnlocking` because it pushes M via the
  // ScriptNum encoder which only accepts canonical small integers. M=0
  // and M=2 are still valid ScriptNum values and the helper handles
  // them, but we may want raw control later — for now use the helper.
  const unlockingScript = buildFlexTransferUnlocking({
    m: overrides.m ?? 1,
    outputTuples: [canonicalTuple],
    amountsInArray: uint128LE(scenario.amount),
    allInputOutpoints: overrides.allInputOutpointsBytes ?? canonicalOutpoints,
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
  overrides: { m?: number; allInputOutpointsBytes?: Uint8Array },
) => {
  const { unlockingScript, inputLockingScript, tx } = buildAdversarialAssembly(
    scenario,
    overrides,
  );
  const prevOutputs: PrevOutput[] = [
    { lockingScript: inputLockingScript, satoshis: scenario.inputSatoshis },
  ];
  return evaluateScripts(
    unlockingScript,
    inputLockingScript,
    { tx, inputIndex: 0, prevOutputs },
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
};

describe("BNTP v2 Normal — D.2c.3 adversarial coverage (N/M out of range)", () => {
  test("N out of range (low): allInputOutpoints empty (N=0) → script aborts", () => {
    // N is derived from |all_input_outpoints| / 36 with `OP_1 OP_5 OP_WITHIN`
    // enforcing N ∈ [1, 4]. An empty array gives N=0 which is below the
    // floor. Note: this also fails HASH_PREVOUTS_BIND (HASH256(empty ‖
    // funding) ≠ preimage.hashPrevouts) — the script aborts on whichever
    // check fires first. Either way the witness is rejected.
    const scenario = buildScenario();
    const r = evalAdversarial(scenario, {
      allInputOutpointsBytes: new Uint8Array(),
    });
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("N out of range (high): allInputOutpoints = 5×36b (N=5) → script aborts", () => {
    // N=5 is above the OP_WITHIN [1, 5) ceiling (max N = 4). 5 valid-
    // looking outpoints (canonical first, four padding) keep the array
    // length divisible by 36 so the OP_MOD check passes; the
    // OP_WITHIN check should reject.
    const scenario = buildScenario();
    const canonical = outpointBytes(scenario.inputTxIdBE, scenario.inputVout);
    const fakeOutpoint = new Uint8Array(36).fill(0x55);
    const fiveOutpoints = concatBytes([
      canonical,
      fakeOutpoint,
      fakeOutpoint,
      fakeOutpoint,
      fakeOutpoint,
    ]);
    const r = evalAdversarial(scenario, {
      allInputOutpointsBytes: fiveOutpoints,
    });
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("M out of range (low): M=0 → M_RANGE OP_VERIFY aborts", () => {
    // M ∈ [1, N] enforced by D.2a M_RANGE block (`M ≥ 1 OP_VERIFY` first,
    // then `M ≤ N OP_VERIFY`). M=0 fails the lower bound.
    const scenario = buildScenario();
    const r = evalAdversarial(scenario, { m: 0 });
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("M out of range (high): M=2 with N=1 → M_RANGE OP_VERIFY aborts", () => {
    // M ≤ N enforced by M_RANGE second VERIFY. With N=1 (canonical),
    // M=2 fails the upper bound.
    const scenario = buildScenario();
    const r = evalAdversarial(scenario, { m: 2 });
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });
});
