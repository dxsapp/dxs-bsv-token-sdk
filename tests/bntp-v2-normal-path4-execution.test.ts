/**
 * BNTP v2 Normal template — Path 4 (confiscate) end-to-end execution test
 * (Phase 1B Wave D.3.1).
 *
 * Per spec §9.5: confiscate is a pure ownership change. confiscAuth signs
 * a tx producing 1 Normal output with:
 *   - amount = my_amount (preserved)
 *   - owner = new_owner (authority chooses, supplied via output_tuple)
 *   - new_depth = my_depth (PRESERVED — Step C decision #39)
 *   - all other tail fields preserved (tokenId, issuerPkh, authFlags,
 *     freezeAuthHash, confiscAuthHash, optionalData)
 *
 * Owner does NOT sign on path 4 — that's the whole point of confiscation.
 * The D.3-prep refactor (commit 80079d7) extracted owner-sig from PREFIX
 * into per-path SUFFIX, enabling paths 3/4 to use authority-only auth.
 */

import {
  buildNormalLockingScript,
  buildPreimage,
  NormalTail,
  outpointBytes,
  pushData,
  scriptNumPush,
  serializeOutput,
  serializeOutputTuple,
  uint128LE,
  uint16LE,
  OutputTuple,
} from "../src/bntp/v2/test-helpers";
import { hash160, hash256 } from "../src/hashes";
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
import { Bytes } from "../src/bytes";

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

const concatBytes = (parts: Bytes[]): Uint8Array => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

type ConfiscateScenario = {
  ownerKey: PrivateKey; // original owner — does NOT sign
  confiscAuthKey: PrivateKey; // confiscation authority — signs
  newOwnerPkh: Bytes; // 20b new owner (from tuple)
  amount: bigint;
  tokenId: Bytes;
  issuerPkh: Bytes;
  authorityFlags: number; // must have bit 1 set (0x02 confiscatable)
  freezeAuthHash: Bytes;
  attestationDepth: number; // preserved on confiscate
  optionalData: Bytes;
  inputTxIdBE: string;
  inputVout: number;
  inputSatoshis: number;
  outputSatoshis: number;
  sequence: number;
  version: number;
  locktime: number;
};

/**
 * Path 4 confiscate unlocking layout per spec §9.5 (and dispatcher contract):
 *
 *   [output_tuple]            (40b: amount16 ‖ newOwner20 ‖ depth2 ‖ marker2)
 *                             — pushed first → bottom of stack
 *   [funding_outpoint]        (0 or 36b)
 *   [preimage]                (var)
 *   [OP_4]                    (path_id = 4)
 *   [confiscAuth_sig]         (DER + 0x41 sighash byte)
 *   [confiscAuth_pubkey]      (compressed 33b)
 *                             — pushed last → top of stack
 *
 * Per spec §9.5: null-data and change outputs DISALLOWED on confiscate.
 */
const buildConfiscateUnlocking = (
  outputTuple: OutputTuple,
  fundingOutpoint: Bytes,
  preimage: Bytes,
  authSigWithType: Bytes,
  authPubkey: Bytes,
): Uint8Array => {
  return concatBytes([
    pushData(serializeOutputTuple(outputTuple)),
    pushData(fundingOutpoint),
    pushData(preimage),
    scriptNumPush(4), // path_id = 4
    pushData(authSigWithType),
    pushData(authPubkey),
  ]);
};

const assembleConfiscateScenario = (s: ConfiscateScenario) => {
  const ownerPkh = hash160(s.ownerKey.PublicKey);
  const confiscAuthPubkey = s.confiscAuthKey.PublicKey;
  const confiscAuthHash = hash160(confiscAuthPubkey);

  // Source UTXO tail. Confiscation preserves all tail fields.
  const tail: NormalTail = {
    tokenId: s.tokenId,
    issuerPkh: s.issuerPkh,
    amount: s.amount,
    authorityFlags: s.authorityFlags,
    freezeAuthHash: s.freezeAuthHash,
    confiscAuthHash,
    attestationDepth: s.attestationDepth,
    optionalData: s.optionalData,
  };
  const inputLockingScript = buildNormalLockingScript(ownerPkh, tail);
  // Output: same tail bytes, but variable prefix has newOwner.
  const outputLockingScript = buildNormalLockingScript(s.newOwnerPkh, tail);

  const outpoint = outpointBytes(s.inputTxIdBE, s.inputVout);
  const hashPrevouts = hash256(outpoint);
  const sequenceBytes = new Uint8Array(4);
  sequenceBytes[0] = s.sequence & 0xff;
  sequenceBytes[1] = (s.sequence >> 8) & 0xff;
  sequenceBytes[2] = (s.sequence >> 16) & 0xff;
  sequenceBytes[3] = (s.sequence >> 24) & 0xff;
  const hashSequence = hash256(sequenceBytes);

  const outputSerialized = serializeOutput(
    s.outputSatoshis,
    outputLockingScript,
  );
  const hashOutputs = hash256(outputSerialized);

  const preimage = buildPreimage({
    version: s.version,
    hashPrevouts,
    hashSequence,
    outpoint,
    scriptCode: inputLockingScript,
    satoshis: s.inputSatoshis,
    sequence: s.sequence,
    hashOutputs,
    locktime: s.locktime,
    sighashType: SIGHASH_ALL_FORKID,
  });

  // Sign preimage with confiscAuth (not owner).
  const sigHash = hash256(preimage);
  const confiscAuthSigDer = s.confiscAuthKey.sign(sigHash);
  const confiscAuthSigWithType = concatBytes([
    confiscAuthSigDer,
    new Uint8Array([SIGHASH_ALL_FORKID]),
  ]);

  const outputTuple: OutputTuple = {
    amount: s.amount, // preserved
    owner: s.newOwnerPkh,
    newDepth: s.attestationDepth, // preserved
    bodyMarker: new Uint8Array([0x01, 0xff]),
  };

  const unlockingScript = buildConfiscateUnlocking(
    outputTuple,
    new Uint8Array(), // no funding input
    preimage,
    confiscAuthSigWithType,
    confiscAuthPubkey,
  );

  const txInput = new TransactionInput(
    s.inputTxIdBE,
    s.inputVout,
    unlockingScript,
    s.sequence,
  );
  const txOutput = new TransactionOutput(s.outputSatoshis, outputLockingScript);
  const tx = new Transaction(
    new Uint8Array(),
    [txInput],
    [txOutput],
    s.version,
    s.locktime,
  );

  return {
    ownerPkh,
    confiscAuthHash,
    confiscAuthPubkey,
    inputLockingScript,
    outputLockingScript,
    preimage,
    unlockingScript,
    tx,
    outputTuple,
  };
};

// confiscAuthKey is an arbitrary 32-byte priv (any value works post the
// sighash scriptCode lenient-walker fix — see
// `tests/sighash-scriptcode-lenient.test.ts`). Pre-fix this test had to
// brute-force a key whose HASH160 produced only "safe" bytes (no push
// opcodes demanding more bytes than the script's tail held), and depth
// was capped at {0, 1}. The fix in `stripCodeSeparators` (lenient
// byte-walker for sighash scriptCode construction) removed that
// restriction by matching real BSV's tolerant FindAndDelete-equivalent
// behaviour.
const buildBaseScenario = (): ConfiscateScenario => ({
  ownerKey: new PrivateKey(
    hexBytes(
      "0000000000000000000000000000000000000000000000000000000000000042",
    ),
  ),
  confiscAuthKey: new PrivateKey(
    hexBytes(
      "0000000000000000000000000000000000000000000000000000000000000099",
    ),
  ),
  newOwnerPkh: new Uint8Array(20).fill(0xaa),
  amount: BigInt(100),
  tokenId: new Uint8Array(32),
  issuerPkh: new Uint8Array(20).fill(0x11),
  authorityFlags: 0x02, // bit 1 = confiscatable enabled, no MPKH bits
  freezeAuthHash: new Uint8Array(20),
  attestationDepth: 5, // arbitrary non-zero — exercises depth-preservation
  optionalData: new Uint8Array(),
  inputTxIdBE:
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  inputVout: 0,
  inputSatoshis: 1,
  outputSatoshis: 1,
  sequence: 0xffffffff,
  version: 1,
  locktime: 0,
});

describe("BNTP v2 Normal — Path 4 confiscate (Wave D.3.1 execution)", () => {
  test("positive: confiscAuth-signed confiscate succeeds end-to-end", () => {
    const scenario = buildBaseScenario();
    const a = assembleConfiscateScenario(scenario);

    const prevOutputs: PrevOutput[] = [
      { lockingScript: a.inputLockingScript, satoshis: scenario.inputSatoshis },
    ];

    const r = evaluateScripts(
      a.unlockingScript,
      a.inputLockingScript,
      { tx: a.tx, inputIndex: 0, prevOutputs },
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
    expect(r.success).toBe(true);
    expect(r.error).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // Negative tests — adversarial coverage of D.3.1 invariants
  // ---------------------------------------------------------------------------

  const evalAdversarial = (
    sigKey: PrivateKey,
    customTuple: OutputTuple,
    customAuthorityFlags: number,
  ) => {
    const scenario = buildBaseScenario();
    if (customAuthorityFlags !== scenario.authorityFlags) {
      scenario.authorityFlags = customAuthorityFlags;
    }

    const ownerPkh = hash160(scenario.ownerKey.PublicKey);
    const confiscAuthHash = hash160(scenario.confiscAuthKey.PublicKey);

    const inputTail: NormalTail = {
      tokenId: scenario.tokenId,
      issuerPkh: scenario.issuerPkh,
      amount: scenario.amount,
      authorityFlags: scenario.authorityFlags,
      freezeAuthHash: scenario.freezeAuthHash,
      confiscAuthHash,
      attestationDepth: scenario.attestationDepth,
      optionalData: scenario.optionalData,
    };
    const inputLockingScript = buildNormalLockingScript(ownerPkh, inputTail);
    const outputLockingScript = buildNormalLockingScript(
      scenario.newOwnerPkh,
      inputTail,
    );

    const outpoint = outpointBytes(scenario.inputTxIdBE, scenario.inputVout);
    const hashPrevouts = hash256(outpoint);
    const sequenceBytes = new Uint8Array(4);
    sequenceBytes[0] = scenario.sequence & 0xff;
    sequenceBytes[1] = (scenario.sequence >> 8) & 0xff;
    sequenceBytes[2] = (scenario.sequence >> 16) & 0xff;
    sequenceBytes[3] = (scenario.sequence >> 24) & 0xff;
    const hashSequence = hash256(sequenceBytes);
    const outputSerialized = serializeOutput(
      scenario.outputSatoshis,
      outputLockingScript,
    );
    const hashOutputs = hash256(outputSerialized);

    const preimage = buildPreimage({
      version: scenario.version,
      hashPrevouts,
      hashSequence,
      outpoint,
      scriptCode: inputLockingScript,
      satoshis: scenario.inputSatoshis,
      sequence: scenario.sequence,
      hashOutputs,
      locktime: scenario.locktime,
      sighashType: SIGHASH_ALL_FORKID,
    });
    const sigDer = sigKey.sign(hash256(preimage));
    const authSigWithType = concatBytes([
      sigDer,
      new Uint8Array([SIGHASH_ALL_FORKID]),
    ]);

    const unlockingScript = buildConfiscateUnlocking(
      customTuple,
      new Uint8Array(),
      preimage,
      authSigWithType,
      sigKey.PublicKey,
    );

    const txInput = new TransactionInput(
      scenario.inputTxIdBE,
      scenario.inputVout,
      unlockingScript,
      scenario.sequence,
    );
    const txOutput = new TransactionOutput(
      scenario.outputSatoshis,
      outputLockingScript,
    );
    const tx = new Transaction(
      new Uint8Array(),
      [txInput],
      [txOutput],
      scenario.version,
      scenario.locktime,
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

  test("negative: authorityFlags bit 1 NOT set → script aborts (confiscatable disabled)", () => {
    const scenario = buildBaseScenario();
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: scenario.newOwnerPkh,
      newDepth: scenario.attestationDepth,
      bodyMarker: new Uint8Array([0x01, 0xff]),
    };
    // authorityFlags = 0 → bit 1 (confiscatable) NOT set.
    const r = evalAdversarial(scenario.confiscAuthKey, tuple, 0x00);
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("negative: wrong key signs (not confiscAuth) → auth-identity check aborts", () => {
    const scenario = buildBaseScenario();
    const wrongKey = new PrivateKey(
      hexBytes(
        "0000000000000000000000000000000000000000000000000000000000000042",
      ),
    );
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: scenario.newOwnerPkh,
      newDepth: scenario.attestationDepth,
      bodyMarker: new Uint8Array([0x01, 0xff]),
    };
    const r = evalAdversarial(wrongKey, tuple, scenario.authorityFlags);
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("negative: tuple.amount != zone.amount → conservation check aborts", () => {
    const scenario = buildBaseScenario();
    const tuple: OutputTuple = {
      amount: BigInt(99), // canonical = 100
      owner: scenario.newOwnerPkh,
      newDepth: scenario.attestationDepth,
      bodyMarker: new Uint8Array([0x01, 0xff]),
    };
    const r = evalAdversarial(
      scenario.confiscAuthKey,
      tuple,
      scenario.authorityFlags,
    );
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("negative: tuple.depth != zone.depth → depth-preservation check aborts", () => {
    const scenario = buildBaseScenario();
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: scenario.newOwnerPkh,
      newDepth: 0, // canonical preserved value = 1
      bodyMarker: new Uint8Array([0x01, 0xff]),
    };
    const r = evalAdversarial(
      scenario.confiscAuthKey,
      tuple,
      scenario.authorityFlags,
    );
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("negative: tuple.marker != 0x01FF → marker check aborts", () => {
    const scenario = buildBaseScenario();
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: scenario.newOwnerPkh,
      newDepth: scenario.attestationDepth,
      bodyMarker: new Uint8Array([0x02, 0xff]), // not Normal marker
    };
    const r = evalAdversarial(
      scenario.confiscAuthKey,
      tuple,
      scenario.authorityFlags,
    );
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });
});
