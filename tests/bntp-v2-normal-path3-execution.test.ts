/**
 * BNTP v2 Normal template — Path 3 (freeze) end-to-end execution test
 * (Phase 1B Wave D.3.2).
 *
 * Per spec §9.4: freeze produces 1 Frozen output preserving amount,
 * owner, depth, and every tail field of the source Normal UTXO.
 * freezeAuth signs (PKH-only for now). Unlocking pushes the actual
 * Frozen template body bytes; locking verifies SHA256(pushed) == the
 * embedded h_Frozen constant before splicing them into the candidate
 * Frozen output's script.
 *
 * Owner does NOT sign on path 3 — analogous to path 4. The D.3-prep
 * refactor extracted owner-sig from PREFIX into per-path SUFFIX,
 * enabling paths 3/4 to use authority-only auth.
 *
 * Bug-fix coverage: D.3.2 also fixes a Phase 1A bug in PATH3_FREEZE_ASM
 * where the candidate Frozen variable-prefix wrote `026D` (push-2-bytes
 * opcode + data byte) instead of `526D` (OP_2 opcode + OP_2DROP). Pre-fix,
 * the produced Frozen UTXO would be unspendable; the EQUALVERIFY against
 * zone.hashOutputs in path 3 would fail because the real (correct) output
 * locking script's bytes diverge from what the buggy reconstruction
 * produced. This test pins the post-fix `526D` byte sequence.
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
import { FROZEN_BODY_BYTES } from "../src/bntp/v2/templates/frozen-body";
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

/**
 * Build the Frozen UTXO locking script. Frozen action_data is OP_2 (0x52)
 * per spec §3 template catalog — distinct from Normal's OP_0 (0x00).
 */
const buildFrozenLockingScript = (
  ownerPkh: Bytes,
  tail: NormalTail,
): Uint8Array => {
  const tailBytes = concatBytes([
    tail.tokenId,
    tail.issuerPkh,
    uint128LE(tail.amount),
    new Uint8Array([tail.authorityFlags & 0xff]),
    tail.freezeAuthHash,
    tail.confiscAuthHash,
    uint16LE(tail.attestationDepth),
    tail.optionalData,
  ]);
  return concatBytes([
    new Uint8Array([0x14]),
    ownerPkh,
    new Uint8Array([0x52, 0x6d]), // OP_2 OP_2DROP — Frozen action_data
    FROZEN_BODY_BYTES,
    new Uint8Array([0x6a]), // OP_RETURN
    tailBytes,
  ]);
};

type FreezeScenario = {
  ownerKey: PrivateKey;
  freezeAuthKey: PrivateKey;
  amount: bigint;
  tokenId: Bytes;
  issuerPkh: Bytes;
  authorityFlags: number; // must have bit 0 set (0x01 freezable)
  confiscAuthHash: Bytes;
  attestationDepth: number; // preserved
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
 * Path 3 freeze unlocking layout per spec §9.4:
 *   [frozen_body_bytes (~1282b)]
 *   [normal_output_tuple]                   (40b)
 *   [null-data?]
 *   [funding_outpoint]
 *   [preimage]
 *   [OP_3]
 *   [freezeAuth_sig]
 *   [freezeAuth_pubkey]
 */
const buildFreezeUnlocking = (
  outputTuple: OutputTuple,
  nullData: Bytes,
  fundingOutpoint: Bytes,
  preimage: Bytes,
  authSigWithType: Bytes,
  authPubkey: Bytes,
): Uint8Array => {
  return concatBytes([
    pushData(FROZEN_BODY_BYTES),
    pushData(serializeOutputTuple(outputTuple)),
    pushData(nullData),
    pushData(fundingOutpoint),
    pushData(preimage),
    scriptNumPush(3),
    pushData(authSigWithType),
    pushData(authPubkey),
  ]);
};

const assembleFreezeScenario = (s: FreezeScenario) => {
  const ownerPkh = hash160(s.ownerKey.PublicKey);
  const freezeAuthPubkey = s.freezeAuthKey.PublicKey;
  const freezeAuthHash = hash160(freezeAuthPubkey);

  const tail: NormalTail = {
    tokenId: s.tokenId,
    issuerPkh: s.issuerPkh,
    amount: s.amount,
    authorityFlags: s.authorityFlags,
    freezeAuthHash,
    confiscAuthHash: s.confiscAuthHash,
    attestationDepth: s.attestationDepth,
    optionalData: s.optionalData,
  };
  const inputLockingScript = buildNormalLockingScript(ownerPkh, tail);
  // Output: Frozen template, same tail (everything preserved), same owner.
  const outputLockingScript = buildFrozenLockingScript(ownerPkh, tail);

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

  const sigHash = hash256(preimage);
  const freezeAuthSigDer = s.freezeAuthKey.sign(sigHash);
  const freezeAuthSigWithType = concatBytes([
    freezeAuthSigDer,
    new Uint8Array([SIGHASH_ALL_FORKID]),
  ]);

  // Tuple: amount/owner/depth all preserved; marker = 0xFEFF (Frozen).
  const outputTuple: OutputTuple = {
    amount: s.amount,
    owner: ownerPkh,
    newDepth: s.attestationDepth,
    bodyMarker: new Uint8Array([0xfe, 0xff]),
  };

  const unlockingScript = buildFreezeUnlocking(
    outputTuple,
    new Uint8Array(), // empty nullData
    new Uint8Array(), // no funding input
    preimage,
    freezeAuthSigWithType,
    freezeAuthPubkey,
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
    freezeAuthHash,
    inputLockingScript,
    outputLockingScript,
    preimage,
    unlockingScript,
    tx,
    outputTuple,
  };
};

const buildBaseScenario = (): FreezeScenario => ({
  ownerKey: new PrivateKey(
    hexBytes(
      "0000000000000000000000000000000000000000000000000000000000000042",
    ),
  ),
  freezeAuthKey: new PrivateKey(
    hexBytes(
      "00000000000000000000000000000000000000000000000000000000000000ab",
    ),
  ),
  amount: BigInt(100),
  tokenId: new Uint8Array(32),
  issuerPkh: new Uint8Array(20).fill(0x11),
  authorityFlags: 0x01, // bit 0 = freezable enabled, no MPKH bits
  confiscAuthHash: new Uint8Array(20),
  attestationDepth: 3, // arbitrary non-zero — exercises depth-preservation
  optionalData: new Uint8Array(),
  inputTxIdBE:
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  inputVout: 0,
  inputSatoshis: 1,
  outputSatoshis: 1,
  sequence: 0xffffffff,
  version: 1,
  locktime: 0,
});

describe("BNTP v2 Normal — Path 3 freeze (Wave D.3.2 execution)", () => {
  test("positive: freezeAuth-signed freeze succeeds end-to-end", () => {
    const scenario = buildBaseScenario();
    const a = assembleFreezeScenario(scenario);

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

  // -------------------------------------------------------------------------
  // Negative tests
  // -------------------------------------------------------------------------

  const evalAdversarial = (
    sigKey: PrivateKey,
    customTuple: OutputTuple,
    customAuthorityFlags: number,
    customFrozenBody: Uint8Array | null = null,
  ) => {
    const scenario = buildBaseScenario();
    if (customAuthorityFlags !== scenario.authorityFlags) {
      scenario.authorityFlags = customAuthorityFlags;
    }
    const ownerPkh = hash160(scenario.ownerKey.PublicKey);
    const freezeAuthHash = hash160(scenario.freezeAuthKey.PublicKey);

    const tail: NormalTail = {
      tokenId: scenario.tokenId,
      issuerPkh: scenario.issuerPkh,
      amount: scenario.amount,
      authorityFlags: scenario.authorityFlags,
      freezeAuthHash,
      confiscAuthHash: scenario.confiscAuthHash,
      attestationDepth: scenario.attestationDepth,
      optionalData: scenario.optionalData,
    };
    const inputLockingScript = buildNormalLockingScript(ownerPkh, tail);
    const outputLockingScript = buildFrozenLockingScript(ownerPkh, tail);

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

    const frozenBodyToPush = customFrozenBody ?? FROZEN_BODY_BYTES;

    const unlockingScript = concatBytes([
      pushData(frozenBodyToPush),
      pushData(serializeOutputTuple(customTuple)),
      pushData(new Uint8Array()),
      pushData(new Uint8Array()),
      pushData(preimage),
      scriptNumPush(3),
      pushData(authSigWithType),
      pushData(sigKey.PublicKey),
    ]);

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

  test("negative: authorityFlags bit 0 NOT set → script aborts (freezable disabled)", () => {
    const scenario = buildBaseScenario();
    const ownerPkh = hash160(scenario.ownerKey.PublicKey);
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: ownerPkh,
      newDepth: scenario.attestationDepth,
      bodyMarker: new Uint8Array([0xfe, 0xff]),
    };
    // bit 0 NOT set (only bit 1 — confiscatable, but not freezable)
    const r = evalAdversarial(scenario.freezeAuthKey, tuple, 0x02);
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("negative: wrong key signs (not freezeAuth) → auth-identity check aborts", () => {
    const scenario = buildBaseScenario();
    const wrongKey = new PrivateKey(
      hexBytes(
        "0000000000000000000000000000000000000000000000000000000000000042",
      ),
    );
    const ownerPkh = hash160(scenario.ownerKey.PublicKey);
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: ownerPkh,
      newDepth: scenario.attestationDepth,
      bodyMarker: new Uint8Array([0xfe, 0xff]),
    };
    const r = evalAdversarial(wrongKey, tuple, scenario.authorityFlags);
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("negative: pushed frozen_body bytes don't hash to h_Frozen → SHA256 EQUALVERIFY aborts", () => {
    const scenario = buildBaseScenario();
    const ownerPkh = hash160(scenario.ownerKey.PublicKey);
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: ownerPkh,
      newDepth: scenario.attestationDepth,
      bodyMarker: new Uint8Array([0xfe, 0xff]),
    };
    // Push wrong bytes (truncated body — SHA256 won't match embedded h_Frozen)
    const r = evalAdversarial(
      scenario.freezeAuthKey,
      tuple,
      scenario.authorityFlags,
      FROZEN_BODY_BYTES.slice(0, FROZEN_BODY_BYTES.length - 10),
    );
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("negative: tuple.owner != zone.owner_pkh → owner-preservation check aborts", () => {
    const scenario = buildBaseScenario();
    // canonical owner_pkh would match; this differs intentionally
    const wrongOwner = new Uint8Array(20).fill(0xff);
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: wrongOwner,
      newDepth: scenario.attestationDepth,
      bodyMarker: new Uint8Array([0xfe, 0xff]),
    };
    const r = evalAdversarial(
      scenario.freezeAuthKey,
      tuple,
      scenario.authorityFlags,
    );
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("negative: tuple.depth != zone.depth → depth-preservation check aborts", () => {
    const scenario = buildBaseScenario();
    const ownerPkh = hash160(scenario.ownerKey.PublicKey);
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: ownerPkh,
      newDepth: 0, // canonical preserved value = 3
      bodyMarker: new Uint8Array([0xfe, 0xff]),
    };
    const r = evalAdversarial(
      scenario.freezeAuthKey,
      tuple,
      scenario.authorityFlags,
    );
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });

  test("negative: tuple.marker != 0xFEFF → marker check aborts", () => {
    const scenario = buildBaseScenario();
    const ownerPkh = hash160(scenario.ownerKey.PublicKey);
    const tuple: OutputTuple = {
      amount: scenario.amount,
      owner: ownerPkh,
      newDepth: scenario.attestationDepth,
      bodyMarker: new Uint8Array([0x01, 0xff]), // Normal marker, not Frozen
    };
    const r = evalAdversarial(
      scenario.freezeAuthKey,
      tuple,
      scenario.authorityFlags,
    );
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });
});
