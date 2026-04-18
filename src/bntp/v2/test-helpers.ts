/**
 * BNTP v2 execution-verification test helpers (Phase 1B Wave C).
 *
 * Utilities to construct a synthetic BSV transaction that spends one BNTP v2
 * Normal UTXO along the flex-transfer path (1 input → 1 output, 1:1 transfer,
 * PKH owner, no MPKH, no funding input, no null-data, no optionalData, M=1,
 * N=1, max_input_depth=0). Used by `tests/bntp-v2-normal-execution.test.ts`.
 *
 * These helpers intentionally DO NOT modify any template source
 * (`normal-body.ts`, `shared-prefix.ts`) and DO NOT patch the script evaluator.
 * If the assembled unlocking + locking pair fails execution, that is a finding
 * about the template, not this helper — see `docs/BNTP_V2_EXECUTION_VERIFICATION_REPORT.md`.
 *
 * References:
 *   - docs/BNTP_V2_SPEC.md §5, §7, §8.1, §9.1, §9.2
 *   - src/bntp/v2/templates/normal-body.ts (template under test)
 *   - src/script/eval/script-evaluator.ts (evaluator under test)
 */

import { Bytes, concat } from "../../bytes";
import { ByteWriter } from "../../binary";
import {
  estimateChunkSize,
  getChunkSize,
  reverseBytes,
} from "../../buffer/buffer-utils";
import { Transaction } from "../../bitcoin/transaction";
import { TransactionInput } from "../../bitcoin/transaction-input";
import { TransactionOutput } from "../../bitcoin/transaction-output";
import { SignatureHashType } from "../../bitcoin/sig-hash-type";
import { PrivateKey } from "../../bitcoin/private-key";
import { hash160, hash256 } from "../../hashes";
import { OpCode } from "../../bitcoin/op-codes";
import { NORMAL_BODY_BYTES } from "./templates/normal-body";

// ---------------------------------------------------------------------------
// Low-level encoders
// ---------------------------------------------------------------------------

/** Encode a uint16 little-endian. */
export const uint16LE = (value: number): Uint8Array => {
  const out = new Uint8Array(2);
  out[0] = value & 0xff;
  out[1] = (value >> 8) & 0xff;
  return out;
};

/** Encode a uint128 little-endian (token amount). */
export const uint128LE = (value: bigint): Uint8Array => {
  const out = new Uint8Array(16);
  let v = value;
  for (let i = 0; i < 16; i++) {
    out[i] = Number(v & BigInt(0xff));
    v >>= BigInt(8);
  }
  return out;
};

/** BSV-script minimal push encoding for a data value (no opcode wrapping). */
export const pushData = (data: Bytes): Bytes => {
  if (data.length === 0) return new Uint8Array([OpCode.OP_0]);
  if (data.length < 76) return concat([new Uint8Array([data.length]), data]);
  if (data.length <= 255)
    return concat([new Uint8Array([OpCode.OP_PUSHDATA1, data.length]), data]);
  if (data.length <= 65535) {
    const prefix = new Uint8Array(3);
    prefix[0] = OpCode.OP_PUSHDATA2;
    prefix[1] = data.length & 0xff;
    prefix[2] = (data.length >> 8) & 0xff;
    return concat([prefix, data]);
  }
  const prefix = new Uint8Array(5);
  prefix[0] = OpCode.OP_PUSHDATA4;
  prefix[1] = data.length & 0xff;
  prefix[2] = (data.length >> 8) & 0xff;
  prefix[3] = (data.length >> 16) & 0xff;
  prefix[4] = (data.length >> 24) & 0xff;
  return concat([prefix, data]);
};

/** Encode a ScriptNum (CScriptNum/bitcoin) for unsigned value n ≥ 0. */
export const scriptNumPush = (n: number): Bytes => {
  if (n === 0) return new Uint8Array([OpCode.OP_0]);
  if (n >= 1 && n <= 16) return new Uint8Array([OpCode.OP_1 + n - 1]);

  // Minimal-encode n as little-endian signed bytes, then wrap as a data push.
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.push(v & 0xff);
    v >>= 8;
  }
  if ((bytes[bytes.length - 1] & 0x80) !== 0) bytes.push(0x00);
  const buf = new Uint8Array(bytes);
  return pushData(buf);
};

// ---------------------------------------------------------------------------
// Tail construction (spec §5.2)
// ---------------------------------------------------------------------------

export type NormalTail = {
  tokenId: Bytes; // 32b
  issuerPkh: Bytes; // 20b
  amount: bigint; // uint128 LE serialized inside tail
  authorityFlags: number; // 1b
  freezeAuthHash: Bytes; // 20b
  confiscAuthHash: Bytes; // 20b
  attestationDepth: number; // uint16 LE
  optionalData: Bytes; // variable (may be empty)
};

export const buildTail = (t: NormalTail): Uint8Array => {
  if (t.tokenId.length !== 32) throw new Error("tail.tokenId must be 32b");
  if (t.issuerPkh.length !== 20) throw new Error("tail.issuerPkh must be 20b");
  if (t.freezeAuthHash.length !== 20)
    throw new Error("tail.freezeAuthHash must be 20b");
  if (t.confiscAuthHash.length !== 20)
    throw new Error("tail.confiscAuthHash must be 20b");
  return concat([
    t.tokenId,
    t.issuerPkh,
    uint128LE(t.amount),
    new Uint8Array([t.authorityFlags & 0xff]),
    t.freezeAuthHash,
    t.confiscAuthHash,
    uint16LE(t.attestationDepth),
    t.optionalData,
  ]);
};

// ---------------------------------------------------------------------------
// Locking script (variable prefix ‖ body ‖ OP_RETURN ‖ tail)
// ---------------------------------------------------------------------------

/**
 * Build a BNTP v2 Normal locking script for a PKH owner.
 *
 * variable_prefix = [0x14 ‖ owner_pkh] ‖ OP_0 (action_data) ‖ OP_2DROP
 * body           = NORMAL_BODY_BYTES (imported)
 * tail           = tail fields (111b fixed + optionalData)
 * full           = variable_prefix ‖ body ‖ OP_RETURN (0x6a) ‖ tail
 */
export const buildNormalLockingScript = (
  ownerPkh: Bytes,
  tail: NormalTail,
): Uint8Array => {
  if (ownerPkh.length !== 20) throw new Error("ownerPkh must be 20b");
  const varPrefix = concat([
    new Uint8Array([0x14]),
    ownerPkh,
    new Uint8Array([OpCode.OP_0, OpCode.OP_2DROP]),
  ]);
  const tailBytes = buildTail(tail);
  return concat([
    varPrefix,
    NORMAL_BODY_BYTES,
    new Uint8Array([OpCode.OP_RETURN]),
    tailBytes,
  ]);
};

// ---------------------------------------------------------------------------
// Preimage construction (SIGHASH_FORKID — BIP143-like)
// ---------------------------------------------------------------------------

export type PreimageSpec = {
  version: number;
  hashPrevouts: Bytes; // 32b
  hashSequence: Bytes; // 32b
  outpoint: Bytes; // 36b (txid reversed-be ‖ vout LE)
  scriptCode: Bytes; // variable
  satoshis: number;
  sequence: number;
  hashOutputs: Bytes; // 32b
  locktime: number;
  sighashType: number; // 0x41 for SIGHASH_ALL | SIGHASH_FORKID
};

export const buildPreimage = (spec: PreimageSpec): Uint8Array => {
  const size =
    4 + 32 + 32 + 36 + getChunkSize(spec.scriptCode) + 8 + 4 + 32 + 4 + 4;
  const buf = new Uint8Array(size);
  const w = new ByteWriter(buf);
  w.writeUInt32(spec.version);
  w.writeChunk(spec.hashPrevouts);
  w.writeChunk(spec.hashSequence);
  w.writeChunk(spec.outpoint);
  w.writeVarChunk(spec.scriptCode);
  w.writeUInt64(spec.satoshis);
  w.writeUInt32(spec.sequence);
  w.writeChunk(spec.hashOutputs);
  w.writeUInt32(spec.locktime);
  w.writeUInt32(spec.sighashType >>> 0);
  return buf;
};

// ---------------------------------------------------------------------------
// Output tuple + unlocking script
// ---------------------------------------------------------------------------

export type OutputTuple = {
  amount: bigint; // 16b uint128 LE
  owner: Bytes; // 20b PKH (raw, no push prefix per §9.2 Gap 4.3)
  newDepth: number; // 2b uint16 LE
  bodyMarker: Bytes; // 2b e.g. [0x01, 0xff]
};

export const serializeOutputTuple = (t: OutputTuple): Uint8Array => {
  return concat([
    uint128LE(t.amount),
    t.owner,
    uint16LE(t.newDepth),
    t.bodyMarker,
  ]);
};

/**
 * Flex-transfer unlocking stack for Normal path 1 (spec §9.2).
 *
 * Stack order per spec (top element pushed LAST, so first in bytes):
 *
 *   [M]                        (1 byte ScriptNum)
 *   [output_tuple_0]           (amount16 ‖ owner20 ‖ depth2 ‖ marker2 = 40b)
 *   ...
 *   [amounts_in_array]         (N × 16 bytes)
 *   [all_input_outpoints]      (N × 36 bytes)
 *   [selfPosition]             (1 byte ScriptNum)
 *   [max_input_depth]          (2 bytes uint16 LE)
 *   [null-data payload?]       (empty push if absent)
 *   [funding_outpoint]         (empty push if no funding input)
 *   [preimage]                 (variable)
 *   [OP_1]                     (path_id = 1)
 *   [owner_sig]                (DER + sighash_type)
 *   [owner_pubkey]             (compressed 33b)
 */
export type FlexTransferUnlockingSpec = {
  m: number;
  outputTuples: OutputTuple[]; // pushed in tx order
  amountsInArray: Bytes; // raw concat of uint128LE amounts
  allInputOutpoints: Bytes; // raw concat of 36b outpoints
  selfPosition: number; // 0..N-1
  maxInputDepth: number;
  nullData: Bytes; // raw bytes of null-data script (may be empty)
  fundingOutpoint: Bytes; // 0 or 36 bytes per §9.2 rule 2
  preimage: Bytes;
  pathId: number;
  ownerSigWithType: Bytes; // DER-encoded sig + 1 sighash byte
  ownerPubkey: Bytes;
};

export const buildFlexTransferUnlocking = (
  u: FlexTransferUnlockingSpec,
): Uint8Array => {
  const pieces: Bytes[] = [];
  pieces.push(scriptNumPush(u.m));
  for (const t of u.outputTuples)
    pieces.push(pushData(serializeOutputTuple(t)));
  pieces.push(pushData(u.amountsInArray));
  pieces.push(pushData(u.allInputOutpoints));
  pieces.push(scriptNumPush(u.selfPosition));
  pieces.push(pushData(uint16LE(u.maxInputDepth)));
  pieces.push(pushData(u.nullData));
  pieces.push(pushData(u.fundingOutpoint));
  pieces.push(pushData(u.preimage));
  pieces.push(scriptNumPush(u.pathId));
  pieces.push(pushData(u.ownerSigWithType));
  pieces.push(pushData(u.ownerPubkey));
  return concat(pieces);
};

// ---------------------------------------------------------------------------
// Outpoint helper (txid hex BE → raw LE ‖ vout LE)
// ---------------------------------------------------------------------------

export const outpointBytes = (txIdHexBE: string, vout: number): Uint8Array => {
  const txIdBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    txIdBytes[i] = parseInt(txIdHexBE.slice(i * 2, i * 2 + 2), 16);
  }
  // In serialized form, txid is reversed (little-endian txid as seen in protocol).
  const txIdLE = reverseBytes(txIdBytes);
  const voutLE = new Uint8Array(4);
  voutLE[0] = vout & 0xff;
  voutLE[1] = (vout >> 8) & 0xff;
  voutLE[2] = (vout >> 16) & 0xff;
  voutLE[3] = (vout >> 24) & 0xff;
  return concat([txIdLE, voutLE]);
};

// ---------------------------------------------------------------------------
// Serialize a single tx output (8b sats ‖ varint len ‖ script).
// ---------------------------------------------------------------------------

export const serializeOutput = (
  satoshis: number,
  script: Bytes,
): Uint8Array => {
  const size = 8 + estimateChunkSize(script.length);
  const buf = new Uint8Array(size);
  const w = new ByteWriter(buf);
  w.writeUInt64(satoshis);
  w.writeVarChunk(script);
  return buf;
};

// ---------------------------------------------------------------------------
// Full scenario builder — 1 BNTP input, 1 BNTP output, same amount preserved.
// ---------------------------------------------------------------------------

export type FlexTransferScenario = {
  ownerKey: PrivateKey;
  amount: bigint;
  tokenId: Bytes;
  issuerPkh: Bytes;
  authorityFlags: number;
  freezeAuthHash: Bytes;
  confiscAuthHash: Bytes;
  inputAttestationDepth: number;
  outputAttestationDepth: number;
  optionalData: Bytes;
  inputTxIdBE: string;
  inputVout: number;
  inputSatoshis: number;
  outputSatoshis: number;
  selfPosition: number;
  maxInputDepth: number;
  sequence: number;
  version: number;
  locktime: number;
};

export type FlexTransferAssembly = {
  ownerPkh: Bytes;
  inputLockingScript: Bytes;
  outputLockingScript: Bytes;
  outputSerialized: Bytes;
  preimage: Bytes;
  unlockingScript: Bytes;
  tx: Transaction;
  sighashType: number;
};

const SIGHASH_ALL_FORKID =
  SignatureHashType.SIGHASH_ALL | SignatureHashType.SIGHASH_FORKID; // 0x41

export const assembleFlexTransferScenario = (
  s: FlexTransferScenario,
): FlexTransferAssembly => {
  const ownerPubkey = s.ownerKey.PublicKey;
  const ownerPkh = hash160(ownerPubkey);

  // Input locking script (source UTXO).
  const inputTail: NormalTail = {
    tokenId: s.tokenId,
    issuerPkh: s.issuerPkh,
    amount: s.amount,
    authorityFlags: s.authorityFlags,
    freezeAuthHash: s.freezeAuthHash,
    confiscAuthHash: s.confiscAuthHash,
    attestationDepth: s.inputAttestationDepth,
    optionalData: s.optionalData,
  };
  const inputLockingScript = buildNormalLockingScript(ownerPkh, inputTail);

  // Output locking script (destination UTXO — same owner, +1 depth, same amount).
  const outputTail: NormalTail = {
    ...inputTail,
    attestationDepth: s.outputAttestationDepth,
  };
  const outputLockingScript = buildNormalLockingScript(ownerPkh, outputTail);

  // Outpoint + preimage hashes.
  const outpoint = outpointBytes(s.inputTxIdBE, s.inputVout);
  const hashPrevouts = hash256(outpoint); // single input, no funding
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

  // Sign preimage. Preimage is double-sha256'd per consensus; sign(msg) takes
  // the hashed message directly.
  const sigHash = hash256(preimage);
  const ownerSigDer = s.ownerKey.sign(sigHash);
  const ownerSigWithType = concat([
    ownerSigDer,
    new Uint8Array([SIGHASH_ALL_FORKID]),
  ]);

  // Build flex-transfer unlocking stack.
  const outputTuple: OutputTuple = {
    amount: s.amount,
    owner: ownerPkh,
    newDepth: s.outputAttestationDepth,
    bodyMarker: new Uint8Array([0x01, 0xff]),
  };
  const unlockingScript = buildFlexTransferUnlocking({
    m: 1,
    outputTuples: [outputTuple],
    amountsInArray: uint128LE(s.amount),
    allInputOutpoints: outpoint,
    selfPosition: s.selfPosition,
    maxInputDepth: s.maxInputDepth,
    nullData: new Uint8Array(),
    fundingOutpoint: new Uint8Array(), // no funding input
    preimage,
    pathId: 1,
    ownerSigWithType,
    ownerPubkey,
  });

  // Assemble a real Transaction object to hand to the evaluator.
  const txInput = new TransactionInput(
    // Transaction-input stores the human-readable big-endian txid hex.
    s.inputTxIdBE,
    s.inputVout,
    unlockingScript,
    s.sequence,
  );
  const txOutput = new TransactionOutput(s.outputSatoshis, outputLockingScript);

  // Raw bytes aren't required for the evaluator's preimage reconstruction
  // (it re-reads from Inputs/Outputs). Pass an empty buffer here; the Transaction
  // ctor only uses it to compute `Id`, which we don't rely on.
  const tx = new Transaction(
    new Uint8Array(),
    [txInput],
    [txOutput],
    s.version,
    s.locktime,
  );

  return {
    ownerPkh,
    inputLockingScript,
    outputLockingScript,
    outputSerialized,
    preimage,
    unlockingScript,
    tx,
    sighashType: SIGHASH_ALL_FORKID,
  };
};
