import { Signature, verify as nobleVerify } from "@noble/secp256k1";
import { ByteWriter } from "../../binary";
import {
  cloneBytes,
  estimateChunkSize,
  getChunkSize,
  reverseBytes,
} from "../../buffer/buffer-utils";
import { SignatureHashType } from "../../bitcoin/sig-hash-type";
import { Transaction } from "../../bitcoin/transaction";
import { TransactionOutput } from "../../bitcoin/transaction-output";
import { OpCode } from "../../bitcoin/op-codes";
import { Bytes, concat, equal, fromHex, toHex } from "../../bytes";
import { hash160, hash256, ripemd160, sha256 } from "../../hashes";
import { TransactionReader } from "../../transaction/read/transaction-reader";
import { getStrictModeConfig } from "../../security/strict-mode";

export type PrevOutput = {
  lockingScript: Bytes;
  satoshis: number;
};

export type ScriptEvalContext = {
  tx: Transaction;
  inputIndex: number;
  prevOutputs: PrevOutput[];
};

export type ScriptEvalResult = {
  success: boolean;
  error?: string;
  stack: Bytes[];
  altStack: Bytes[];
  trace?: ScriptTraceStep[];
  equalityTrace?: ScriptEqualityStep[];
};

export type ScriptEvalOptions = {
  allowOpReturn?: boolean;
  scriptFlags?: number;
  trace?: boolean;
  traceLimit?: number;
  strict?: boolean;
  requireDerSignatures?: boolean;
  maxScriptSizeBytes?: number;
  maxOps?: number;
  maxStackDepth?: number;
  maxElementSizeBytes?: number;
};

export type ScriptTraceStep = {
  phase: "unlocking" | "locking";
  pc: number;
  opcode: number;
  stackDepth: number;
  stackTopHex?: string;
  altStackDepth: number;
};

export type ScriptEqualityStep = {
  phase: "unlocking" | "locking";
  pc: number;
  opcode: number;
  leftHex: string;
  rightHex: string;
  result: boolean;
};

export const SCRIPT_ENABLE_SIGHASH_FORKID = 1 << 16;
export const SCRIPT_ENABLE_MAGNETIC_OPCODES = 1 << 17;
export const SCRIPT_ENABLE_MONOLITH_OPCODES = 1 << 18;

const DEFAULT_SCRIPT_FLAGS =
  SCRIPT_ENABLE_SIGHASH_FORKID |
  SCRIPT_ENABLE_MAGNETIC_OPCODES |
  SCRIPT_ENABLE_MONOLITH_OPCODES;

export type ResolvePrevOutput = (
  txId: string,
  vout: number,
) => PrevOutput | undefined;

export type TransactionInputEvalResult = {
  inputIndex: number;
  success: boolean;
  error?: string;
};

export type TransactionEvalResult = {
  txId: string;
  success: boolean;
  inputs: TransactionInputEvalResult[];
  errors: string[];
};

class ScriptEvalError extends Error {
  constructor(message: string) {
    super(message);
  }
}

const isTruthy = (value: Bytes): boolean => {
  for (let i = 0; i < value.length; i++) {
    if (value[i] !== 0) {
      if (i === value.length - 1 && value[i] === 0x80) return false;
      return true;
    }
  }
  return false;
};

const decodeScriptNum = (value: Bytes): bigint => {
  if (value.length === 0) return BigInt(0);

  let result = BigInt(0);
  for (let i = 0; i < value.length; i++) {
    result |= BigInt(value[i]) << BigInt(8 * i);
  }

  const signBit = BigInt(1) << BigInt(8 * value.length - 1);
  const isNegative = (result & signBit) !== BigInt(0);
  if (isNegative) {
    result &= signBit - BigInt(1);
    return -result;
  }

  return result;
};

const encodeScriptNum = (value: bigint): Bytes => {
  if (value === BigInt(0)) return new Uint8Array();

  const neg = value < BigInt(0);
  let absValue = neg ? -value : value;
  const result: number[] = [];

  while (absValue > BigInt(0)) {
    result.push(Number(absValue & BigInt(0xff)));
    absValue >>= BigInt(8);
  }

  if ((result[result.length - 1] & 0x80) !== 0) {
    result.push(neg ? 0x80 : 0x00);
  } else if (neg) {
    result[result.length - 1] |= 0x80;
  }

  return new Uint8Array(result);
};

const fromBigInt = (value: bigint): Bytes => encodeScriptNum(value);

const pushBool = (stack: Bytes[], value: boolean) => {
  stack.push(value ? new Uint8Array([1]) : new Uint8Array());
};

const decodePushData = (script: Bytes, offset: number) => {
  const opcode = script[offset];

  if (opcode >= 1 && opcode <= 75) {
    const size = opcode;
    const start = offset + 1;
    const end = start + size;
    if (end > script.length) throw new ScriptEvalError("Push out of bounds");
    return { opcode, data: script.subarray(start, end), next: end };
  }

  if (opcode === OpCode.OP_PUSHDATA1) {
    if (offset + 2 > script.length)
      throw new ScriptEvalError("Pushdata1 out of bounds");
    const size = script[offset + 1];
    const start = offset + 2;
    const end = start + size;
    if (end > script.length) throw new ScriptEvalError("Push out of bounds");
    return { opcode, data: script.subarray(start, end), next: end };
  }

  if (opcode === OpCode.OP_PUSHDATA2) {
    if (offset + 3 > script.length)
      throw new ScriptEvalError("Pushdata2 out of bounds");
    const size = script[offset + 1] | (script[offset + 2] << 8);
    const start = offset + 3;
    const end = start + size;
    if (end > script.length) throw new ScriptEvalError("Push out of bounds");
    return { opcode, data: script.subarray(start, end), next: end };
  }

  if (opcode === OpCode.OP_PUSHDATA4) {
    if (offset + 5 > script.length)
      throw new ScriptEvalError("Pushdata4 out of bounds");
    const size =
      (script[offset + 1] |
        (script[offset + 2] << 8) |
        (script[offset + 3] << 16) |
        (script[offset + 4] << 24)) >>>
      0;
    const start = offset + 5;
    const end = start + size;
    if (end > script.length) throw new ScriptEvalError("Push out of bounds");
    return { opcode, data: script.subarray(start, end), next: end };
  }

  return { opcode, data: undefined, next: offset + 1 };
};

// Per BIP143 (BSV post-Genesis), the SIGHASH preimage's scriptCode is a
// byte-level transform of the executing script's tail (post-codeSeparator):
// copy bytes verbatim, removing only `OP_CODESEPARATOR` opcode bytes
// (0xab). To distinguish 0xab opcodes from raw 0xab data inside a push,
// the walker is push-aware.
//
// IMPORTANT — this walker is LENIENT about malformed pushes (push opcodes
// demanding more bytes than the script holds). The strict
// `decodePushData` used by the main interpreter loop throws on truncated
// pushes — that's correct behaviour for execution (a script that doesn't
// parse is invalid per consensus). But the sighash scriptCode path runs
// on the full executing script, including any post-`OP_RETURN` data
// section, where the bytes may resemble malformed push opcodes purely by
// chance (e.g. a random 20-byte hash160 in a template's tail). Those
// bytes never reach the main interpreter (OP_RETURN halts it) and don't
// need to "parse cleanly" — they only need to hash deterministically.
// Real BSV nodes tolerate truncated pushes here by folding the remainder
// of the script into the output as-is; this implementation matches that
// behaviour. See `tests/sighash-script-code-edge.test.ts` for the
// scriptCode-byte-equivalence contract.
const stripCodeSeparators = (script: Bytes): Bytes => {
  const parts: Bytes[] = [];
  let i = 0;

  while (i < script.length) {
    const opcode = script[i];
    let pushDataStart = i + 1;
    let pushSize = 0;
    let isPushOpcode = false;

    if (opcode >= 1 && opcode <= 75) {
      pushSize = opcode;
      isPushOpcode = true;
    } else if (opcode === OpCode.OP_PUSHDATA1) {
      if (i + 1 < script.length) {
        pushSize = script[i + 1];
        pushDataStart = i + 2;
        isPushOpcode = true;
      } else {
        // Truncated PUSHDATA1: no length byte present. Copy remaining
        // bytes verbatim (lenient — the bytes are part of scriptCode for
        // hashing) and stop.
        parts.push(script.subarray(i));
        break;
      }
    } else if (opcode === OpCode.OP_PUSHDATA2) {
      if (i + 2 < script.length) {
        pushSize = script[i + 1] | (script[i + 2] << 8);
        pushDataStart = i + 3;
        isPushOpcode = true;
      } else {
        parts.push(script.subarray(i));
        break;
      }
    } else if (opcode === OpCode.OP_PUSHDATA4) {
      if (i + 4 < script.length) {
        pushSize =
          (script[i + 1] |
            (script[i + 2] << 8) |
            (script[i + 3] << 16) |
            (script[i + 4] << 24)) >>>
          0;
        pushDataStart = i + 5;
        isPushOpcode = true;
      } else {
        parts.push(script.subarray(i));
        break;
      }
    }

    if (isPushOpcode) {
      // Clamp the declared push end to the script length — a push that
      // demands more bytes than available is folded as-is into scriptCode.
      const end = Math.min(pushDataStart + pushSize, script.length);
      parts.push(script.subarray(i, end));
      i = end;
    } else {
      if (opcode !== OpCode.OP_CODESEPARATOR) {
        parts.push(script.subarray(i, i + 1));
      }
      i += 1;
    }
  }

  return concat(parts);
};

const derDecodeSignature = (der: Bytes) => {
  if (der.length < 8 || der[0] !== 0x30) {
    throw new ScriptEvalError("Invalid DER signature");
  }

  const totalLen = der[1];
  if (totalLen + 2 !== der.length) {
    throw new ScriptEvalError("Invalid DER signature length");
  }

  let offset = 2;
  if (der[offset++] !== 0x02)
    throw new ScriptEvalError("Invalid DER signature");
  const rLen = der[offset++];
  const r = der.subarray(offset, offset + rLen);
  offset += rLen;

  if (der[offset++] !== 0x02)
    throw new ScriptEvalError("Invalid DER signature");
  const sLen = der[offset++];
  const s = der.subarray(offset, offset + sLen);

  const bytesToBigInt = (bytes: Bytes) => {
    let result = BigInt(0);
    for (const byte of bytes) {
      result = (result << BigInt(8)) + BigInt(byte);
    }
    return result;
  };

  return new Signature(bytesToBigInt(r), bytesToBigInt(s));
};

const parseSignature = (
  sigWithHashType: Bytes,
  requireDerSignatures = false,
) => {
  if (sigWithHashType.length === 0) {
    return { signature: new Uint8Array(), sighashType: 0 };
  }

  const sighashType = sigWithHashType[sigWithHashType.length - 1];
  const signature = sigWithHashType.subarray(0, sigWithHashType.length - 1);

  if (signature.length === 0) {
    return { signature: new Uint8Array(), sighashType };
  }

  if (requireDerSignatures && signature[0] !== 0x30) {
    throw new ScriptEvalError("Non-DER signature is rejected in strict mode");
  }

  const sigBytes =
    signature[0] === 0x30 ? derDecodeSignature(signature).toBytes() : signature;

  return { signature: sigBytes, sighashType };
};

const writeOutputTo = (writer: ByteWriter, output: TransactionOutput) => {
  writer.writeUInt64(output.Satoshis);
  writer.writeVarChunk(output.LockingScript);
};

const outputSize = (output: TransactionOutput) =>
  8 + estimateChunkSize(output.LockingScript.length);

const buildSighashPreimage = (
  ctx: ScriptEvalContext,
  scriptCode: Bytes,
  sighashType: number,
) => {
  const tx = ctx.tx;
  const inputIdx = ctx.inputIndex;
  const baseType = sighashType & 0x1f;
  const anyoneCanPay =
    (sighashType & SignatureHashType.SIGHASH_ANYONECANPAY) !== 0;

  const prevoutHash = anyoneCanPay
    ? new Uint8Array(32)
    : hash256(
        concat(
          tx.Inputs.map((input) =>
            concat([
              reverseBytes(fromHex(input.TxId)),
              new Uint8Array([
                input.Vout & 0xff,
                (input.Vout >> 8) & 0xff,
                (input.Vout >> 16) & 0xff,
                (input.Vout >> 24) & 0xff,
              ]),
            ]),
          ),
        ),
      );

  const sequenceHash =
    anyoneCanPay ||
    baseType === SignatureHashType.SIGHASH_NONE ||
    baseType === SignatureHashType.SIGHASH_SINGLE
      ? new Uint8Array(32)
      : hash256(
          concat(
            tx.Inputs.map(
              (input) =>
                new Uint8Array([
                  input.Sequence & 0xff,
                  (input.Sequence >> 8) & 0xff,
                  (input.Sequence >> 16) & 0xff,
                  (input.Sequence >> 24) & 0xff,
                ]),
            ),
          ),
        );

  let outputsHash: Uint8Array = new Uint8Array(32);
  if (baseType === SignatureHashType.SIGHASH_ALL) {
    const outputsSize = tx.Outputs.reduce(
      (sum, out) => sum + outputSize(out),
      0,
    );
    const outputsBuffer = new Uint8Array(outputsSize);
    const outputsWriter = new ByteWriter(outputsBuffer);
    for (const output of tx.Outputs) writeOutputTo(outputsWriter, output);
    outputsHash = hash256(outputsBuffer);
  } else if (baseType === SignatureHashType.SIGHASH_SINGLE) {
    if (inputIdx < tx.Outputs.length) {
      const output = tx.Outputs[inputIdx];
      const singleBuffer = new Uint8Array(outputSize(output));
      const singleWriter = new ByteWriter(singleBuffer);
      writeOutputTo(singleWriter, output);
      outputsHash = hash256(singleBuffer);
    }
  }

  const prevOutput = ctx.prevOutputs[inputIdx];
  if (!prevOutput) throw new ScriptEvalError("Missing prev output for input");

  const scriptChunk = stripCodeSeparators(scriptCode);
  const preimageSize =
    4 + 32 + 32 + 32 + 4 + getChunkSize(scriptChunk) + 8 + 4 + 32 + 4 + 4;

  const preimageBuffer = new Uint8Array(preimageSize);
  const preimageWriter = new ByteWriter(preimageBuffer);

  preimageWriter.writeUInt32(tx.Version);
  preimageWriter.writeChunk(prevoutHash);
  preimageWriter.writeChunk(sequenceHash);
  preimageWriter.writeChunk(reverseBytes(fromHex(tx.Inputs[inputIdx].TxId)));
  preimageWriter.writeUInt32(tx.Inputs[inputIdx].Vout);
  preimageWriter.writeVarChunk(scriptChunk);
  preimageWriter.writeUInt64(prevOutput.satoshis);
  preimageWriter.writeUInt32(tx.Inputs[inputIdx].Sequence);
  preimageWriter.writeChunk(outputsHash);
  preimageWriter.writeUInt32(tx.LockTime);
  preimageWriter.writeUInt32(sighashType >>> 0);

  return preimageBuffer;
};

class ScriptInterpreter {
  private stack: Bytes[] = [];
  private altStack: Bytes[] = [];
  private execStack: boolean[] = [];
  private script: Bytes = new Uint8Array();
  private codeSeparator = -1;
  private ctx: ScriptEvalContext;
  private allowOpReturn: boolean;
  private scriptFlags: number;
  private traceEnabled: boolean;
  private traceLimit: number;
  private tracePhase: "unlocking" | "locking" = "unlocking";
  private trace: ScriptTraceStep[] = [];
  private equalityTrace: ScriptEqualityStep[] = [];
  private strictMode: boolean;
  private requireDerSignatures: boolean;
  private maxScriptSizeBytes: number;
  private maxOps: number;
  private maxStackDepth: number;
  private maxElementSizeBytes: number;
  private opCount = 0;

  constructor(ctx: ScriptEvalContext, options?: ScriptEvalOptions) {
    const strictConfig = getStrictModeConfig();
    const strict = options?.strict ?? strictConfig.strictScriptEvaluation;

    this.ctx = ctx;
    this.allowOpReturn = options?.allowOpReturn === true;
    this.scriptFlags = options?.scriptFlags ?? DEFAULT_SCRIPT_FLAGS;
    this.traceEnabled = options?.trace === true;
    this.traceLimit = options?.traceLimit ?? 400;
    this.strictMode = strict;
    this.requireDerSignatures = options?.requireDerSignatures ?? strict;
    this.maxScriptSizeBytes =
      options?.maxScriptSizeBytes ??
      strictConfig.scriptEvaluationLimits.maxScriptSizeBytes;
    this.maxOps = options?.maxOps ?? strictConfig.scriptEvaluationLimits.maxOps;
    this.maxStackDepth =
      options?.maxStackDepth ??
      strictConfig.scriptEvaluationLimits.maxStackDepth;
    this.maxElementSizeBytes =
      options?.maxElementSizeBytes ??
      strictConfig.scriptEvaluationLimits.maxElementSizeBytes;
  }

  getStack = () => this.stack;
  getAltStack = () => this.altStack;
  getTrace = () => this.trace;
  getEqualityTrace = () => this.equalityTrace;
  setTracePhase = (phase: "unlocking" | "locking") => {
    this.tracePhase = phase;
  };

  private isExecuting = () => this.execStack.every((v) => v);

  private pop = (): Bytes => {
    if (this.stack.length === 0) throw new ScriptEvalError("Stack underflow");
    return this.stack.pop()!;
  };

  private popNum = (): bigint => decodeScriptNum(this.pop());

  private popBool = (): boolean => isTruthy(this.pop());

  private ensureElementSize = (value: Bytes) => {
    if (this.strictMode && value.length > this.maxElementSizeBytes) {
      throw new ScriptEvalError(
        `Script element exceeds strict limit: ${value.length} > ${this.maxElementSizeBytes}`,
      );
    }
  };

  private ensureStackDepth = () => {
    if (
      this.strictMode &&
      this.stack.length + this.altStack.length > this.maxStackDepth
    ) {
      throw new ScriptEvalError(
        `Stack depth exceeds strict limit: ${
          this.stack.length + this.altStack.length
        } > ${this.maxStackDepth}`,
      );
    }
  };

  private push = (value: Bytes) => {
    this.ensureElementSize(value);
    this.stack.push(value);
    this.ensureStackDepth();
  };

  private top = (): Bytes => {
    if (this.stack.length === 0) throw new ScriptEvalError("Stack underflow");
    return this.stack[this.stack.length - 1];
  };

  private getScriptCode = () => {
    const start = this.codeSeparator + 1;
    return this.script.subarray(start);
  };

  private hasFlag = (flag: number): boolean => (this.scriptFlags & flag) !== 0;

  private requireMonolithOpcodes = () => {
    if (!this.hasFlag(SCRIPT_ENABLE_MONOLITH_OPCODES)) {
      throw new ScriptEvalError("Monolith opcodes disabled");
    }
  };

  private requireMagneticOpcodes = () => {
    if (!this.hasFlag(SCRIPT_ENABLE_MAGNETIC_OPCODES)) {
      throw new ScriptEvalError("Magnetic opcodes disabled");
    }
  };

  execute = (script: Bytes) => {
    if (this.strictMode && script.length > this.maxScriptSizeBytes) {
      throw new ScriptEvalError(
        `Script exceeds strict size limit: ${script.length} > ${this.maxScriptSizeBytes}`,
      );
    }

    this.script = script;
    this.codeSeparator = -1;

    let pc = 0;

    while (pc < script.length) {
      const { opcode, data, next } = decodePushData(script, pc);
      const executing = this.isExecuting();

      if (data !== undefined) {
        if (executing) this.push(data);
        pc = next;
        continue;
      }

      this.opCount++;
      if (this.strictMode && this.opCount > this.maxOps) {
        throw new ScriptEvalError(
          `Opcode count exceeds strict limit: ${this.opCount} > ${this.maxOps}`,
        );
      }

      if (!executing) {
        if (
          opcode === OpCode.OP_IF ||
          opcode === OpCode.OP_NOTIF ||
          opcode === OpCode.OP_ELSE ||
          opcode === OpCode.OP_ENDIF
        ) {
          this.execControl(opcode);
        }
        pc = next;
        continue;
      }

      const halt = this.execOp(opcode, pc);
      if (this.traceEnabled) {
        const top =
          this.stack.length > 0 ? this.stack[this.stack.length - 1] : undefined;
        this.trace.push({
          phase: this.tracePhase,
          pc,
          opcode,
          stackDepth: this.stack.length,
          stackTopHex: top ? toHex(top) : undefined,
          altStackDepth: this.altStack.length,
        });
        if (this.trace.length > this.traceLimit) this.trace.shift();
      }
      if (halt) break;
      pc = next;
    }

    if (this.execStack.length !== 0)
      throw new ScriptEvalError("Unbalanced conditional");
  };

  private execControl = (opcode: number) => {
    if (opcode === OpCode.OP_IF || opcode === OpCode.OP_NOTIF) {
      if (this.isExecuting()) {
        const cond = this.popBool();
        this.execStack.push(opcode === OpCode.OP_IF ? cond : !cond);
      } else {
        this.execStack.push(false);
      }
      return;
    }

    if (opcode === OpCode.OP_ELSE) {
      if (this.execStack.length === 0)
        throw new ScriptEvalError("OP_ELSE without OP_IF");

      const parentExec = this.execStack
        .slice(0, this.execStack.length - 1)
        .every((v) => v);

      if (parentExec) {
        this.execStack[this.execStack.length - 1] =
          !this.execStack[this.execStack.length - 1];
      }
      return;
    }

    if (opcode === OpCode.OP_ENDIF) {
      if (this.execStack.length === 0)
        throw new ScriptEvalError("OP_ENDIF without OP_IF");
      this.execStack.pop();
    }
  };

  private execOp = (opcode: number, pc: number): boolean | void => {
    switch (opcode) {
      case OpCode.OP_0:
        this.push(new Uint8Array());
        return;
      case OpCode.OP_1NEGATE:
        this.push(fromBigInt(BigInt(-1)));
        return;
      case OpCode.OP_1:
      case OpCode.OP_2:
      case OpCode.OP_3:
      case OpCode.OP_4:
      case OpCode.OP_5:
      case OpCode.OP_6:
      case OpCode.OP_7:
      case OpCode.OP_8:
      case OpCode.OP_9:
      case OpCode.OP_10:
      case OpCode.OP_11:
      case OpCode.OP_12:
      case OpCode.OP_13:
      case OpCode.OP_14:
      case OpCode.OP_15:
      case OpCode.OP_16:
        this.push(fromBigInt(BigInt(opcode - OpCode.OP_1 + 1)));
        return;

      case OpCode.OP_NOP:
      case OpCode.OP_NOP1:
      case OpCode.OP_NOP4:
      case OpCode.OP_NOP5:
      case OpCode.OP_NOP6:
      case OpCode.OP_NOP7:
      case OpCode.OP_NOP8:
      case OpCode.OP_NOP9:
      case OpCode.OP_NOP10:
        return;

      case OpCode.OP_VERIFY: {
        const ok = this.popBool();
        if (!ok) throw new ScriptEvalError("OP_VERIFY failed");
        return;
      }

      case OpCode.OP_RETURN:
        if (this.allowOpReturn) return true;
        throw new ScriptEvalError("OP_RETURN");

      case OpCode.OP_IF:
      case OpCode.OP_NOTIF:
      case OpCode.OP_ELSE:
      case OpCode.OP_ENDIF:
        return this.execControl(opcode);

      case OpCode.OP_TOALTSTACK:
        this.altStack.push(this.pop());
        this.ensureStackDepth();
        return;
      case OpCode.OP_FROMALTSTACK:
        if (this.altStack.length === 0)
          throw new ScriptEvalError("Alt stack underflow");
        this.push(this.altStack.pop()!);
        return;
      case OpCode.OP_2DROP:
        this.pop();
        this.pop();
        return;
      case OpCode.OP_2DUP: {
        const a = this.pop();
        const b = this.pop();
        this.push(b);
        this.push(a);
        this.push(cloneBytes(b));
        this.push(cloneBytes(a));
        return;
      }
      case OpCode.OP_3DUP: {
        const a = this.pop();
        const b = this.pop();
        const c = this.pop();
        this.push(c);
        this.push(b);
        this.push(a);
        this.push(cloneBytes(c));
        this.push(cloneBytes(b));
        this.push(cloneBytes(a));
        return;
      }
      case OpCode.OP_2OVER: {
        if (this.stack.length < 4) throw new ScriptEvalError("Stack underflow");
        this.push(cloneBytes(this.stack[this.stack.length - 4]));
        this.push(cloneBytes(this.stack[this.stack.length - 3]));
        return;
      }
      case OpCode.OP_2ROT: {
        if (this.stack.length < 6) throw new ScriptEvalError("Stack underflow");
        const a = this.stack.splice(this.stack.length - 6, 2);
        this.stack.push(a[0], a[1]);
        return;
      }
      case OpCode.OP_2SWAP: {
        if (this.stack.length < 4) throw new ScriptEvalError("Stack underflow");
        const a = this.stack.splice(this.stack.length - 4, 2);
        this.stack.push(a[0], a[1]);
        return;
      }
      case OpCode.OP_IFDUP: {
        if (this.stack.length === 0)
          throw new ScriptEvalError("Stack underflow");
        if (isTruthy(this.top())) this.push(cloneBytes(this.top()));
        return;
      }
      case OpCode.OP_DEPTH:
        this.push(fromBigInt(BigInt(this.stack.length)));
        return;
      case OpCode.OP_DROP:
        this.pop();
        return;
      case OpCode.OP_DUP:
        this.push(cloneBytes(this.top()));
        return;
      case OpCode.OP_NIP: {
        const a = this.pop();
        this.pop();
        this.push(a);
        return;
      }
      case OpCode.OP_OVER: {
        if (this.stack.length < 2) throw new ScriptEvalError("Stack underflow");
        this.push(cloneBytes(this.stack[this.stack.length - 2]));
        return;
      }
      case OpCode.OP_PICK: {
        const n = Number(this.popNum());
        if (n < 0 || n >= this.stack.length)
          throw new ScriptEvalError("OP_PICK out of range");
        this.push(cloneBytes(this.stack[this.stack.length - 1 - n]));
        return;
      }
      case OpCode.OP_ROLL: {
        const n = Number(this.popNum());
        if (n < 0 || n >= this.stack.length)
          throw new ScriptEvalError("OP_ROLL out of range");
        const idx = this.stack.length - 1 - n;
        const [val] = this.stack.splice(idx, 1);
        this.push(val);
        return;
      }
      case OpCode.OP_ROT: {
        if (this.stack.length < 3) throw new ScriptEvalError("Stack underflow");
        const a = this.stack.splice(this.stack.length - 3, 1)[0];
        this.stack.push(a);
        return;
      }
      case OpCode.OP_SWAP: {
        if (this.stack.length < 2) throw new ScriptEvalError("Stack underflow");
        const a = this.pop();
        const b = this.pop();
        this.push(a);
        this.push(b);
        return;
      }
      case OpCode.OP_TUCK: {
        if (this.stack.length < 2) throw new ScriptEvalError("Stack underflow");
        const a = this.pop();
        const b = this.pop();
        this.push(cloneBytes(a));
        this.push(b);
        this.push(a);
        return;
      }

      case OpCode.OP_CAT: {
        this.requireMonolithOpcodes();
        const b = this.pop();
        const a = this.pop();
        this.push(concat([a, b]));
        return;
      }
      case OpCode.OP_SPLIT: {
        this.requireMonolithOpcodes();
        const pos = Number(this.popNum());
        const data = this.pop();
        if (pos < 0 || pos > data.length)
          throw new ScriptEvalError("OP_SPLIT out of range");
        this.push(data.subarray(0, pos));
        this.push(data.subarray(pos));
        return;
      }
      case OpCode.OP_NUM2BIN: {
        this.requireMonolithOpcodes();
        const size = Number(this.popNum());
        const num = this.popNum();
        if (size < 0) throw new ScriptEvalError("OP_NUM2BIN size < 0");
        if (size === 0) {
          if (num !== BigInt(0))
            throw new ScriptEvalError("OP_NUM2BIN overflow");
          this.push(new Uint8Array());
          return;
        }

        const minimal = fromBigInt(num);
        if (minimal.length > size)
          throw new ScriptEvalError("OP_NUM2BIN overflow");

        if (minimal.length === size) {
          this.push(minimal);
          return;
        }

        const out = new Uint8Array(size);
        out.set(minimal);

        if (num < BigInt(0)) {
          if (minimal.length > 0) {
            out[minimal.length - 1] &= 0x7f;
          }
          out[size - 1] |= 0x80;
        }

        this.push(out);
        return;
      }
      case OpCode.OP_BIN2NUM: {
        this.requireMonolithOpcodes();
        const num = this.popNum();
        this.push(fromBigInt(num));
        return;
      }
      case OpCode.OP_SIZE: {
        this.push(fromBigInt(BigInt(this.top().length)));
        return;
      }

      case OpCode.OP_INVERT: {
        this.requireMonolithOpcodes();
        const data = this.pop();
        const out = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) out[i] = data[i] ^ 0xff;
        this.push(out);
        return;
      }
      case OpCode.OP_AND:
      case OpCode.OP_OR:
      case OpCode.OP_XOR: {
        this.requireMonolithOpcodes();
        const b = this.pop();
        const a = this.pop();
        if (a.length !== b.length)
          throw new ScriptEvalError("Bitwise length mismatch");
        const out = new Uint8Array(a.length);
        for (let i = 0; i < a.length; i++) {
          if (opcode === OpCode.OP_AND) out[i] = a[i] & b[i];
          else if (opcode === OpCode.OP_OR) out[i] = a[i] | b[i];
          else out[i] = a[i] ^ b[i];
        }
        this.push(out);
        return;
      }
      case OpCode.OP_EQUAL: {
        const b = this.pop();
        const a = this.pop();
        const ok = equal(a, b);
        if (this.traceEnabled) {
          this.equalityTrace.push({
            phase: this.tracePhase,
            pc,
            opcode,
            leftHex: toHex(a),
            rightHex: toHex(b),
            result: ok,
          });
          if (this.equalityTrace.length > this.traceLimit)
            this.equalityTrace.shift();
        }
        pushBool(this.stack, ok);
        return;
      }
      case OpCode.OP_EQUALVERIFY: {
        const b = this.pop();
        const a = this.pop();
        const ok = equal(a, b);
        if (this.traceEnabled) {
          this.equalityTrace.push({
            phase: this.tracePhase,
            pc,
            opcode,
            leftHex: toHex(a),
            rightHex: toHex(b),
            result: ok,
          });
          if (this.equalityTrace.length > this.traceLimit)
            this.equalityTrace.shift();
        }
        if (!ok) throw new ScriptEvalError("OP_EQUALVERIFY failed");
        return;
      }

      case OpCode.OP_1ADD:
        this.push(fromBigInt(this.popNum() + BigInt(1)));
        return;
      case OpCode.OP_1SUB:
        this.push(fromBigInt(this.popNum() - BigInt(1)));
        return;
      case OpCode.OP_2MUL:
        this.push(fromBigInt(this.popNum() * BigInt(2)));
        return;
      case OpCode.OP_2DIV:
        this.push(fromBigInt(this.popNum() / BigInt(2)));
        return;
      case OpCode.OP_NEGATE:
        this.push(fromBigInt(-this.popNum()));
        return;
      case OpCode.OP_ABS: {
        const n = this.popNum();
        this.push(fromBigInt(n < BigInt(0) ? -n : n));
        return;
      }
      case OpCode.OP_NOT:
        pushBool(this.stack, this.popNum() === BigInt(0));
        return;
      case OpCode.OP_0NOTEQUAL:
        pushBool(this.stack, this.popNum() !== BigInt(0));
        return;
      case OpCode.OP_ADD: {
        const b = this.popNum();
        const a = this.popNum();
        this.push(fromBigInt(a + b));
        return;
      }
      case OpCode.OP_SUB: {
        const b = this.popNum();
        const a = this.popNum();
        this.push(fromBigInt(a - b));
        return;
      }
      case OpCode.OP_MUL: {
        this.requireMagneticOpcodes();
        const b = this.popNum();
        const a = this.popNum();
        this.push(fromBigInt(a * b));
        return;
      }
      case OpCode.OP_DIV: {
        this.requireMagneticOpcodes();
        const b = this.popNum();
        if (b === BigInt(0)) throw new ScriptEvalError("OP_DIV by zero");
        const a = this.popNum();
        this.push(fromBigInt(a / b));
        return;
      }
      case OpCode.OP_MOD: {
        this.requireMagneticOpcodes();
        const b = this.popNum();
        if (b === BigInt(0)) throw new ScriptEvalError("OP_MOD by zero");
        const a = this.popNum();
        this.push(fromBigInt(a % b));
        return;
      }
      case OpCode.OP_LSHIFT: {
        this.requireMagneticOpcodes();
        const b = this.popNum();
        const a = this.popNum();
        this.push(fromBigInt(a << b));
        return;
      }
      case OpCode.OP_RSHIFT: {
        this.requireMagneticOpcodes();
        const b = this.popNum();
        const a = this.popNum();
        this.push(fromBigInt(a >> b));
        return;
      }
      case OpCode.OP_BOOLAND: {
        const b = this.popNum();
        const a = this.popNum();
        pushBool(this.stack, a !== BigInt(0) && b !== BigInt(0));
        return;
      }
      case OpCode.OP_BOOLOR: {
        const b = this.popNum();
        const a = this.popNum();
        pushBool(this.stack, a !== BigInt(0) || b !== BigInt(0));
        return;
      }
      case OpCode.OP_NUMEQUAL: {
        const b = this.popNum();
        const a = this.popNum();
        pushBool(this.stack, a === b);
        return;
      }
      case OpCode.OP_NUMEQUALVERIFY: {
        const b = this.popNum();
        const a = this.popNum();
        if (a !== b) throw new ScriptEvalError("OP_NUMEQUALVERIFY failed");
        return;
      }
      case OpCode.OP_NUMNOTEQUAL: {
        const b = this.popNum();
        const a = this.popNum();
        pushBool(this.stack, a !== b);
        return;
      }
      case OpCode.OP_LESSTHAN: {
        const b = this.popNum();
        const a = this.popNum();
        pushBool(this.stack, a < b);
        return;
      }
      case OpCode.OP_GREATERTHAN: {
        const b = this.popNum();
        const a = this.popNum();
        pushBool(this.stack, a > b);
        return;
      }
      case OpCode.OP_LESSTHANOREQUAL: {
        const b = this.popNum();
        const a = this.popNum();
        pushBool(this.stack, a <= b);
        return;
      }
      case OpCode.OP_GREATERTHANOREQUAL: {
        const b = this.popNum();
        const a = this.popNum();
        pushBool(this.stack, a >= b);
        return;
      }
      case OpCode.OP_MIN: {
        const b = this.popNum();
        const a = this.popNum();
        this.push(fromBigInt(a < b ? a : b));
        return;
      }
      case OpCode.OP_MAX: {
        const b = this.popNum();
        const a = this.popNum();
        this.push(fromBigInt(a > b ? a : b));
        return;
      }
      case OpCode.OP_WITHIN: {
        const max = this.popNum();
        const min = this.popNum();
        const x = this.popNum();
        pushBool(this.stack, x >= min && x < max);
        return;
      }

      case OpCode.OP_RIPEMD160: {
        const data = this.pop();
        this.push(ripemd160(data));
        return;
      }
      case OpCode.OP_SHA1:
        throw new ScriptEvalError("OP_SHA1 not supported");
      case OpCode.OP_SHA256: {
        const data = this.pop();
        this.push(sha256(data));
        return;
      }
      case OpCode.OP_HASH160: {
        const data = this.pop();
        this.push(hash160(data));
        return;
      }
      case OpCode.OP_HASH256: {
        const data = this.pop();
        this.push(hash256(data));
        return;
      }
      case OpCode.OP_CODESEPARATOR:
        this.codeSeparator = pc;
        return;
      case OpCode.OP_CHECKSIG:
      case OpCode.OP_CHECKSIGVERIFY: {
        const pubKey = this.pop();
        const sigWithType = this.pop();
        const { signature, sighashType } = parseSignature(
          sigWithType,
          this.requireDerSignatures,
        );

        const requireForkId = this.hasFlag(SCRIPT_ENABLE_SIGHASH_FORKID);
        const hasForkId =
          (sighashType & SignatureHashType.SIGHASH_FORKID) ===
          SignatureHashType.SIGHASH_FORKID;
        if (requireForkId && !hasForkId) {
          if (opcode === OpCode.OP_CHECKSIGVERIFY) {
            throw new ScriptEvalError("OP_CHECKSIGVERIFY missing FORKID");
          }
          pushBool(this.stack, false);
          return;
        }

        const scriptCode = this.getScriptCode();
        const preimage = buildSighashPreimage(
          this.ctx,
          scriptCode,
          sighashType,
        );
        const msg = hash256(preimage);

        const ok = (() => {
          try {
            return (
              signature.length > 0 &&
              nobleVerify(signature, msg, pubKey, {
                prehash: false,
                format: "compact",
              })
            );
          } catch {
            return false;
          }
        })();

        if (opcode === OpCode.OP_CHECKSIGVERIFY) {
          if (!ok) throw new ScriptEvalError("OP_CHECKSIGVERIFY failed");
          return;
        }

        pushBool(this.stack, ok);
        return;
      }
      case OpCode.OP_CHECKMULTISIG:
      case OpCode.OP_CHECKMULTISIGVERIFY: {
        const n = Number(this.popNum());
        if (n < 0 || n > this.stack.length)
          throw new ScriptEvalError("OP_CHECKMULTISIG invalid pubkey count");

        const pubKeys = this.stack.splice(this.stack.length - n, n);
        const m = Number(this.popNum());
        if (m < 0 || m > this.stack.length)
          throw new ScriptEvalError("OP_CHECKMULTISIG invalid sig count");

        const sigs = this.stack.splice(this.stack.length - m, m);

        this.pop(); // OP_CHECKMULTISIG bug

        let sigIdx = 0;
        let keyIdx = 0;
        let ok = false;
        try {
          while (sigIdx < m && keyIdx < n) {
            const { signature, sighashType } = parseSignature(
              sigs[sigIdx],
              this.requireDerSignatures,
            );
            const requireForkId = this.hasFlag(SCRIPT_ENABLE_SIGHASH_FORKID);
            const hasForkId =
              (sighashType & SignatureHashType.SIGHASH_FORKID) ===
              SignatureHashType.SIGHASH_FORKID;
            if (requireForkId && !hasForkId) {
              keyIdx++;
              continue;
            }
            const scriptCode = this.getScriptCode();
            const preimage = buildSighashPreimage(
              this.ctx,
              scriptCode,
              sighashType,
            );
            const msg = hash256(preimage);

            const matched =
              signature.length > 0 &&
              nobleVerify(signature, msg, pubKeys[keyIdx], {
                prehash: false,
                format: "compact",
              });

            if (matched) sigIdx++;
            keyIdx++;
          }

          ok = sigIdx === m;
        } catch {
          ok = false;
        }
        const success = ok;

        if (opcode === OpCode.OP_CHECKMULTISIGVERIFY) {
          if (!success)
            throw new ScriptEvalError("OP_CHECKMULTISIGVERIFY failed");
          return;
        }

        pushBool(this.stack, success);
        return;
      }

      case OpCode.OP_CHECKLOCKTIMEVERIFY: {
        const locktime = Number(decodeScriptNum(this.top()));
        if (locktime < 0) throw new ScriptEvalError("CLTV negative");
        const txLock = this.ctx.tx.LockTime;
        const txInput = this.ctx.tx.Inputs[this.ctx.inputIndex];
        if (txInput.Sequence === 0xffffffff)
          throw new ScriptEvalError("CLTV disabled by sequence");
        if (
          (locktime < 500000000 && txLock >= 500000000) ||
          (locktime >= 500000000 && txLock < 500000000)
        )
          throw new ScriptEvalError("CLTV locktime type mismatch");
        if (txLock < locktime)
          throw new ScriptEvalError("CLTV not yet reached");
        return;
      }
      case OpCode.OP_CHECKSEQUENCEVERIFY:
        throw new ScriptEvalError("OP_CHECKSEQUENCEVERIFY not supported");

      case OpCode.OP_RESERVED:
      case OpCode.OP_VER:
      case OpCode.OP_VERIF:
      case OpCode.OP_VERNOTIF:
      case OpCode.OP_RESERVED1:
      case OpCode.OP_RESERVED2:
        throw new ScriptEvalError("Disabled opcode");

      default:
        throw new ScriptEvalError(
          `Unsupported opcode: 0x${opcode.toString(16)}`,
        );
    }
  };
}

export const evaluateScripts = (
  unlockingScript: Bytes,
  lockingScript: Bytes,
  ctx: ScriptEvalContext,
  options?: ScriptEvalOptions,
): ScriptEvalResult => {
  const interpreter = new ScriptInterpreter(ctx, options);

  try {
    interpreter.setTracePhase("unlocking");
    interpreter.execute(unlockingScript);
    interpreter.setTracePhase("locking");
    interpreter.execute(lockingScript);

    const stack = interpreter.getStack();
    const success = stack.length > 0 && isTruthy(stack[stack.length - 1]);

    return {
      success,
      stack,
      altStack: interpreter.getAltStack(),
      trace: interpreter.getTrace(),
      equalityTrace: interpreter.getEqualityTrace(),
      error: success ? undefined : "Script evaluated to false",
    };
  } catch (err) {
    return {
      success: false,
      stack: interpreter.getStack(),
      altStack: interpreter.getAltStack(),
      trace: interpreter.getTrace(),
      equalityTrace: interpreter.getEqualityTrace(),
      error: err instanceof Error ? err.message : "Script error",
    };
  }
};

export const evaluateTransactionHex = (
  txHex: string,
  resolvePrevOutput: ResolvePrevOutput,
  options?: ScriptEvalOptions,
): TransactionEvalResult => {
  const tx = TransactionReader.readHex(txHex);
  const inputResults: TransactionInputEvalResult[] = [];
  const errors: string[] = [];
  const prevOutputs: PrevOutput[] = [];

  for (let i = 0; i < tx.Inputs.length; i++) {
    const input = tx.Inputs[i];
    const prev = resolvePrevOutput(input.TxId, input.Vout);
    if (!prev) {
      const error = `Missing prev output for input ${i}: ${input.TxId}:${input.Vout}`;
      inputResults.push({ inputIndex: i, success: false, error });
      errors.push(error);
      prevOutputs.push({ lockingScript: new Uint8Array(), satoshis: 0 });
      continue;
    }

    prevOutputs.push(prev);
  }

  for (let i = 0; i < tx.Inputs.length; i++) {
    if (inputResults.some((r) => r.inputIndex === i && !r.success)) continue;

    const result = evaluateScripts(
      tx.Inputs[i].UnlockingScript,
      prevOutputs[i].lockingScript,
      { tx, inputIndex: i, prevOutputs },
      options,
    );

    if (!result.success) {
      inputResults.push({
        inputIndex: i,
        success: false,
        error: result.error,
      });
      errors.push(`Input ${i} failed: ${result.error}`);
    } else {
      inputResults.push({ inputIndex: i, success: true });
    }
  }

  return {
    txId: tx.Id,
    success: inputResults.every((r) => r.success),
    inputs: inputResults.sort((a, b) => a.inputIndex - b.inputIndex),
    errors,
  };
};

export const createPrevOutputResolverFromTransactions = (
  txMap: Map<string, Transaction>,
): ResolvePrevOutput => {
  return (txId: string, vout: number) => {
    const tx = txMap.get(txId);
    if (!tx) return undefined;
    const output = tx.Outputs[vout];
    if (!output) return undefined;
    return {
      lockingScript: output.LockingScript,
      satoshis: output.Satoshis,
    };
  };
};
