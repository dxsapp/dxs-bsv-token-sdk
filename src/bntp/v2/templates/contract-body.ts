import { toHex } from "../../../bytes";
import { asmToBytes } from "../../../script/build/asm-template-builder";
import { NORMAL_BODY_BYTES } from "./normal-body";

import {
  COVENANT_S_PREAMBLE_ASM,
  COVENANT_TAIL_ASM,
  SIGHASH_CHECK_ASM,
  PREIMAGE_PARSE_ASM,
  TAIL_CACHE_ASM,
} from "./shared-prefix";
// ---------------------------------------------------------------------------
// Shared PREFIX ASM blocks — copied verbatim from normal-body.ts.
// ---------------------------------------------------------------------------
// normal-body.ts keeps these as non-exported `const` (module-local), so we
// cannot import them directly. To avoid modifying normal-body.ts (forbidden
// scope per Phase 1A.3 brief), we duplicate the ASM text here. The duplicates
// are byte-for-byte identical; a CI lint could assert this equality. Any
// future edit to normal-body's PREFIX MUST be mirrored here — Phase 1B's
// template-hash-verification tool (decision #26) will catch drift at deploy.
//
// Sections copied:
//   - COVENANT_S_PREAMBLE_ASM  (§3.2 covenant preamble — 197b)
//   - COVENANT_TAIL_ASM        (§3.2 covenant tail     — 241b)
//   - SIGHASH_CHECK_ASM        (§3.3 sighash check     —  13b)
//   - PREIMAGE_PARSE_ASM       (§3.4 preimage parse    — 121b)
//   - TAIL_CACHE_ASM           (§3.5 tail cache        — 159b)
// ---------------------------------------------------------------------------






/**
 * BNTP v2 Contract template body ASM — Phase 1 A.3 scope.
 *
 * Covers (real, assemblable BSV Script):
 *   - PREFIX (shared with Normal): body marker (Contract-specific `0xc0 0xff`),
 *     OP_PUSH_TX covenant preamble + tail, sighash-type check, preimage parse,
 *     scriptCode tail cache (tail layout identical to Normal per §9.9.1).
 *   - PATH DISPATCHER: Contract has exactly one spend path (`path_id = 6`
 *     issue). Dispatcher is therefore trivial (`OP_6 OP_EQUALVERIFY`).
 *   - PATH 6 SUFFIX — issue (§9.9): issuer identity (PKH + MPKH per §8.1 /
 *     §8.2, via reused `authorityIdentityAsm` pattern), N-output reconstruction
 *     using an INLINED Normal body constant (decision #28, §5.5.2), tail-field
 *     preservation (issuerPkh/flags/freezeAuthHash/confiscAuthHash/
 *     optionalData byte-exact — decision #10/#47), `new_depth = 0` on every
 *     output, output-owner OP_SIZE==20 check (decision #43, Phase 1A PKH-only
 *     per A.3.2), amount conservation `Σ output_amounts == Contract.reserve_amount`
 *     (decision #17), null-data attestation at output index N with
 *     `thisOutpoint = preimage.outpoint` (decision #42, Step C Moderate #4),
 *     `HASH160(issuer_pubkey) == issuerPkh` check, and hashOutputs closure.
 *
 * Key design constraint (decision #28, §5.5.2):
 * Contract body INLINES the full Normal template body bytes (2620b) as a
 * single data push constant, used during candidate-output reconstruction.
 * The constant is pushed once and cached on altstack; each of the N output
 * reconstructions pulls and re-pushes it via FROMALTSTACK/DUP/TOALTSTACK
 * (rather than re-emitting a 2620b push per output).
 *
 * Output-count bound: we unroll N = 4 outputs per issue tx. Larger N is
 * rejected in Phase 1A (matches flex-transfer's ×4 unroll, consistent with
 * spec §9.2 rule 7 M ∈ [1,4] for Normal flex-transfer; §9.9 does not cap N
 * explicitly, but Phase 1A adopts the same bound for body-budget reasons).
 * Phase 1B may extend to larger N via explicit loop-unroll or different
 * template variant (`ContractMintableLarge`), at additional byte cost.
 *
 * IMPORTANT — this script is written to be byte-measurable and structurally
 * complete. Stack-management sequences mirror Normal's patterns and are
 * subject to the same audit caveat (see normal-body.ts header). Execution
 * correctness is a Phase 1B deliverable.
 *
 * References:
 *   - docs/BNTP_V2_SPEC.md §3 (Contract row), §5.5.2, §7, §8.1, §8.2,
 *     §9.1, §9.9, §9.9.1, §9.11, §13.6, §15 decisions #17, #28, #29, #34,
 *     #41, #42, #43, #47.
 *   - src/bntp/v2/templates/normal-body.ts — donor for all PREFIX blocks.
 */

// ---------------------------------------------------------------------------
// §3.1 Body marker (Contract: `0xc0 0xff`)
// ---------------------------------------------------------------------------
// Same encoding convention as Normal: OP_PUSHDATA1 0x02 0xc0 0xff OP_DROP (5b).
// The leading `4c 02` distinguishes body-marker push from other 2-byte pushes;
// the `c0 ff` payload is Contract-specific (Normal is `01 ff`, Frozen is
// `02 ff`).
const BODY_MARKER_BYTES = new Uint8Array([0x4c, 0x02, 0xc0, 0xff, 0x75]);

// ---------------------------------------------------------------------------
// §3.7 Path dispatcher (Contract has only path 6)
// ---------------------------------------------------------------------------
// `path_id` sits on the main stack top (just-below owner/issuer pubkey-sig
// pair per §9.1 common stack layout — but Contract's issue unlocking is
// structured such that the covenant already consumed the preimage, and
// `path_id` is immediately below the issuer sig/pubkey pair). We simply
// verify `path_id == 6` (§9.9 mandates this path and only this path exists
// for Contract). OP_6 in BSV Script is `0x56`; OP_EQUALVERIFY checks the
// constant. Trailing OP_DROP is not needed because OP_EQUALVERIFY consumes
// both operands.
const CONTRACT_DISPATCHER_ASM = `
  OP_6 OP_EQUALVERIFY
`;

// ---------------------------------------------------------------------------
// §9.9 Path 6 — issue (Contract → Normal × N, with N ≤ 4 in Phase 1A)
// ---------------------------------------------------------------------------

// Issuer identity helper (copied verbatim from Normal's `authorityIdentityAsm`
// with `flagMaskHex = "10"` for bit 4 / issuer). We redefine locally because
// the helper is not exported from normal-body.ts; the byte-level structure
// must match exactly so that any future edit to Normal's helper propagates
// here intentionally (not silently). Per decision #41, this helper performs
// the on-chain `m ≥ 1` MPKH bounds check.
const CONTRACT_ISSUER_IDENTITY_ASM = `
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  10 OP_AND 00 OP_EQUAL
  OP_IF
    OP_OVER OP_HASH160
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
    OP_EQUALVERIFY
    OP_CHECKSIGVERIFY
  OP_ELSE
    OP_OVER OP_HASH160
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
    OP_EQUALVERIFY
    OP_OVER
    OP_1 OP_SPLIT OP_SWAP 00 OP_CAT OP_BIN2NUM
    OP_TOALTSTACK
    OP_SIZE OP_1SUB OP_SPLIT OP_NIP 00 OP_CAT OP_BIN2NUM
    OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY
    OP_DUP OP_1 OP_6 OP_WITHIN OP_VERIFY
    OP_2DUP OP_LESSTHANOREQUAL OP_VERIFY
    OP_TOALTSTACK
    OP_FROMALTSTACK
    OP_DUP 21 OP_SPLIT OP_SWAP OP_TOALTSTACK
    OP_DUP OP_SIZE OP_NIP OP_IF
      21 OP_SPLIT OP_SWAP OP_TOALTSTACK
    OP_ENDIF
    OP_DUP OP_SIZE OP_NIP OP_IF
      21 OP_SPLIT OP_SWAP OP_TOALTSTACK
    OP_ENDIF
    OP_DUP OP_SIZE OP_NIP OP_IF
      21 OP_SPLIT OP_SWAP OP_TOALTSTACK
    OP_ENDIF
    OP_DUP OP_SIZE OP_NIP OP_IF
      21 OP_SPLIT OP_SWAP OP_TOALTSTACK
    OP_ENDIF
    OP_DROP
    OP_FROMALTSTACK
    OP_CHECKMULTISIGVERIFY
  OP_ENDIF
`;

// Derive N from the top-of-stack marker pushed by SDK (path 6 unlocking
// pushes N as ScriptNum right after the output tuples). N is range-checked
// `1 ≤ N ≤ 4` in Phase 1A (§9.9 uncapped; Phase 1A matches flex-transfer ×4
// bound). Cached on altstack.
const PATH6_N_DERIVE_ASM = `
  OP_DEPTH OP_1SUB OP_PICK
  OP_DUP OP_1 OP_5 OP_WITHIN OP_VERIFY
  OP_TOALTSTACK
`;

// Inline Normal body as a single data push, cache on altstack. The 2620b
// push compiles via OP_PUSHDATA2 (0x4d <2b LE len> <bytes>) ⇒ 2623b on-chain.
// Altstack persistence lets all N output reconstructions share the push.
const NORMAL_BODY_HEX = toHex(NORMAL_BODY_BYTES);
const PATH6_INLINE_NORMAL_BODY_ASM = `
  ${NORMAL_BODY_HEX}
  OP_TOALTSTACK
`;

// Per-output reconstruction block. Assumes:
//   - Top of main stack: output_tuple_i = [amount 16b ‖ owner 20b (PKH only,
//     phase 1A per A.3.2) ‖ body_marker 2b = 0x01ff]
//   - Altstack slot (read-only via FROMALTSTACK/TOALTSTACK round-trip):
//     tokenId, issuerPkh, authorityFlags, freezeAuthHash, confiscAuthHash,
//     optionalData (all from tail cache — §3.5 of normal-body.ts),
//     NORMAL_BODY_INLINE (just-cached above), running outputs_hash_buffer
//     (accumulator).
//
// This block is gated on `i < N` (caller emits OP_IF gate based on N-counter).
//
// Candidate output layout (byte-exact, matching §9.9 rule 2 with decision
// #33 raw-bytes owner field):
//   `[owner_push: 14 ‖ owner_pkh_20b] ‖ [action_data: 00 6d] ‖
//    [NORMAL_BODY_INLINE] ‖ [OP_RETURN: 6a] ‖
//    [reconstructed_tail: tokenId_32b ‖ issuerPkh_20b ‖ new_amount_16b ‖
//     authorityFlags_1b ‖ freezeAuthHash_20b ‖ confiscAuthHash_20b ‖
//     new_depth_2b(=0000) ‖ optionalData_var]`
//
// Pre-pended with `[satoshis: 01 00 00 00 00 00 00 00]` (1-sat anti-dust) and
// varint length prefix via the same FD-only pattern as Normal (decision #38;
// Normal output lands in [0xFD..0xFFFF] range always — body + tail + owner +
// action_data >> 252 bytes, and < 65535 due to 4096b optionalData cap).
//
// Per decision #43 (Step C Moderate #5), we verify `OP_SIZE(owner) == 20`
// explicitly. Phase 1A owner field is PKH-only (A.3.2 gap).
const PATH6_OUTPUT_ONE_ASM = `
  OP_DEPTH OP_1SUB OP_PICK
  10 OP_SPLIT
  OP_OVER OP_BIN2NUM OP_0 OP_GREATERTHAN OP_VERIFY
  OP_SWAP OP_TOALTSTACK
  14 OP_SPLIT
  OP_SWAP
  OP_DUP OP_SIZE OP_NIP 14 OP_NUMEQUALVERIFY
  OP_SWAP
  01FF OP_EQUALVERIFY
  14 OP_CAT
  006D OP_SWAP OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  6A OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  0000 OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  0100000000000000 OP_SWAP
  OP_SIZE OP_SWAP
  OP_ROT OP_SWAP
  FD OP_CAT OP_SWAP OP_2 OP_SPLIT OP_DROP OP_CAT
  OP_SWAP OP_CAT OP_CAT
`;

// Amount accumulation: after each output's amount is extracted (cached on
// altstack pre-tuple-parse above), add to running sum on altstack. The
// sum is initialized to 0 before the first output and compared to
// `Contract.reserve_amount` (tail cache slot) at the end.
//
// To keep byte budget tractable, this helper does NOT repeat per-output — the
// accumulator is threaded inline via OP_ADD inside the loop body below.

// Gate wrapper: executes body if `i < N`. N is on altstack top; we
// FROMALTSTACK to read it, DUP, TOALTSTACK to replace, then compare to
// literal `i`. N is uint range [1..4] so OP_GREATERTHAN works.
const gateIter = (index: number, bodyAsm: string) => `
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_${index} OP_GREATERTHAN
  OP_IF
    ${bodyAsm}
    OP_CAT
  OP_ELSE
  OP_ENDIF
`;

// Four iterations of per-output reconstruction, gated on i < N. The first
// iteration initializes the outputs_hash_buffer accumulator; subsequent
// iterations OP_CAT their serialized output bytes onto it.
const PATH6_RECON_ASM = `
  ${""} OP_0 OP_TOALTSTACK
  ${""} OP_0 OP_TOALTSTACK
  ${gateIter(0, PATH6_OUTPUT_ONE_ASM)}
  ${gateIter(1, PATH6_OUTPUT_ONE_ASM)}
  ${gateIter(2, PATH6_OUTPUT_ONE_ASM)}
  ${gateIter(3, PATH6_OUTPUT_ONE_ASM)}
`;

// Amount conservation: Σ output_amounts == Contract.reserve_amount. The
// running sum (built via OP_ADD during the four iterations above) is
// compared to the tail-cached reserve_amount (16b LE u128 at the
// `amount` slot of the tail cache from TAIL_CACHE_ASM). OP_BIN2NUM
// truncates the push to ScriptNum (int63 cap per §9.11).
const PATH6_CONSERVATION_ASM = `
  OP_FROMALTSTACK
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  00 OP_CAT OP_BIN2NUM
  OP_EQUALVERIFY
`;

// Null-data attestation parse (output at index N). The unlocking pushes the
// null-data payload below the tuples; here we reach it via OP_DEPTH offset
// (approximate — exact offset is a Phase 1B refinement). The null-data
// payload contains three fields (per §7.2): tokenId (32b), thisOutpoint
// (36b = Contract's spending outpoint per decision #42, from preimage.
// outpoint cached on altstack in §3.4), and issuerPubkey (33b compressed or
// MPKH preimage). Each is direct-push-minimal (§7.2.1 / decision #24).
//
// Verification (§7.3 + decision #42):
//   1. tokenId == Contract.tokenId (tail cache)
//   2. thisOutpoint == preimage.outpoint (altstack slot, decision #42)
//   3. HASH160(issuerPubkey) == Contract.issuerPkh (tail cache)
//
// The null-data output is also appended to the outputs_hash_buffer so that
// the final hashOutputs match includes it.
const PATH6_NULLDATA_VERIFY_ASM = `
  OP_DEPTH OP_2 OP_SUB OP_PICK
  OP_1 OP_SPLIT OP_NIP
  OP_1 OP_SPLIT OP_NIP
  OP_1 OP_SPLIT OP_NIP
  20 OP_SPLIT
  OP_SWAP
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_EQUALVERIFY
  OP_1 OP_SPLIT OP_NIP
  24 OP_SPLIT
  OP_SWAP
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_EQUALVERIFY
  OP_1 OP_SPLIT OP_NIP
  OP_HASH160
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_EQUALVERIFY
`;

// hashOutputs closure: append the serialized null-data output to the
// accumulator, HASH256 it, compare to preimage's hashOutputs field.
const PATH6_HASHOUTPUTS_CLOSE_ASM = `
  OP_DEPTH OP_2 OP_SUB OP_PICK
  OP_SWAP OP_CAT
  OP_HASH256
  OP_FROMALTSTACK
  OP_EQUALVERIFY
`;

// Full path 6 SUFFIX.
const PATH6_ISSUE_ASM = `
  ${CONTRACT_ISSUER_IDENTITY_ASM}
  ${PATH6_N_DERIVE_ASM}
  ${PATH6_INLINE_NORMAL_BODY_ASM}
  ${PATH6_RECON_ASM}
  ${PATH6_CONSERVATION_ASM}
  ${PATH6_NULLDATA_VERIFY_ASM}
  ${PATH6_HASHOUTPUTS_CLOSE_ASM}
`;

// ---------------------------------------------------------------------------
// Assemble CONTRACT_BODY_ASM
// ---------------------------------------------------------------------------
export const CONTRACT_BODY_ASM = `
  ${COVENANT_S_PREAMBLE_ASM}
  ${COVENANT_TAIL_ASM}
  ${SIGHASH_CHECK_ASM}
  ${PREIMAGE_PARSE_ASM}
  ${TAIL_CACHE_ASM}
  ${CONTRACT_DISPATCHER_ASM}
  ${PATH6_ISSUE_ASM}
`;

/**
 * Compile CONTRACT_BODY_ASM to raw bytes. Prepends the Contract body-marker
 * PUSHDATA1 sequence (`4c 02 c0 ff 75`) that asmToBytes cannot emit directly.
 */
export const compileContractBody = (): Uint8Array => {
  const tail = asmToBytes(CONTRACT_BODY_ASM);
  const out = new Uint8Array(BODY_MARKER_BYTES.length + tail.length);
  out.set(BODY_MARKER_BYTES, 0);
  out.set(tail, BODY_MARKER_BYTES.length);
  return out;
};

export const CONTRACT_BODY_BYTES: Uint8Array = compileContractBody();
export const CONTRACT_BODY_SIZE: number = CONTRACT_BODY_BYTES.length;

/**
 * Per-section byte breakdown (for reporting). Each section is compiled in
 * isolation; sum equals CONTRACT_BODY_BYTES.length.
 *
 * `inlinedNormalBody` = 2620b payload + 3b PUSHDATA2 prefix + 1b OP_TOALTSTACK
 * (the whole PATH6_INLINE_NORMAL_BODY_ASM block).
 */
export const CONTRACT_BODY_SECTION_SIZES = {
  bodyMarker: BODY_MARKER_BYTES.length,
  covenantPreamble: asmToBytes(COVENANT_S_PREAMBLE_ASM).length,
  covenantTail: asmToBytes(COVENANT_TAIL_ASM).length,
  sighashCheck: asmToBytes(SIGHASH_CHECK_ASM).length,
  preimageParse: asmToBytes(PREIMAGE_PARSE_ASM).length,
  tailCache: asmToBytes(TAIL_CACHE_ASM).length,
  dispatcher: asmToBytes(CONTRACT_DISPATCHER_ASM).length,
  issuerIdentity: asmToBytes(CONTRACT_ISSUER_IDENTITY_ASM).length,
  path6NDerive: asmToBytes(PATH6_N_DERIVE_ASM).length,
  inlinedNormalBody: asmToBytes(PATH6_INLINE_NORMAL_BODY_ASM).length,
  path6Recon: asmToBytes(PATH6_RECON_ASM).length,
  path6Conservation: asmToBytes(PATH6_CONSERVATION_ASM).length,
  path6NullDataVerify: asmToBytes(PATH6_NULLDATA_VERIFY_ASM).length,
  path6HashOutputsClose: asmToBytes(PATH6_HASHOUTPUTS_CLOSE_ASM).length,
} as const;
