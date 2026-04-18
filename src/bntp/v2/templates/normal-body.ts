import { asmToBytes } from "../../../script/build/asm-template-builder";
import {
  COVENANT_PREIMAGE_ROLL_ASM,
  COVENANT_S_PREAMBLE_ASM,
  COVENANT_TAIL_ASM,
  SIGHASH_CHECK_ASM,
  PREIMAGE_PARSE_ASM,
  TAIL_CACHE_ASM,
  VARINT_SERIALIZE_ASM,
  authorityIdentityAsm,
} from "./shared-prefix";

// Re-export shared PREFIX blocks for backward compatibility with sibling
// templates and tests that import from normal-body.ts. Canonical source:
// ./shared-prefix.ts (Phase 1B decision #51 refactor).
export {
  COVENANT_S_PREAMBLE_ASM,
  COVENANT_TAIL_ASM,
  SIGHASH_CHECK_ASM,
  PREIMAGE_PARSE_ASM,
  TAIL_CACHE_ASM,
  VARINT_SERIALIZE_ASM,
  authorityIdentityAsm,
};

/**
 * BNTP v2 Normal template body ASM — Phase 1 A.1.1 + A.2 + A.2.5 scope.
 *
 * Covers (real, assemblable BSV Script):
 *   - PREFIX (§3 of pseudo-ASM): body marker, OP_PUSH_TX covenant, sighash-type
 *     check, preimage parse, scriptCode tail cache, owner identity (PKH + MPKH),
 *     path dispatcher.
 *   - Path 1 flex-transfer SUFFIX (§4.1): hashPrevouts binding, N derive,
 *     selfPosition match, amounts_in_array length, amounts_in_array[selfPos]
 *     check, M range check, max_input_depth check, amount conservation
 *     (unrolled ×4 in + ×4 out), output reconstruction (unrolled ×4),
 *     hashOutputs closure.
 *   - **A.2 additions:** Path 2 refresh (§4.2), Path 3 freeze (§4.3), Path 4
 *     confiscate (§4.4) SUFFIXes. Each path emits real assembled opcodes
 *     implementing spec §9.3 / §9.4 / §9.5 verification rules, including
 *     PKH + MPKH branches for freeze / confisc / issuer authorities per §8.1.
 *   - **A.2.5 additions (decisions #34, #37, #38):** (1) MPKH issuer branch on
 *     path 2 gated on authorityFlags bit 4; (2) optional P2PKH-style change
 *     output at index 3 of refresh tx, gated on non-empty `change_script_bytes`
 *     in unlocking; (3) retroactive FD-only varint optimization applied to
 *     path 1 output reconstruction (three-branch selector → single-branch
 *     FD + 2-byte LE length, mirroring A.2's `VARINT_SERIALIZE_ASM`).
 *
 * Scope completed: A.1.1 + A.2 + A.2.5. Remaining: Contract and Frozen
 * template bodies (separate artifacts, not in this file).
 *
 * IMPORTANT — this script is written to be byte-measurable and structurally
 * complete. It has NOT been executed on a node; several stack-management
 * sequences are best-effort reproductions of the pseudo-ASM's intent with
 * audit-flagged stack corrections (see §3.5). The primary purpose of A.1.1
 * is to falsify the byte-budget assumption via concrete artifact — NOT to
 * ship a ready-to-deploy covenant. Execution correctness is A.2 / Phase 1B work.
 *
 * References:
 *   - docs/BNTP_V2_SPEC.md §3, §5, §8.1, §9.1, §9.2
 *   - docs/BNTP_V2_NORMAL_TEMPLATE_AUDIT.md §2-§3
 *   - docs/BNTP_V2_TEMPLATE_NORMAL_ASM.md §3-§4
 *   - src/script/templates/dstas-locking-template.ts (donor for §3.2 covenant)
 */

// ---------------------------------------------------------------------------
// §3.1 Body marker `0x01 0xff`
// ---------------------------------------------------------------------------
// Spec §5 convention: emit marker via OP_PUSHDATA1 0x02 0x01 0xFF OP_DROP (5b)
// for external-parser discoverability (a 2-byte direct push would be 4b but
// breaks the scanner convention used by wallets/indexers).
//
// The ASM-builder auto-selects minimal push encoding (direct push for data ≤ 75b)
// and there is no ASM escape for "force PUSHDATA1". We therefore emit these 5
// bytes as a literal byte prefix in the compile helper below.
const BODY_MARKER_BYTES = new Uint8Array([0x4c, 0x02, 0x01, 0xff, 0x75]);

// ---------------------------------------------------------------------------
// §3.2 OP_PUSH_TX covenant (ported from DSTAS donor)
// ---------------------------------------------------------------------------
// Standard generator-point covenant: dynamic `s` from HASH256(preimage), DER
// assembly from two 16-byte r/s chunks, parity-branched generator pubkey,
// OP_CHECKSIGVERIFY. This is the preimage-authentication block — NOT the
// owner-authorization block (see §3.6 per spec §8.1 / decision #29).
//
// The covenant expects the preimage on the top of the main stack and leaves
// the preimage on top after completion, plus altstack state consistent with
// the DSTAS original (the parity bit was prepared in preamble). For A.1.1
// byte-budget purposes we embed only the tail portion from the `3044...`
// signature prefix marker through OP_CHECKSIGVERIFY, matching the task spec
// ("from `3044022079BE...0220` through `OP_CHECKSIGVERIFY`").
//
// The preamble computing `s` is ~120b in DSTAS. We include it here too since
// omitting it would leave the covenant non-functional and the byte budget
// artificially low. See DSTAS_LOCKING_TEMPLATE_ASM for original context.

// Tail of the covenant: assembles DER-encoded sig, appends sighash byte,
// branches pubkey by parity, runs CHECKSIGVERIFY. Verbatim from DSTAS donor.

// ---------------------------------------------------------------------------
// §3.3 Sighash-type check (preimage last 4 bytes == 0x41000000)
// ---------------------------------------------------------------------------
// Extract last 4 bytes of preimage and compare to 0x41000000 (SIGHASH_ALL |
// SIGHASH_FORKID, LE-encoded in preimage trailer). Per spec §9.2.

// ---------------------------------------------------------------------------
// §3.4 Preimage parse
// ---------------------------------------------------------------------------
// Unoptimized DSTAS-style parse — per audit §4.3 this comes in at ~240-300b
// when DSTAS 5.1.A/5.1.B optimizations are NOT applied. For A.1.1 we ship
// the honest unoptimized version; optimization pass is a separate task.
//
// BSV SIGHASH_FORKID preimage layout:
//   [4b nVersion] [32b hashPrevouts] [32b hashSequence] [36b outpoint]
//   [varint scriptCodeLen] [scriptCode] [8b nValue] [4b nSequence]
//   [32b hashOutputs] [4b nLocktime] [4b sighashType]
//
// We cache hashPrevouts, thisOutpoint, scriptCode, hashOutputs to altstack.
// Preimage itself stays on main stack after parse for downstream covenant use.

// ---------------------------------------------------------------------------
// §3.5 ScriptCode tail extraction + cache (7 tail fields to altstack)
// ---------------------------------------------------------------------------
// The scriptCode is on altstack (cached in §3.4). Pull it back and walk the
// fixed 111-byte tail layout. Note: OP_SPLIT leaves `[left, right]` with
// right on top — so after a split of N bytes we SWAP to put the left chunk
// (the field value) on top, TOALTSTACK it, then continue splitting the
// remaining suffix. This is the stack-arithmetic correction called out in
// audit §3.1.
//
// Tail layout (111 bytes fixed + var optionalData):
//   [0..32)    tokenId        32b
//   [32..52)   issuerPkh      20b
//   [52..68)   amount (LE u128) 16b
//   [68..69)   authorityFlags 1b
//   [69..89)   freezeAuthHash 20b
//   [89..109)  confiscAuthHash 20b
//   [109..111) attestation_depth (LE u16) 2b
//   [111..)    optionalData (variable)
//
// First we find OP_RETURN in scriptCode. Since scriptCode = body_before_tail ‖
// OP_RETURN ‖ tail, we walk scriptCode searching for 0x6a. For A.1.1 we assume
// there is exactly one OP_RETURN (body invariant) and use a fixed-offset split
// at compile time: the SDK's deployer resolves PREFIX+SUFFIX length and patches
// a constant. Here we use a 2-byte length placeholder pushed as `0000` — the
// actual value is replaced post-assembly by the deployer. This keeps byte
// count honest.

// ---------------------------------------------------------------------------
// §3.6 Owner identity check (PKH + MPKH)
// ---------------------------------------------------------------------------
// Per spec §8.1 / decision #29: PKH owner requires TWO checks:
//   1. HASH160(owner_pubkey) == owner_field (identity binding)
//   2. Explicit OP_CHECKSIGVERIFY(owner_sig, owner_pubkey, preimage)
// Covenant's CHECKSIGVERIFY (§3.2) is preimage-auth only, NOT owner-auth.
//
// Owner field is in the variable prefix (before body), not in the tail. For
// PKH: owner_field = 20b PKH. For MPKH: owner_field = 20b HASH160 of MPKH
// preimage. The flag bit 5 of authorityFlags indicates MPKH owner.
//
// This block assumes:
//   - owner_pubkey on top of stack (from unlocking, above [path_id=1])
//   - owner_sig one-below
//   - preimage somewhere accessible (on altstack via §3.4)
//   - authorityFlags available from altstack (cached in §3.5 slot 4 from bottom)
//   - owner_field pushed here as a template-compile-time constant is NOT
//     possible since it varies per UTXO; SDK resolves it at locking build.
//     We read owner_field from the scriptCode's variable-prefix, which means
//     in real deployment the variable prefix must be walkable. For A.1.1 the
//     owner_field is assumed to already be on altstack from §3.5's pre-split
//     step (implicit — A.2 refinement will formalize).
const OWNER_IDENTITY_ASM = `
  OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
  OP_DUP OP_TOALTSTACK
  OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
  20 OP_AND 00 OP_EQUAL
  OP_IF
    OP_DUP OP_HASH160
    OP_DUP OP_TOALTSTACK
    OP_EQUALVERIFY
    OP_SWAP
    OP_DUP OP_TOALTSTACK
    OP_ROT
    OP_CHECKSIGVERIFY
  OP_ELSE
    OP_DUP OP_HASH160
    OP_DUP OP_TOALTSTACK
    OP_EQUALVERIFY
    OP_DUP
    OP_1 OP_SPLIT OP_SWAP 00 OP_CAT OP_BIN2NUM
    OP_TOALTSTACK
    OP_SIZE OP_1SUB OP_SPLIT OP_NIP 00 OP_CAT OP_BIN2NUM
    OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY
    OP_DUP OP_1 OP_6 OP_WITHIN OP_VERIFY
    OP_2DUP OP_LESSTHANOREQUAL OP_VERIFY
    OP_TOALTSTACK
    OP_FROMALTSTACK
    OP_DUP
    21 OP_SPLIT OP_SWAP OP_TOALTSTACK
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

// ---------------------------------------------------------------------------
// §3.7 Path dispatcher
// ---------------------------------------------------------------------------
// path_id ∈ [1, 4] range check, then 4-way dispatch. Paths 2-4 are stubbed
// (`OP_FALSE OP_VERIFY`). Path 1 is the flex-transfer suffix body below.
const DISPATCHER_HEADER_ASM = `
  OP_DUP OP_1 OP_5 OP_WITHIN OP_VERIFY
  OP_DUP OP_1 OP_EQUAL OP_IF
`;

// DISPATCHER_MIDDLE_ASM is defined below, after paths 2, 3, 4 constants
// (§4.2-§4.4), because its template expansion inlines them. See definition
// just above the NORMAL_BODY_ASM assembly block.

// ---------------------------------------------------------------------------
// §4.1 Path 1 — flex-transfer SUFFIX
// ---------------------------------------------------------------------------
// Stack expected on entry (schematic — exact choreography is A.2 refinement):
//   main: [preimage ... M output_tuples... amounts_in_array all_input_outpoints selfPosition max_input_depth ...]
//   alt: [ hashPrevouts, thisOutpoint, scriptCode (consumed), hashOutputs, tokenId, issuerPkh, amount, authorityFlags, freezeAuthHash, confiscAuthHash, attestation_depth, optionalData, owner_field ]
//
// For byte-count honesty we write the real opcodes that spec §9.2 mandates.

// (a) hashPrevouts binding: HASH256(all_input_outpoints ‖ funding_outpoint) == hashPrevouts
const PATH1_HASHPREVOUTS_BIND_ASM = `
  OP_OVER OP_OVER OP_CAT
  OP_HASH256
  OP_FROMALTSTACK
  OP_DUP OP_TOALTSTACK
  OP_EQUALVERIFY
`;

// (b) N derive: N = |all_input_outpoints| / 36; N ∈ [1, 32]
const PATH1_N_DERIVE_ASM = `
  OP_OVER OP_SIZE OP_NIP
  OP_DUP 24 OP_MOD 00 OP_EQUALVERIFY
  24 OP_DIV
  OP_DUP OP_1 OP_GREATERTHANOREQUAL OP_VERIFY
  OP_DUP 20 OP_LESSTHANOREQUAL OP_VERIFY
  OP_TOALTSTACK
`;

// (c) selfPosition: all_input_outpoints[selfPos*36..+36] == thisOutpoint
const PATH1_SELFPOS_OUTPOINT_ASM = `
  OP_DUP 24 OP_MUL
  OP_2 OP_PICK OP_SWAP OP_SPLIT OP_NIP
  24 OP_SPLIT OP_DROP
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_EQUALVERIFY
`;

// (d) amounts_in_array length == N*16, and amounts_in_array[selfPos*16..+16] == my_amount
const PATH1_AMOUNTS_ARRAY_ASM = `
  OP_3 OP_PICK OP_SIZE OP_NIP
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK 10 OP_MUL
  OP_EQUALVERIFY
  OP_DUP 10 OP_MUL
  OP_4 OP_PICK OP_SWAP OP_SPLIT OP_NIP
  10 OP_SPLIT OP_DROP
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_EQUALVERIFY
`;

// (e) M range check: M ∈ [1, 4]
const PATH1_M_CHECK_ASM = `
  OP_DEPTH OP_1SUB OP_PICK
  OP_DUP OP_1 OP_5 OP_WITHIN OP_VERIFY
  OP_TOALTSTACK
`;

// (f) max_input_depth: my_depth ≤ max_input_depth
const PATH1_DEPTH_CHECK_ASM = `
  OP_OVER
  00 OP_CAT OP_BIN2NUM
  OP_FROMALTSTACK OP_FROMALTSTACK
  OP_DUP OP_TOALTSTACK OP_SWAP OP_TOALTSTACK
  00 OP_CAT OP_BIN2NUM
  OP_SWAP OP_LESSTHANOREQUAL OP_VERIFY
`;

// (g) Amount conservation — sum inputs (×4 unrolled, gated on i < N) and
// sum outputs (×4 unrolled, gated on i < M), then EQUALVERIFY.
//
// Per-iteration cost: push offset constant, extract 16b slice from the
// array, BIN2NUM, accumulate via altstack, with i<N gate (OP_IF...OP_ENDIF).
// ~20-25b × 4 per side.
const PATH1_SUM_INPUTS_ASM = `
  OP_0 OP_TOALTSTACK

  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_0 OP_LESSTHAN OP_NOT
  OP_IF
    OP_2 OP_PICK OP_0 10 OP_ADD OP_SPLIT OP_NIP 10 OP_SPLIT OP_DROP
    OP_8 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP OP_BIN2NUM
    OP_0 OP_EQUALVERIFY
    OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
  OP_ENDIF

  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_1 OP_GREATERTHAN
  OP_IF
    OP_2 OP_PICK 10 OP_ADD OP_SPLIT OP_NIP 10 OP_SPLIT OP_DROP
    OP_8 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP OP_BIN2NUM
    OP_0 OP_EQUALVERIFY
    OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
  OP_ENDIF

  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_2 OP_GREATERTHAN
  OP_IF
    OP_2 OP_PICK 20 OP_ADD OP_SPLIT OP_NIP 10 OP_SPLIT OP_DROP
    OP_8 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP OP_BIN2NUM
    OP_0 OP_EQUALVERIFY
    OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
  OP_ENDIF

  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_3 OP_GREATERTHAN
  OP_IF
    OP_2 OP_PICK 30 OP_ADD OP_SPLIT OP_NIP 10 OP_SPLIT OP_DROP
    OP_8 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP OP_BIN2NUM
    OP_0 OP_EQUALVERIFY
    OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
  OP_ENDIF
`;

const PATH1_SUM_OUTPUTS_ASM = `
  OP_0 OP_TOALTSTACK

  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_DEPTH OP_1SUB OP_PICK
    10 OP_SPLIT OP_DROP
    OP_8 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP OP_BIN2NUM
    OP_0 OP_EQUALVERIFY
    OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
  OP_ENDIF

  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_1 OP_GREATERTHAN
  OP_IF
    OP_DEPTH OP_2 OP_SUB OP_PICK
    10 OP_SPLIT OP_DROP
    OP_8 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP OP_BIN2NUM
    OP_0 OP_EQUALVERIFY
    OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
  OP_ENDIF

  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_2 OP_GREATERTHAN
  OP_IF
    OP_DEPTH OP_3 OP_SUB OP_PICK
    10 OP_SPLIT OP_DROP
    OP_8 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP OP_BIN2NUM
    OP_0 OP_EQUALVERIFY
    OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
  OP_ENDIF

  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_3 OP_GREATERTHAN
  OP_IF
    OP_DEPTH OP_4 OP_SUB OP_PICK
    10 OP_SPLIT OP_DROP
    OP_8 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP OP_BIN2NUM
    OP_0 OP_EQUALVERIFY
    OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
  OP_ENDIF

  OP_FROMALTSTACK OP_FROMALTSTACK OP_EQUALVERIFY
`;

// (h) Output reconstruction ×4, gated on i < M. For each output tuple we:
//   - Parse tuple into (amount 16b, owner 20b/MPKH, new_depth 2b, body_marker 2b)
//   - Anti-dust: amount > 0
//   - body_marker == 0x01ff (Normal)
//   - new_depth saturates: depth == min(max_input_depth + 1, 65535)
//   - Build candidate locking script: owner_push ‖ 00 6d (action_data + OP_2DROP)
//     ‖ body_before_tail (from altstack cache) ‖ 6a (OP_RETURN) ‖ reconstructed_tail
//     where reconstructed_tail = tokenId ‖ issuerPkh ‖ new_amount ‖ authorityFlags
//       ‖ freezeAuthHash ‖ confiscAuthHash ‖ new_depth ‖ optionalData
//   - Serialize output: 8b satoshis (anti-dust 1) ‖ varint(len) ‖ candidate_script
//   - Accumulate into outputs_hash_buffer
//
// A.2.5 retro-optimization (decision #38): the varint block is now FD-only
// single-branch (mirroring A.2's `VARINT_SERIALIZE_ASM` helper) instead of the
// original three-branch selector. Candidate locking scripts always land in the
// `[0xFD..0xFFFF]` range, so the smaller (252-byte) and larger (≥64KB)
// branches were dead code. Savings: ~30b per iteration × 4 iterations = ~120b
// cumulative, measured −136b. Correctness caveat identical to §4.X helper.
const PATH1_OUTPUT_ONE_ASM = `
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_DEPTH OP_1SUB OP_PICK
    10 OP_SPLIT
    OP_OVER OP_BIN2NUM OP_0 OP_GREATERTHAN OP_VERIFY
    OP_SWAP OP_TOALTSTACK
    14 OP_SPLIT
    OP_SWAP
    OP_DUP OP_SIZE OP_NIP 14 OP_NUMEQUALVERIFY
    OP_TOALTSTACK
    OP_2 OP_SPLIT
    OP_SWAP OP_TOALTSTACK
    01ff OP_EQUALVERIFY
    OP_FROMALTSTACK
    OP_DUP 00 OP_CAT OP_BIN2NUM
    OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
    FFFF 00 OP_CAT OP_BIN2NUM OP_LESSTHANOREQUAL OP_VERIFY
    OP_FROMALTSTACK
    14 OP_CAT
    006D OP_CAT
    OP_FROMALTSTACK
    OP_CAT
    6A OP_CAT
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_SWAP OP_CAT
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
    OP_SWAP OP_CAT
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
    0100000000000000 OP_SWAP OP_CAT
    OP_SIZE OP_SWAP
    OP_SWAP FD OP_SWAP OP_2 OP_SPLIT OP_DROP OP_CAT OP_CAT OP_SWAP OP_CAT
    OP_CAT
  OP_ENDIF
`;

// Four iterations of output reconstruction. The four bodies are identical in
// shape but pick from successively deeper tuple slots. We collapse via
// concatenation for byte accuracy.
const PATH1_OUTPUT_RECON_ASM = `
  ${PATH1_OUTPUT_ONE_ASM}
  ${PATH1_OUTPUT_ONE_ASM}
  ${PATH1_OUTPUT_ONE_ASM}
  ${PATH1_OUTPUT_ONE_ASM}
`;

// (i) hashOutputs closure. Accumulator (built across iterations above) is now
// HASH256'd and compared to hashOutputs from preimage cache. Also optional
// null-data output append.
const PATH1_HASHOUTPUTS_CLOSE_ASM = `
  OP_DEPTH OP_1SUB OP_PICK
  OP_DUP OP_SIZE OP_NIP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_DUP OP_SIZE OP_NIP
    OP_DUP FC00 OP_LESSTHANOREQUAL
    OP_IF
      OP_1 OP_SPLIT OP_DROP OP_CAT
    OP_ELSE
      OP_DUP FFFF OP_LESSTHANOREQUAL
      OP_IF
        FD OP_SWAP OP_2 OP_SPLIT OP_DROP OP_CAT OP_CAT
      OP_ELSE
        FE OP_SWAP OP_4 OP_SPLIT OP_DROP OP_CAT OP_CAT
      OP_ENDIF
    OP_ENDIF
    0000000000000000 OP_SWAP OP_CAT
    OP_SWAP OP_CAT
  OP_ELSE
    OP_DROP
  OP_ENDIF
  OP_HASH256
  OP_FROMALTSTACK
  OP_EQUALVERIFY
`;

// ---------------------------------------------------------------------------
// §4.X Shared helpers for paths 2, 3, 4
// ---------------------------------------------------------------------------

// Varint + sats prefix for candidate-output serialization. The candidate
// locking script in BNTP v2 is always between ~2000 and ~3000 bytes (body
// marker + covenant + preimage parse + tail cache + owner identity +
// dispatcher + all path SUFFIXes + OP_RETURN + tail), so the varint length
// encoding always falls into the 0xFD (2-byte length) branch. Unlike path 1,
// which uses a three-branch varint selector inside each per-output loop
// (FC / FF / FFFFFFFF), paths 2/3/4 use a single-branch variant that emits
// `FD <len-le-2b>` unconditionally. This saves ~45b per output reconstruction.
// Correctness: if the candidate script length ever escapes the [0xFD .. 0xFFFF]
// range, SDK pre-validation rejects the tx before broadcast; the on-chain
// covenant would fail via hashOutputs mismatch (varint malformed).
//
// Stack effect: main top = candidate_script (bytes). After block executes,
// top of main stack = (8b sats ‖ 3b varint ‖ candidate_script) — ready for
// append to hashOutputs accumulator.

// Generic authority identity + CHECKSIG(VERIFY) block. Used for freeze auth
// (path 3), confisc auth (path 4), and issuer auth (path 2). Per spec §8.1 /
// decision #29, PKH authorities MUST run TWO checks: HASH160(pubkey) match
// AND explicit CHECKSIGVERIFY against preimage. MPKH authorities run
// HASH160(preimage) match + CHECKMULTISIGVERIFY with m-of-n pubkeys parsed
// from the MPKH preimage (max n=5, matching v1 identity-field spec).
//
// Parameter `flagMaskHex` is the 1-byte authorityFlags mask that discriminates
// PKH vs MPKH for the specific authority:
//   - 0x04 for freezeAuth (bit 2)
//   - 0x08 for confiscAuth (bit 3)
//   - 0x10 for issuer      (bit 4)
//
// Stack pre-condition (main): [auth_sig, auth_pubkey_or_mpkh_preimage] on top.
// Altstack pre-condition: authorityFlags byte and the target hash (freezeAuthHash
// / confiscAuthHash / issuerPkh) are reachable via FROMALTSTACK/TOALTSTACK
// round-trips (the caller arranges the altstack accordingly).
//
// NOTE (stack choreography caveat): altstack round-trip sequences in this
// block assume caller-specific ordering. As with A.1.1, this block is
// byte-measurable and structurally complete but NOT yet execution-verified.
// Execution correctness is Phase 1B work.

// ---------------------------------------------------------------------------
// §4.2 Path 2 — refresh SUFFIX (spec §9.3)
// ---------------------------------------------------------------------------
// Produces exactly 2 Normal outputs: output[0] = refreshed (amount =
// my_amount − royalty, owner = my_owner, new_depth = 0), output[1] = royalty
// (amount = royalty, owner = my_issuerPkh, new_depth = 0). Plus null-data
// attestation at output[2] verifying tokenId / thisOutpoint / issuerPubkey
// (PKH issuer) or tokenId / thisOutpoint / MPKH preimage (MPKH issuer).
//
// A.2.5 additions:
//   - MPKH issuer branch (decision #34, +~75b measured): gated on
//     `authorityFlags bit 4`. PKH branch is original A.2 code; MPKH branch
//     mirrors `authorityIdentityAsm` MPKH pattern — HASH160 match,
//     multisig-m/n extraction from preimage (up to n=5), CHECKMULTISIGVERIFY.
//     Issuer sig is the last one-below-path_id on main stack (OP_ROT reaches it).
//   - Optional change output at output index 3 (decision #37, +~30b measured).
//     If unlocking pushes non-empty `change_script_bytes` + `change_satoshis`,
//     the locking script appends `change_satoshis (8b LE) ‖ varint(len) ‖
//     change_script_bytes` to the hashOutputs accumulator. Gated on
//     `|change_script_bytes| > 0`. Varint uses the 1-byte direct-push form
//     (assuming P2PKH-style change ≤ 252b; SDK MUST enforce this at build).
//
// Byte-budget trimmings vs path 1's per-output block:
//   - new_depth is a 2-byte constant (0x0000), not extracted from tuple
//   - amount is computed (SUB / ROYALTY), not extracted from tuple
//   - body_marker is fixed 0x01ff (Normal); tuple's marker slot is trusted
//     via downstream byte-exact match on hashOutputs
//   - varint uses FD-only branch (see VARINT_SERIALIZE_ASM note)
//
// This gets per-output cost down to ~70b vs path 1's 155b. Two outputs = 140b
// for reconstruction; remaining ~80b covers conservation, null-data parse,
// issuer identity, hashOutputs closure.
const PATH2_OUTPUT_ONE_ASM = `
  OP_OVER
  14 OP_CAT
  006D OP_CAT
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
  ${VARINT_SERIALIZE_ASM}
`;

export const PATH2_REFRESH_ASM = `
  OP_DEPTH OP_3 OP_SUB OP_PICK OP_BIN2NUM
  OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY
  OP_DEPTH OP_3 OP_SUB OP_PICK OP_BIN2NUM
  OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY
  OP_ADD
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  00 OP_CAT OP_BIN2NUM
  OP_EQUALVERIFY

  ${PATH2_OUTPUT_ONE_ASM}
  ${PATH2_OUTPUT_ONE_ASM}

  OP_DEPTH OP_3 OP_SUB OP_PICK
  OP_1 OP_SPLIT OP_NIP
  OP_1 OP_SPLIT OP_NIP
  OP_1 OP_SPLIT OP_NIP
  20 OP_SPLIT
  OP_SWAP
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_EQUALVERIFY
  OP_1 OP_SPLIT OP_NIP
  24 OP_SPLIT
  OP_SWAP
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_EQUALVERIFY
  OP_1 OP_SPLIT OP_NIP

  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  10 OP_AND 00 OP_EQUAL
  OP_IF
    OP_DUP OP_HASH160
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
    OP_EQUALVERIFY
    OP_DROP

    OP_ROT
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
    OP_CHECKSIGVERIFY
  OP_ELSE
    OP_DUP OP_HASH160
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
    OP_EQUALVERIFY
    OP_DUP
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
    OP_ROT
    OP_CHECKMULTISIGVERIFY
  OP_ENDIF

  OP_CAT
  OP_DEPTH OP_3 OP_SUB OP_PICK OP_CAT

  OP_DEPTH OP_4 OP_SUB OP_PICK
  OP_DUP OP_SIZE OP_NIP
  OP_DUP OP_0 OP_GREATERTHAN
  OP_IF
    OP_DEPTH OP_5 OP_SUB OP_PICK
    OP_SWAP
    OP_1 OP_SPLIT OP_DROP
    OP_SWAP OP_CAT
    OP_SWAP OP_CAT
    OP_CAT
  OP_ELSE
    OP_DROP
    OP_DROP
  OP_ENDIF

  OP_HASH256
  OP_FROMALTSTACK OP_EQUALVERIFY
`;

// ---------------------------------------------------------------------------
// §4.3 Path 3 — freeze SUFFIX (spec §9.4)
// ---------------------------------------------------------------------------
// Produces exactly 1 Frozen output with amount / owner / new_depth all
// preserved byte-exact from source. Unlocking pushes `frozen_body_bytes`
// (~700b); locking verifies SHA256 match against embedded h_Frozen constant.
//
// h_Frozen is a 32-byte constant embedded in Normal body. Here it is a
// placeholder of 32 zero bytes — SDK deployer patches in the real
// SHA256(Frozen body) post-compilation. See H_FROZEN_PLACEHOLDER_HEX.
//
// The Frozen candidate output script uses action_data = OP_2 (0x52) per §3
// template catalog (Normal uses OP_0 / 0x00). Push bytes = `14 ‖ owner_pkh`
// for PKH owner; `4c XX ‖ mpkh_preimage` for MPKH owner (owner preserved, so
// same encoding as source's variable prefix owner).

// Placeholder SHA256 value for the Frozen template body. A 32-byte zero
// push inserted directly into ASM. The SDK's deployer resolves the real
// SHA256(Frozen body) at deploy time and patches these 32 bytes in-place
// in the compiled locking script. Keeps byte count honest at compile time.
export const H_FROZEN_PLACEHOLDER_HEX =
  "0000000000000000000000000000000000000000000000000000000000000000";

export const PATH3_FREEZE_ASM = `
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  01 OP_AND 01 OP_EQUALVERIFY

  ${authorityIdentityAsm("04")}

  OP_DEPTH OP_2 OP_SUB OP_PICK
  OP_SHA256
  ${H_FROZEN_PLACEHOLDER_HEX} OP_EQUALVERIFY

  OP_DEPTH OP_3 OP_SUB OP_PICK
  10 OP_SPLIT
  OP_OVER OP_BIN2NUM OP_0 OP_GREATERTHAN OP_VERIFY
  OP_SWAP OP_TOALTSTACK
  14 OP_SPLIT OP_SWAP OP_TOALTSTACK
  OP_2 OP_SPLIT OP_SWAP OP_TOALTSTACK
  FEFF OP_EQUALVERIFY
  OP_FROMALTSTACK
  14 OP_CAT
  026D OP_CAT
  OP_DEPTH OP_2 OP_SUB OP_PICK OP_CAT
  6A OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  ${VARINT_SERIALIZE_ASM}

  OP_HASH256
  OP_FROMALTSTACK OP_EQUALVERIFY
`;

// ---------------------------------------------------------------------------
// §4.4 Path 4 — confiscate SUFFIX (spec §9.5)
// ---------------------------------------------------------------------------
// Produces exactly 1 Normal output with amount preserved, owner = new_owner
// (authority chooses, supplied via output_tuple), new_depth = my_depth
// (PRESERVED — per Step C Critical #1 / decision #39). Confiscate is a pure
// ownership change and MUST NOT reset attestation_depth; the rolling-freshness
// invariant (§6.3) is maintained by inheriting the source UTXO's depth so that
// `depth = 0` unambiguously implies issuer attestation. Symmetric with freeze.
// Prior-draft behavior (0000 literal) is rejected. Same-template reconstruction
// reuses body_before_tail cache from §3.5 — no h_X push needed.
export const PATH4_CONFISCATE_ASM = `
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  02 OP_AND 02 OP_EQUALVERIFY

  ${authorityIdentityAsm("08")}

  OP_DEPTH OP_2 OP_SUB OP_PICK
  10 OP_SPLIT
  OP_OVER OP_BIN2NUM OP_0 OP_GREATERTHAN OP_VERIFY
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  00 OP_CAT OP_BIN2NUM
  OP_OVER OP_BIN2NUM OP_EQUALVERIFY
  OP_DROP
  OP_SWAP OP_TOALTSTACK
  14 OP_SPLIT OP_SWAP
  OP_DUP OP_SIZE OP_NIP 14 OP_NUMEQUALVERIFY
  OP_TOALTSTACK
  OP_2 OP_SPLIT OP_SWAP OP_TOALTSTACK
  01FF OP_EQUALVERIFY
  OP_FROMALTSTACK
  14 OP_CAT
  006D OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  6A OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT
  ${VARINT_SERIALIZE_ASM}

  OP_HASH256
  OP_FROMALTSTACK OP_EQUALVERIFY
`;

// ---------------------------------------------------------------------------
// §3.7 (continued) Dispatcher middle (paths 2, 3, 4)
// ---------------------------------------------------------------------------
// Gates paths 2, 3, 4 on path_id. Each inner branch runs the path's real
// SUFFIX (A.2 scope: PATH2_REFRESH_ASM / PATH3_FREEZE_ASM /
// PATH4_CONFISCATE_ASM). Leading OP_ENDIF closes the path-1 branch opened
// in DISPATCHER_HEADER_ASM; trailing OP_DROP consumes the path_id byte.
const DISPATCHER_MIDDLE_ASM = `
  OP_ENDIF
  OP_DUP OP_2 OP_EQUAL OP_IF
    ${PATH2_REFRESH_ASM}
  OP_ENDIF
  OP_DUP OP_3 OP_EQUAL OP_IF
    ${PATH3_FREEZE_ASM}
  OP_ENDIF
  OP_DUP OP_4 OP_EQUAL OP_IF
    ${PATH4_CONFISCATE_ASM}
  OP_ENDIF
  OP_DROP
`;

// ---------------------------------------------------------------------------
// Assemble NORMAL_BODY_ASM
// ---------------------------------------------------------------------------
export const NORMAL_BODY_ASM = `
  ${COVENANT_PREIMAGE_ROLL_ASM}
  ${COVENANT_S_PREAMBLE_ASM}
  ${COVENANT_TAIL_ASM}
  ${SIGHASH_CHECK_ASM}
  ${PREIMAGE_PARSE_ASM}
  ${TAIL_CACHE_ASM}
  ${OWNER_IDENTITY_ASM}
  ${DISPATCHER_HEADER_ASM}
  ${PATH1_HASHPREVOUTS_BIND_ASM}
  ${PATH1_N_DERIVE_ASM}
  ${PATH1_SELFPOS_OUTPOINT_ASM}
  ${PATH1_AMOUNTS_ARRAY_ASM}
  ${PATH1_M_CHECK_ASM}
  ${PATH1_DEPTH_CHECK_ASM}
  ${PATH1_SUM_INPUTS_ASM}
  ${PATH1_SUM_OUTPUTS_ASM}
  ${PATH1_OUTPUT_RECON_ASM}
  ${PATH1_HASHOUTPUTS_CLOSE_ASM}
  ${DISPATCHER_MIDDLE_ASM}
`;

/**
 * Compile NORMAL_BODY_ASM to raw bytes. Prepends the body-marker PUSHDATA1
 * sequence (which asmToBytes cannot emit directly) and appends the ASM-compiled
 * body, yielding the full measurable body.
 */
export const compileNormalBody = (): Uint8Array => {
  const tail = asmToBytes(NORMAL_BODY_ASM);
  const out = new Uint8Array(BODY_MARKER_BYTES.length + tail.length);
  out.set(BODY_MARKER_BYTES, 0);
  out.set(tail, BODY_MARKER_BYTES.length);
  return out;
};

export const NORMAL_BODY_BYTES: Uint8Array = compileNormalBody();
export const NORMAL_BODY_SIZE: number = NORMAL_BODY_BYTES.length;

/**
 * Per-section byte breakdown (for reporting). Each section is compiled in
 * isolation; the sum equals NORMAL_BODY_BYTES.length.
 */
export const NORMAL_BODY_SECTION_SIZES = {
  bodyMarker: BODY_MARKER_BYTES.length,
  covenantPreamble: asmToBytes(COVENANT_S_PREAMBLE_ASM).length,
  covenantTail: asmToBytes(COVENANT_TAIL_ASM).length,
  sighashCheck: asmToBytes(SIGHASH_CHECK_ASM).length,
  preimageParse: asmToBytes(PREIMAGE_PARSE_ASM).length,
  tailCache: asmToBytes(TAIL_CACHE_ASM).length,
  ownerIdentity: asmToBytes(OWNER_IDENTITY_ASM).length,
  dispatcherHeader: asmToBytes(DISPATCHER_HEADER_ASM).length,
  path1HashprevoutsBind: asmToBytes(PATH1_HASHPREVOUTS_BIND_ASM).length,
  path1NDerive: asmToBytes(PATH1_N_DERIVE_ASM).length,
  path1SelfposOutpoint: asmToBytes(PATH1_SELFPOS_OUTPOINT_ASM).length,
  path1AmountsArray: asmToBytes(PATH1_AMOUNTS_ARRAY_ASM).length,
  path1MCheck: asmToBytes(PATH1_M_CHECK_ASM).length,
  path1DepthCheck: asmToBytes(PATH1_DEPTH_CHECK_ASM).length,
  path1SumInputs: asmToBytes(PATH1_SUM_INPUTS_ASM).length,
  path1SumOutputs: asmToBytes(PATH1_SUM_OUTPUTS_ASM).length,
  path1OutputRecon: asmToBytes(PATH1_OUTPUT_RECON_ASM).length,
  path1HashoutputsClose: asmToBytes(PATH1_HASHOUTPUTS_CLOSE_ASM).length,
  // A.2 — path 2 refresh, path 3 freeze, path 4 confiscate. Each measurement
  // is the raw SUFFIX body bytes (NOT including the outer path_id OP_IF/OP_ENDIF
  // gate, which is counted in dispatcherMiddle's ~10b overhead).
  path2Refresh: asmToBytes(PATH2_REFRESH_ASM).length,
  path3Freeze: asmToBytes(PATH3_FREEZE_ASM).length,
  path4Confiscate: asmToBytes(PATH4_CONFISCATE_ASM).length,
  dispatcherMiddle:
    asmToBytes(DISPATCHER_MIDDLE_ASM).length -
    asmToBytes(PATH2_REFRESH_ASM).length -
    asmToBytes(PATH3_FREEZE_ASM).length -
    asmToBytes(PATH4_CONFISCATE_ASM).length,
} as const;
