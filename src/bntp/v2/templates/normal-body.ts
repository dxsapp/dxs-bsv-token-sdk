import { asmToBytes } from "../../../script/build/asm-template-builder";

/**
 * BNTP v2 Normal template body ASM — Phase 1 A.1.1 scope.
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
 *
 * Out-of-scope (A.2): refresh (path 2), freeze (path 3), confiscate (path 4).
 * These are stubbed as `OP_FALSE OP_VERIFY` branches so the dispatcher structure
 * is complete and byte-measurable, but the branches themselves are placeholders.
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
const COVENANT_S_PREAMBLE_ASM = `
  OP_HASH256
  OP_16 OP_SPLIT OP_15 OP_SPLIT OP_SWAP OP_14 OP_SPLIT OP_SWAP OP_13 OP_SPLIT OP_SWAP
  OP_12 OP_SPLIT OP_SWAP OP_11 OP_SPLIT OP_SWAP OP_10 OP_SPLIT OP_SWAP OP_9 OP_SPLIT OP_SWAP
  OP_8 OP_SPLIT OP_SWAP OP_7 OP_SPLIT OP_SWAP OP_6 OP_SPLIT OP_SWAP OP_5 OP_SPLIT OP_SWAP
  OP_4 OP_SPLIT OP_SWAP OP_3 OP_SPLIT OP_SWAP OP_2 OP_SPLIT OP_SWAP OP_1 OP_SPLIT OP_SWAP
  OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
  OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
  OP_SWAP OP_15 OP_SPLIT OP_SWAP OP_14 OP_SPLIT OP_SWAP OP_13 OP_SPLIT OP_SWAP OP_12 OP_SPLIT OP_SWAP
  OP_11 OP_SPLIT OP_SWAP OP_10 OP_SPLIT OP_SWAP OP_9 OP_SPLIT OP_SWAP OP_8 OP_SPLIT OP_SWAP
  OP_7 OP_SPLIT OP_SWAP OP_6 OP_SPLIT OP_SWAP OP_5 OP_SPLIT OP_SWAP OP_4 OP_SPLIT OP_SWAP
  OP_3 OP_SPLIT OP_SWAP OP_2 OP_SPLIT OP_SWAP OP_1 OP_SPLIT OP_SWAP
  OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
  OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
  1F OP_SPLIT OP_TUCK OP_CAT 00 OP_CAT OP_BIN2NUM
  414136D08C5ED2BF3BA048AFE6DCAEBAFE 00 OP_15 OP_NUM2BIN OP_INVERT OP_CAT 00 OP_CAT
  OP_DUP OP_2 OP_DIV OP_ROT OP_3 OP_ROLL OP_DUP ff OP_EQUAL OP_SWAP 00 OP_EQUAL OP_BOOLOR
  OP_TUCK OP_NOTIF OP_1ADD OP_ELSE OP_2 OP_PICK OP_ADD OP_ENDIF
  OP_3 OP_ROLL OP_TUCK OP_MOD OP_DUP OP_4 OP_ROLL OP_GREATERTHAN OP_IF OP_SUB OP_ELSE OP_NIP OP_ENDIF
`;

// Tail of the covenant: assembles DER-encoded sig, appends sighash byte,
// branches pubkey by parity, runs CHECKSIGVERIFY. Verbatim from DSTAS donor.
const COVENANT_TAIL_ASM = `
  3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220
  OP_SWAP
  OP_16 OP_SPLIT OP_15 OP_SPLIT OP_SWAP OP_14 OP_SPLIT OP_SWAP OP_13 OP_SPLIT OP_SWAP
  OP_12 OP_SPLIT OP_SWAP OP_11 OP_SPLIT OP_SWAP OP_10 OP_SPLIT OP_SWAP OP_9 OP_SPLIT OP_SWAP
  OP_8 OP_SPLIT OP_SWAP OP_7 OP_SPLIT OP_SWAP OP_6 OP_SPLIT OP_SWAP OP_5 OP_SPLIT OP_SWAP
  OP_4 OP_SPLIT OP_SWAP OP_3 OP_SPLIT OP_SWAP OP_2 OP_SPLIT OP_SWAP OP_1 OP_SPLIT OP_SWAP
  OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
  OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
  OP_SWAP OP_15 OP_SPLIT OP_SWAP OP_14 OP_SPLIT OP_SWAP OP_13 OP_SPLIT OP_SWAP OP_12 OP_SPLIT OP_SWAP
  OP_11 OP_SPLIT OP_SWAP OP_10 OP_SPLIT OP_SWAP OP_9 OP_SPLIT OP_SWAP OP_8 OP_SPLIT OP_SWAP
  OP_7 OP_SPLIT OP_SWAP OP_6 OP_SPLIT OP_SWAP OP_5 OP_SPLIT OP_SWAP OP_4 OP_SPLIT OP_SWAP
  OP_3 OP_SPLIT OP_SWAP OP_2 OP_SPLIT OP_SWAP OP_1 OP_SPLIT OP_SWAP
  OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
  OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
  41 OP_CAT OP_SWAP
  OP_NOTIF 038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218
  OP_ELSE 023635954789a02e39fb7e54440b6f528d53efd65635ddad7f3c4085f97fdbdc48
  OP_ENDIF
  OP_CHECKSIGVERIFY
`;

// ---------------------------------------------------------------------------
// §3.3 Sighash-type check (preimage last 4 bytes == 0x41000000)
// ---------------------------------------------------------------------------
// Extract last 4 bytes of preimage and compare to 0x41000000 (SIGHASH_ALL |
// SIGHASH_FORKID, LE-encoded in preimage trailer). Per spec §9.2.
const SIGHASH_CHECK_ASM = `
  OP_DUP OP_SIZE OP_NIP OP_4 OP_SUB OP_SPLIT OP_NIP
  41000000 OP_EQUALVERIFY
`;

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
const PREIMAGE_PARSE_ASM = `
  OP_DUP
  OP_4 OP_SPLIT
  OP_SWAP OP_DROP
  20 OP_SPLIT
  OP_SWAP OP_TOALTSTACK
  20 OP_SPLIT
  OP_SWAP OP_TOALTSTACK
  24 OP_SPLIT
  OP_SWAP OP_TOALTSTACK
  OP_1 OP_SPLIT
  OP_OVER
  00 OP_CAT OP_BIN2NUM
  OP_DUP 4b OP_LESSTHANOREQUAL
  OP_IF
    OP_NIP
  OP_ELSE
    OP_DUP 4c OP_NUMEQUAL
    OP_IF
      OP_DROP OP_DROP
      OP_1 OP_SPLIT OP_SWAP 00 OP_CAT OP_BIN2NUM
    OP_ELSE
      OP_DUP 4d OP_NUMEQUAL
      OP_IF
        OP_DROP OP_DROP
        OP_2 OP_SPLIT OP_SWAP 0000 OP_CAT OP_BIN2NUM
      OP_ELSE
        4e OP_NUMEQUALVERIFY
        OP_DROP
        OP_4 OP_SPLIT OP_SWAP OP_BIN2NUM
      OP_ENDIF
    OP_ENDIF
  OP_ENDIF
  OP_DUP OP_TOALTSTACK
  OP_SPLIT
  OP_SWAP OP_TOALTSTACK
  OP_FROMALTSTACK OP_DROP
  OP_8 OP_SPLIT
  OP_SWAP OP_TOALTSTACK
  OP_4 OP_SPLIT
  OP_SWAP OP_TOALTSTACK
  20 OP_SPLIT
  OP_SWAP OP_TOALTSTACK
  OP_4 OP_SPLIT
  OP_SWAP OP_TOALTSTACK
  OP_DUP OP_SIZE OP_NIP OP_4 OP_NUMEQUALVERIFY
  41000000 OP_EQUALVERIFY
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK OP_TOALTSTACK
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK OP_TOALTSTACK
`;

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
const TAIL_CACHE_ASM = `
  OP_FROMALTSTACK
  OP_DUP OP_TOALTSTACK
  OP_SIZE OP_SWAP
  OP_1 OP_SPLIT
  00 OP_CAT OP_BIN2NUM
  OP_DUP 4b OP_LESSTHANOREQUAL
  OP_IF
    OP_NIP OP_SWAP
  OP_ELSE
    OP_DUP 4c OP_NUMEQUAL
    OP_IF
      OP_DROP OP_DROP
      OP_1 OP_SPLIT OP_SWAP 00 OP_CAT OP_BIN2NUM OP_SWAP
    OP_ELSE
      OP_DUP 4d OP_NUMEQUAL
      OP_IF
        OP_DROP OP_DROP
        OP_2 OP_SPLIT OP_SWAP 0000 OP_CAT OP_BIN2NUM OP_SWAP
      OP_ELSE
        OP_DROP OP_DROP
        OP_4 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP
      OP_ENDIF
    OP_ENDIF
  OP_ENDIF
  OP_SPLIT
  OP_DUP OP_TOALTSTACK
  OP_DROP
  OP_1 OP_SPLIT OP_NIP
  OP_1 OP_SPLIT OP_SWAP
  00 OP_EQUALVERIFY
  0000 0000 OP_CAT
  OP_SPLIT
  OP_SWAP OP_TOALTSTACK
  OP_DUP OP_SIZE OP_NIP
  OP_1 OP_SPLIT OP_NIP
  6A OP_EQUALVERIFY
  OP_DUP
  20 OP_SPLIT OP_SWAP OP_TOALTSTACK
  14 OP_SPLIT OP_SWAP OP_TOALTSTACK
  10 OP_SPLIT OP_SWAP OP_TOALTSTACK
  OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK
  14 OP_SPLIT OP_SWAP OP_TOALTSTACK
  14 OP_SPLIT OP_SWAP OP_TOALTSTACK
  OP_2 OP_SPLIT OP_SWAP OP_TOALTSTACK
  OP_TOALTSTACK
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK
  OP_DUP OP_TOALTSTACK
  OP_1 OP_SPLIT
  OP_DROP
  OP_1 OP_SPLIT
  00 OP_CAT OP_BIN2NUM
  OP_DUP 14 OP_NUMEQUAL
  OP_IF
    OP_DROP
    14 OP_SPLIT
    OP_SWAP OP_TOALTSTACK
  OP_ELSE
    OP_SPLIT
    OP_SWAP OP_TOALTSTACK
  OP_ENDIF
  00 OP_EQUALVERIFY
  OP_FROMALTSTACK OP_TOALTSTACK
`;

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
    OP_DUP OP_1 OP_5 OP_WITHIN OP_VERIFY
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

const DISPATCHER_MIDDLE_ASM = `
  OP_ENDIF
  OP_DUP OP_2 OP_EQUAL OP_IF
    OP_FALSE OP_VERIFY
  OP_ENDIF
  OP_DUP OP_3 OP_EQUAL OP_IF
    OP_FALSE OP_VERIFY
  OP_ENDIF
  OP_DUP OP_4 OP_EQUAL OP_IF
    OP_FALSE OP_VERIFY
  OP_ENDIF
  OP_DROP
`;

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
const PATH1_OUTPUT_ONE_ASM = `
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_DEPTH OP_1SUB OP_PICK
    10 OP_SPLIT
    OP_OVER OP_BIN2NUM OP_0 OP_GREATERTHAN OP_VERIFY
    OP_SWAP OP_TOALTSTACK
    14 OP_SPLIT
    OP_SWAP OP_TOALTSTACK
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
    OP_DUP FC00 OP_LESSTHANOREQUAL
    OP_IF
      OP_SWAP OP_1 OP_SPLIT OP_DROP OP_CAT OP_SWAP OP_CAT
    OP_ELSE
      OP_DUP FFFF OP_LESSTHANOREQUAL
      OP_IF
        OP_SWAP FD OP_CAT OP_SWAP OP_2 OP_SPLIT OP_DROP OP_CAT OP_SWAP OP_CAT
      OP_ELSE
        OP_SWAP FE OP_CAT OP_SWAP OP_4 OP_SPLIT OP_DROP OP_CAT OP_SWAP OP_CAT
      OP_ENDIF
    OP_ENDIF
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
// Assemble NORMAL_BODY_ASM
// ---------------------------------------------------------------------------
export const NORMAL_BODY_ASM = `
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
  dispatcherMiddle: asmToBytes(DISPATCHER_MIDDLE_ASM).length,
} as const;
