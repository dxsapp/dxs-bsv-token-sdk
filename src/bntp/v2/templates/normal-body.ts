import { asmToBytes } from "../../../script/build/asm-template-builder";
import { sha256 } from "../../../hashes";
import { toHex } from "../../../bytes";
import { FROZEN_BODY_BYTES } from "./frozen-body";
import {
  COVENANT_PREIMAGE_ROLL_ASM,
  COVENANT_S_PREAMBLE_ASM,
  COVENANT_TAIL_ASM,
  SIGHASH_CHECK_ASM,
  PREIMAGE_PARSE_ASM,
  prefixZoneAsm,
  OWNER_IDENTITY_CHECK_ASM,
  authIdentityCheckPkhAsm,
  OUTPUT_BYTES_WRAP_ASM,
  tailCacheAsm,
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
// §3.6 / §3.7 / §3.8 — Superseded by `prefixOwnerAndZoneAsm` (Wave D.1).
// ---------------------------------------------------------------------------
//
// The prior split of owner-identity (§3.6) and tail-cache (§3.5) blocks is
// replaced by the single `prefixOwnerAndZoneAsm(bodySize)` helper in
// `shared-prefix.ts`. It implements PREFIX Phases 5+6+7 per
// `docs/BNTP_V2_PREFIX_CONTRACT.md` and produces the canonical §2 system zone
// (14 fixed-depth slots on main, altstack empty). Historical code below
// (`OWNER_IDENTITY_ASM`) is removed; callers consume the zone via OP_PICK/
// OP_ROLL from fixed depths.
//
// Legacy placeholder left intentionally blank.
// ---------------------------------------------------------------------------
// (See §3.6/§3.7/§3.8 notice above.)

// ---------------------------------------------------------------------------
// §4.1 Path 1 — flex-transfer SUFFIX (Wave D.2a — pre-loop validation)
// ---------------------------------------------------------------------------
//
// D.2a scope: non-destructive predicate checks over the §2 zone (depths 0-13)
// and the unlocking witness (depths 14-21 for N=1). Pure PICK/VERIFY — no
// stack consumption, no altstack use, no ROLL. On any predicate failure the
// script aborts via OP_VERIFY; on success the stack's pre-existing items are
// unchanged, with `sP` (selfPos) and `N` added on top of the zone.
//
// At PATH1_ASM entry (per D.0 §2 zone contract):
//   depth 0:  path_id                         [ZONE]
//   depth 1:  hashPrevouts  (32b)             [ZONE]
//   depth 2:  thisOutpoint  (36b)             [ZONE]
//   depth 3:  hashOutputs   (32b)             [ZONE]
//   depth 4:  owner_pkh     (20b)             [ZONE]
//   depth 5:  body          (var)             [ZONE]
//   depth 6:  optionalData  (var)             [ZONE]
//   depth 7:  depth         (2b LE)           [ZONE]
//   depth 8:  confiscAuth   (20b)             [ZONE]
//   depth 9:  freezeAuth    (20b)             [ZONE]
//   depth 10: authFlags     (1b)              [ZONE]
//   depth 11: amount        (16b LE)          [ZONE]
//   depth 12: issuerPkh     (20b)             [ZONE]
//   depth 13: tokenId       (32b)             [ZONE]
//   depth 14: funding_outpoint  (0 or 36b)    [WITNESS]
//   depth 15: nullData          (var, may be 0b)
//   depth 16: max_input_depth   (2b LE)
//   depth 17: selfPos           (ScriptNum, 0b for value 0)
//   depth 18: all_input_outpoints  (N*36b)
//   depth 19: amounts_in_array     (N*16b)
//   depth 20..20+N-1: output_tuple_k (40b each: amount16‖owner20‖depth2‖marker2)
//   depth 20+N: M (ScriptNum, 1..N)
//
// D.2a leaves `sP` (selfPos, top) and `N` (below) on the stack above the zone.
// The dispatcher appends `OP_1` and then `OP_NIP` drops sP, leaving OP_1 on
// top (truthy sentinel). D.2b consumes sP and N for the sum-in/sum-out loops.
//
// Validated invariants:
//   P1. HashPrevouts binding: HASH256(all_input_outpoints ‖ funding_outpoint)
//       == zone.hashPrevouts. Binds this covenant to the full set of inputs.
//   P2. N derive: N = |all_input_outpoints| / 36 with |outpoints| % 36 == 0
//       and N ∈ [1..4]. Rejects malformed-length outpoints blob.
//   P3. Amounts length: |amounts_in_array| == N * 16. Array is N elements.
//   P4. selfPos range: selfPos ∈ [0, N). Guards negative / out-of-range.
//   P5. selfPos → outpoint: all_input_outpoints[selfPos*36..selfPos*36+36]
//       == zone.thisOutpoint. This input's outpoint lives at selfPos in the
//       array; else covenant is being replayed under a different input.
//   P6. my_amount: amounts_in_array[selfPos*16..selfPos*16+16] == zone.amount.
//       Witness commitment of my amount matches scriptCode tail byte-exactly.
//   P7. M range: M ∈ [1, N]. Must have at least 1 authority signature and at
//       most N (one per input).
//   P8. Depth ordering: zone.depth ≤ max_input_depth. This input's attested
//       depth is within the bound signed by the unlocker; per-output depth
//       verification (new_depth == max_input_depth + 1) is D.2c.

const PATH1_D2A_HASH_PREVOUTS_BIND = `
  12 OP_PICK
  OP_15 OP_PICK
  OP_CAT
  OP_HASH256
  OP_2 OP_PICK
  OP_EQUALVERIFY
`;

const PATH1_D2A_N_DERIVE_AND_AMOUNTS_LEN = `
  12 OP_PICK
  OP_SIZE OP_NIP
  OP_DUP 24 OP_MOD OP_0 OP_EQUALVERIFY
  24 OP_DIV
  OP_DUP OP_1 OP_5 OP_WITHIN OP_VERIFY
  14 OP_PICK
  OP_SIZE OP_NIP
  OP_1 OP_PICK OP_16 OP_MUL
  OP_EQUALVERIFY
`;

const PATH1_D2A_SELFPOS_CHECK = `
  12 OP_PICK
  OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
  OP_DUP OP_2 OP_PICK OP_LESSTHAN OP_VERIFY
  14 OP_PICK
  OP_1 OP_PICK
  24 OP_MUL
  OP_SPLIT OP_NIP
  24 OP_SPLIT OP_DROP
  OP_5 OP_PICK
  OP_EQUALVERIFY
`;

const PATH1_D2A_MY_AMOUNT_CHECK = `
  15 OP_PICK
  OP_1 OP_PICK
  OP_16 OP_MUL
  OP_SPLIT OP_NIP
  OP_16 OP_SPLIT OP_DROP
  OP_14 OP_PICK
  OP_EQUALVERIFY
`;

const PATH1_D2A_M_RANGE = `
  OP_DEPTH OP_1 OP_SUB OP_PICK
  OP_DUP OP_1 OP_GREATERTHANOREQUAL OP_VERIFY
  OP_2 OP_PICK OP_LESSTHANOREQUAL OP_VERIFY
`;

const PATH1_D2A_DEPTH_CHECK = `
  12 OP_PICK OP_BIN2NUM
  OP_10 OP_PICK OP_BIN2NUM
  OP_GREATERTHANOREQUAL OP_VERIFY
`;

// ---------------------------------------------------------------------------
// Wave D.2b — sum-in / sum-out / balance check
// ---------------------------------------------------------------------------
//
// Consumes `amounts_in_array` (witness depth 19 at D.2a exit — after our
// two pushes of sP and N, depth 21) and the N output tuples (witness depth
// 22 at D.2a exit), verifying Σ(amounts_in) == Σ(tuple.amount_field).
//
// Stack discipline:
//   - Before D.2b: [..., sP, N]  (top = sP; §2 zone + witness below)
//   - After D.2b:  [..., sP, N]  (identical to D.2a exit — sP/N preserved;
//     amounts and tuples consumed; balance asserted)
//
// The identical shape lets the dispatcher's trailing `OP_1 / OP_NIP` keep
// working: OP_1 pushes on top, OP_NIP drops sP, leaving OP_1 truthy.
//
// Implementation: sum-in unrolled ×4 over 16-byte amount slots via OP_SPLIT
// + OP_BIN2NUM + OP_ADD; guarded per-iter on residual `|amounts_rem| > 0`.
// Sum-out unrolled ×4 consuming topmost tuple each iter via
// `OP_DEPTH OP_2 OP_SUB OP_ROLL`; guarded per-iter on altstack counter > 0
// (initialized from a pick-copy of N). Post-loop: `OP_NUMEQUALVERIFY`.
//
// Max N is 4 (enforced in D.2a §P2 via `OP_WITHIN` against [1..5)); the
// unroll is exactly 4 iterations so shorter N is handled by the guard
// predicate branching to a cheap no-op ELSE arm.

// --- Sum-in loop (setup + 4 iters + drop) ---
//
// 15 OP_ROLL: pull amounts (at top-depth 21 for our stack state at D.2b
//             entry) to top. Depth 0x15=21 matches §2 zone(14)+sP+N+witness
//             layout where amounts_in_array sits at that slot.
// OP_0 OP_SWAP: push acc=0 then swap so iter invariant holds — amounts on
//             top, acc below. (D.2b shipped without OP_SWAP; first DUP/SIZE
//             then read size of acc=0 → IF predicate always false, iter no-op.
//             Fixed in D.2c.0.5.)
//
// Per iter: DUP/SIZE/NIP yields `|amounts_rem|`. If >0, OP_16 OP_SPLIT
// extracts the next 16-byte amount; OP_BIN2NUM decodes it as a scriptnum;
// OP_ROT + OP_ADD folds it into the acc; final OP_SWAP restores invariant
// (amounts_rem on top, acc below). If 0, ELSE is empty — guard naturally
// idempotent so N<4 inputs simply hit IF N times then ELSE (4-N) times.

const PATH1_D2B_SUM_IN_ITER = `
  OP_DUP OP_SIZE OP_NIP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_16 OP_SPLIT
    OP_SWAP OP_BIN2NUM
    OP_ROT OP_ADD
    OP_SWAP
  OP_ENDIF
`;

const PATH1_D2B_SUM_IN = `
  15 OP_ROLL
  OP_0 OP_SWAP
  ${PATH1_D2B_SUM_IN_ITER}
  ${PATH1_D2B_SUM_IN_ITER}
  ${PATH1_D2B_SUM_IN_ITER}
  ${PATH1_D2B_SUM_IN_ITER}
  OP_DROP
`;

// ---------------------------------------------------------------------------
// Wave D.2c.2 — unified per-tuple loop with full output reconstruction +
// hashOutputs closure. Builds on D.2c.1's conservation half by retaining
// tuple parts (amount, owner, depth) past the sanity checks and rebuilding
// each candidate output's full serialized bytes (sats ‖ varint ‖ scriptBytes)
// inside the loop. Bytes are CAT'd into an `acc_recon` accumulator stashed
// on the altstack (under the loop counter); closing pops the accumulator,
// HASH256s it, and EQUALVERIFYs against zone.hashOutputs (slot 3).
// ---------------------------------------------------------------------------
//
// D.2c sub-wave history:
//   - D.2c.1: sum-out + marker + depth-skip + closing NUMEQUALVERIFY.
//   - D.2c.2 (this block): retains D.2c.1's checks; adds reconstruction
//                          (new_tail, candidate_script, sats+varint wrap)
//                          and CAT to acc_recon; closing adds
//                          HASH256+EQUALVERIFY against zone.hashOutputs.
//   - D.2c.3: N-/M-out-of-range adversarial coverage, final size-floor
//             retighten (D.2c.2 bumps size ceiling temporarily — see
//             tests/bntp-v2-normal-template-size.test.ts).
//
// Per-iter byte budget is intentionally LOOSE — emphasis is on a working,
// readable, individually-verifiable assembly. Optimization passes (e.g.,
// shared output-reconstruction helper, FROMALT-shuffle minimization,
// fixed-point varint embedding) come AFTER the protocol is proven correct
// end-to-end across all 4 paths × 8 BNTP test vectors. See size-test
// "TODO: tighten in optimization wave" note.
//
// Stack invariants at D.2c.2 SETUP entry (= PATH1_D2B_SUM_IN exit):
//   d0:  sum_in
//   d1:  sP
//   d2:  N
//   d3:  path_id
//   d4..d16:  zone[1..13]    (hashPrev .. tokenId)
//   d17: funding_outpoint
//   d18: nullData
//   d19: max_input_depth
//   d20: selfPos
//   d21: all_input_outpoints
//   d22..d22+N-1: tuples (tuple_topmost at d22)
//   d22+N: M
//
// Setup pushes acc_recon (=empty bytes) and counter=N to alt (acc_recon
// deeper, counter on top), and sum_out_acc=0 to main top. After SETUP all
// items shift down by 1 (sum_in → d1, …, max_input → d20, tuple_topmost
// at d23).

// One-time setup: stash acc_recon (empty) and counter=N to alt; push
// sum_out_acc=0. Order of TOALTSTACKs determines alt LIFO: acc_recon
// pushed FIRST so it sits BELOW counter for next iter's FROMALT pulls.
const PATH1_D2C_SETUP = `
  OP_0 OP_TOALTSTACK
  OP_2 OP_PICK OP_TOALTSTACK
  OP_0
`;

// Per-iteration body (unrolled ×4). Stack at ITER entry (post-SETUP for
// iter 1, post-prev-iter otherwise):
//   d0:  sum_out_acc            (carrying)
//   d1:  sum_in
//   d2:  sP
//   d3:  N
//   d4..d17: zone (path_id at d4 .. tokenId at d17)
//   d18: funding_outpoint
//   d19: nullData
//   d20: max_input_depth
//   d21: selfPos
//   d22: all_input_outpoints
//   d23..: tuple_topmost (always at d23 — invariant across iters since
//          consuming a tuple shifts items BELOW (M, deeper tuples) up by 1
//          while items above d23 stay anchored).
//   alt: [counter (top), acc_recon].
//
// IF body sequence (counter > 0):
//   (1) decrement counter, stash on alt.
//   (2) ROLL tuple to top, split into amount_16 ‖ owner_20 ‖ depth_2 ‖
//       marker_2. Update sum_out_acc with amount_num; verify marker;
//       verify depth == max_input + 1. Tuple parts (amount_16, owner_20,
//       depth_2) end up stashed on alt for reconstruction.
//   (3) Pull tuple parts back to main; build new_tail by CATting zone
//       fields (PICK) and tuple parts in order: tokenId ‖ issuerPkh ‖
//       amount ‖ authFlags ‖ freezeAuth ‖ confiscAuth ‖ depth ‖
//       optionalData.
//   (4) Wrap to candidate_script: prepend 0x14 ‖ owner_20 ‖ 0x00 0x6d ‖
//       body ‖ 0x6a to new_tail.
//   (5) Compute scriptLen via OP_DUP OP_SIZE OP_NIP, encode as 2-byte LE
//       via OP_2 OP_NUM2BIN, build varint = 0xFD ‖ scriptLen_le_2b.
//   (6) Prepend sats_8b (constant `0100000000000000` = 1 sat dust) and
//       varint to candidate_script → output_bytes.
//   (7) Pull acc_recon and counter-1 from alt, CAT output_bytes onto
//       acc_recon, push both back (acc_recon deeper, counter-1 on top).
//
// ELSE body (counter == 0): TOALTSTACK counter back unchanged; iter is
// a no-op (acc_recon and main untouched).
//
// Sats are hardcoded to 1 satoshi (matching test scenarios). Variable-sats
// support requires extending the unlocking witness with per-tuple sats
// fields — separate wave.

const PATH1_D2C2_ITER = `
  OP_FROMALTSTACK
  OP_DUP OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB OP_TOALTSTACK

    17 OP_ROLL
    OP_16 OP_SPLIT
    OP_SWAP
    OP_DUP OP_TOALTSTACK
    OP_BIN2NUM
    OP_2 OP_ROLL OP_ADD
    OP_SWAP
    14 OP_SPLIT
    OP_SWAP
    OP_TOALTSTACK
    OP_2 OP_SPLIT
    01FF OP_EQUALVERIFY
    OP_DUP OP_TOALTSTACK
    OP_BIN2NUM
    15 OP_PICK OP_BIN2NUM OP_1ADD OP_NUMEQUALVERIFY

    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_FROMALTSTACK

    14 OP_PICK
    14 OP_PICK
    OP_CAT
    OP_SWAP OP_CAT
    11 OP_PICK OP_CAT
    OP_16 OP_PICK OP_CAT
    OP_15 OP_PICK OP_CAT
    OP_2 OP_ROLL OP_CAT
    OP_12 OP_PICK OP_CAT

    6A OP_SWAP OP_CAT
    OP_11 OP_PICK OP_SWAP OP_CAT
    006D OP_SWAP OP_CAT
    OP_CAT
    14 OP_SWAP OP_CAT

    ${OUTPUT_BYTES_WRAP_ASM}

    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_2 OP_ROLL
    OP_CAT
    OP_TOALTSTACK
    OP_TOALTSTACK
  OP_ELSE
    OP_TOALTSTACK
  OP_ENDIF
`;

// Closing: pop final counter (=0 after all iters) and discard; pop
// acc_recon and HASH256 it; PICK zone.hashOutputs (slot 3, at d8 after
// FROMALT); EQUALVERIFY hashes; NUMEQUALVERIFY balance.
//
// Stack at closing entry (post 4 unrolled iters):
//   d0: sum_out_acc, d1: sum_in, d2: sP, d3: N, d4..d17: zone, d18..d22:
//   witness (max_input at d20, all_inputs at d22), d23: M.
//   alt: [counter=0 (top), acc_recon].
//
// After OP_FROMALTSTACK OP_DROP: counter consumed.
// After OP_FROMALTSTACK: acc_recon on main top; zone shifts +1.
// After OP_HASH256: hashed acc_recon on top (size unchanged).
// After OP_8 OP_PICK: copy of zone[3]=hashOutputs (currently at d8) to
//                     top.
// After OP_EQUALVERIFY: -2.
// After OP_NUMEQUALVERIFY: -2 (pops sum_out_acc and sum_in).
// Final: top = sP, dispatcher's `OP_1 OP_NIP` works as before.
const PATH1_D2C2_CLOSING = `
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK
  OP_HASH256
  OP_8 OP_PICK OP_EQUALVERIFY
  OP_NUMEQUALVERIFY
`;

// PATH1 SUFFIX entry: owner-identity check (D.3 prep refactor — owner-sig
// extracted from PREFIX into per-path SUFFIX). See `OWNER_IDENTITY_CHECK_ASM`
// in shared-prefix.ts for the full pre/post-state contract.
//
// After this 10b helper consumes pubkey + sig (left at d14, d15 by
// `prefixZoneAsm`), the stack layout matches the legacy
// `prefixOwnerAndZoneAsm` post-state — D.2a/D.2b/D.2c sub-blocks below
// reference unchanged depths.
const PATH1_ASM = `
  ${OWNER_IDENTITY_CHECK_ASM}
  ${PATH1_D2A_HASH_PREVOUTS_BIND}
  ${PATH1_D2A_N_DERIVE_AND_AMOUNTS_LEN}
  ${PATH1_D2A_SELFPOS_CHECK}
  ${PATH1_D2A_MY_AMOUNT_CHECK}
  ${PATH1_D2A_M_RANGE}
  ${PATH1_D2A_DEPTH_CHECK}
  ${PATH1_D2B_SUM_IN}
  ${PATH1_D2C_SETUP}
  ${PATH1_D2C2_ITER}
  ${PATH1_D2C2_ITER}
  ${PATH1_D2C2_ITER}
  ${PATH1_D2C2_ITER}
  ${PATH1_D2C2_CLOSING}
`;

// Legacy path-1 sub-blocks (A.2 altstack-centric design) — REMOVED in
// Wave D.1. D.2b shipped sum-in. D.2c.1 added per-tuple conservation
// + sanity. D.2c.2 (this commit) extends each iter with full output
// reconstruction and adds HASH256+EQUALVERIFY against zone.hashOutputs
// at closing. D.2c.3 will add N-/M-out-of-range adversarial coverage
// and re-tighten the size floor.
//
// For historical reference see commit 18490e2^ (pre-D.0) or
// `docs/BNTP_V2_NORMAL_TEMPLATE_A3_REPORT.md`.

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
// §4.3 Path 3 — freeze SUFFIX (spec §9.4) — Wave D.3.2 rewrite
// ---------------------------------------------------------------------------
// Produces exactly 1 Frozen output with amount / owner / new_depth + every
// tail field preserved byte-exact from the source Normal UTXO. Unlocking
// pushes `frozen_body_bytes` (~1282b); locking verifies SHA256 match
// against the embedded `h_Frozen` constant before splicing the pushed
// bytes into the candidate Frozen output's script.
//
// Rewrite scope (D.3.2):
//   - Adapted to D.1 main-stack zone contract (was legacy A.2 altstack-
//     centric). Same posture as D.3.1 PATH4: PKH-only auth, loose-bytes
//     posture, no shared output-bytes helper.
//   - Bug fix vs Phase 1A version: action_data byte for the candidate
//     Frozen variable-prefix is `0x52` (= OP_2 opcode) per spec §3 template
//     catalog (Frozen template `action_data = OP_2`). The legacy ASM
//     wrote `026D` (data byte 0x02 + OP_2DROP byte 0x6d) which would have
//     made the deployed Frozen UTXO unspendable — `0x02` in script is the
//     "push 2 bytes" opcode, consuming subsequent bytes as data. The fix
//     emits `526D` (= OP_2 opcode + OP_2DROP).
//   - h_Frozen is computed at module load from the ACTUAL FROZEN_BODY_BYTES
//     produced by `frozen-body.ts`. Pre-D.3.2 this was a 32-byte zero
//     placeholder slated for SDK-deployer patching; with the D.3 series
//     building toward end-to-end execution, embedding the real value is
//     necessary for path-3 testing AND simplifies the deployment story
//     (no out-of-band patching). FROZEN_BODY_BYTES itself is still on the
//     legacy A.2 zone (frozen-body.ts hasn't been migrated yet) — the
//     embedded hash will need refreshing once D.5 / Phase 1B closeout
//     migrates Frozen to D.1 zone, but the BYTE-WIDTH of the hash (32b)
//     is invariant so the Normal body's compile-time fixed-point holds.
//
// Pre-state (PATH3_FREEZE_ASM entry):
//   d0:  path_id (=3)
//   d1:  hashPrev
//   d2:  thisOut
//   d3:  hashOutputs
//   d4:  owner_pkh        (preserved across freeze)
//   d5:  body
//   d6:  optionalData
//   d7:  depth (zone)     "my_depth" — preserved
//   d8:  confiscAuth
//   d9:  freezeAuth
//   d10: authFlags
//   d11: amount (zone)    "my_amount" — preserved
//   d12: issuerPkh
//   d13: tokenId
//   d14: pubkey (freezeAuth's; consumed by `authIdentityCheckPkhAsm(9)`)
//   d15: sig (freezeAuth's; consumed by `authIdentityCheckPkhAsm(9)`)
//   d16: funding_outpoint (may be empty)
//   d17: nullData (may be empty per spec §9.4)
//   d18: output_tuple (40b: amount16 ‖ owner20 ‖ depth2 ‖ marker2=FEFF)
//   d19: frozen_body_bytes (~1282b)
//
// Verification rules (per spec §9.4):
//   1. authFlags bit 0 set (freezable enabled): `authFlags & 0x01 == 0x01`
//   2. freezeAuth signature valid (PKH-only for now): HASH160(pubkey) ==
//      zone.freezeAuth + CHECKSIGVERIFY (`authIdentityCheckPkhAsm(9)`)
//   3. SHA256(pushed_frozen_body_bytes) == embedded h_Frozen
//   4. Output[0]:
//      - amount = zone.amount (preserved)
//      - owner_pkh = zone.owner_pkh (preserved — freeze does NOT change
//        ownership)
//      - new_depth = zone.depth (preserved per spec rule 6)
//      - marker = 0xFEFF (Frozen output marker)
//   5. HASH256(reconstructed_output_bytes) == zone.hashOutputs
//
// Reconstructed candidate Frozen output script:
//   0x14 ‖ owner_pkh ‖ 0x52 0x6D ‖ pushed_frozen_body ‖ 0x6A ‖ tail
// Tail = same 8 fields as Normal tail (preserved from zone): tokenId,
// issuerPkh, amount, authFlags, freezeAuth, confiscAuth, depth, optionalData.
//
// Sats hardcoded to 1 satoshi (BNTP v2 dust convention).

// h_Frozen = SHA256 of the actual Frozen template body bytes. Computed at
// module load. Embedded as a 32-byte literal in PATH3_FREEZE_ASM.
const H_FROZEN_HEX = toHex(sha256(FROZEN_BODY_BYTES));

// Back-compat: the placeholder constant remains exported (former SDK-
// deployer hook). Now equals the real h_Frozen hex; the "placeholder"
// naming is retained to avoid breaking imports until the next API revision.
export const H_FROZEN_PLACEHOLDER_HEX = H_FROZEN_HEX;

export const PATH3_FREEZE_ASM = `
  OP_10 OP_PICK
  01 OP_AND
  01 OP_EQUALVERIFY

  ${authIdentityCheckPkhAsm(9)}

  11 OP_PICK
  OP_SHA256
  ${H_FROZEN_HEX} OP_EQUALVERIFY

  OP_16 OP_ROLL
  OP_16 OP_SPLIT
  OP_SWAP

  OP_13 OP_PICK
  OP_EQUALVERIFY

  14 OP_SPLIT
  OP_SWAP

  OP_6 OP_PICK
  OP_EQUALVERIFY

  OP_2 OP_SPLIT
  FEFF OP_EQUALVERIFY

  OP_8 OP_PICK
  OP_EQUALVERIFY

  OP_13 OP_PICK
  OP_13 OP_PICK
  OP_CAT
  OP_12 OP_PICK OP_CAT
  OP_11 OP_PICK OP_CAT
  OP_10 OP_PICK OP_CAT
  OP_9 OP_PICK OP_CAT
  OP_8 OP_PICK OP_CAT
  OP_7 OP_PICK OP_CAT

  6A OP_SWAP OP_CAT
  11 OP_PICK OP_SWAP OP_CAT
  526D OP_SWAP OP_CAT
  OP_5 OP_PICK OP_SWAP OP_CAT
  14 OP_SWAP OP_CAT

  ${OUTPUT_BYTES_WRAP_ASM}

  OP_HASH256
  OP_4 OP_PICK OP_EQUALVERIFY
`;

// ---------------------------------------------------------------------------
// §4.4 Path 4 — confiscate SUFFIX (spec §9.5) — Wave D.3.1 rewrite
// ---------------------------------------------------------------------------
// Produces exactly 1 Normal output with amount preserved, owner = new_owner
// (authority chooses, supplied via output_tuple), new_depth = my_depth
// (PRESERVED — per Step C Critical #1 / decision #39). Confiscate is a pure
// ownership change and MUST NOT reset attestation_depth.
//
// Rewrite scope (D.3.1):
//   - Adapted to D.1 main-stack zone contract (was legacy A.2 altstack-
//     centric — full rewrite from scratch).
//   - Pre/post-state matches the dispatcher contract: path_id (=4) on top
//     at entry, path_id on top at exit (dispatcher's `OP_1 OP_NIP` handles
//     the rest).
//   - PKH-only confiscAuth; MPKH branch deferred to a follow-up wave.
//   - Loose-bytes posture (mirrors D.2c.2 inline reconstruction); no shared
//     output-bytes helper yet — optimization wave will extract it.
//
// Pre-state (PATH4_CONFISCATE_ASM entry):
//   d0:  path_id (=4)
//   d1:  hashPrev
//   d2:  thisOut
//   d3:  hashOutputs
//   d4:  owner_pkh        (existing owner being confiscated FROM —
//                          unused in path 4 logic but kept in zone)
//   d5:  body
//   d6:  optionalData
//   d7:  depth (zone) — "my_depth", preserved on confiscation
//   d8:  confiscAuth
//   d9:  freezeAuth
//   d10: authFlags
//   d11: amount (zone) — "my_amount", preserved on confiscation
//   d12: issuerPkh
//   d13: tokenId
//   d14: pubkey (confiscAuth's; consumed by `authIdentityCheckPkhAsm(8)`)
//   d15: sig (confiscAuth's; consumed by `authIdentityCheckPkhAsm(8)`)
//   d16: funding_outpoint (may be empty)
//   d17: output_tuple (40b: amount16 ‖ newOwner20 ‖ depth2 ‖ marker2)
//
// Verification rules (per spec §9.5):
//   1. authFlags bit 1 set (confiscatable enabled): `authFlags & 0x02 == 0x02`
//   2. confiscAuth signature valid: HASH160(pubkey) == zone.confiscAuth +
//      CHECKSIGVERIFY (PKH-only for now)
//   3. Output[0]:
//      - amount = zone.amount (preserved)
//      - new_depth = zone.depth (preserved per Step C decision #39)
//      - marker = 0x01FF (Normal output marker)
//      - owner = new_owner (from tuple; no validation, used in reconstruction)
//      - all other tail fields preserved from zone
//   4. HASH256(reconstructed_output_bytes) == zone.hashOutputs
//
// Post-state: path_id on top, zone-13 below, original layout below path_id.
// Dispatcher's `OP_1 OP_NIP` then drops path_id leaving truthy sentinel.
//
// Sats are hardcoded to 1 satoshi (matching test scenarios and the BNTP v2
// dust convention; see VARINT_SERIALIZE_ASM rationale).

// Step-by-step depth annotations:
//
// After PATH4 entry + step 1 (auth flag) + step 2 (auth identity check):
//   main = [path_id(d0), zone(d1-d13), funding(d14), tuple(d15)]
//
// After OP_15 OP_ROLL (tuple to top):
//   main = [tuple(d0), path_id(d1), zone(d2-d14), funding(d15)]
//
// After OP_16 OP_SPLIT OP_SWAP (parse amount):
//   main = [amount_16(d0), right_24(d1), path_id(d2), zone(d3-d15), funding(d16)]
//   amount(zone) at d13 (was d11 + 2 shift).
//
// After OP_13 OP_PICK OP_EQUALVERIFY (verify amount == zone.amount):
//   main = [right_24(d0), path_id(d1), zone(d2-d14), funding(d15)]
//
// After 14 OP_SPLIT OP_SWAP + size-check + OP_TOALTSTACK (extract owner_20
// to alt) + OP_2 OP_SPLIT 01FF OP_EQUALVERIFY (marker):
//   main = [depth_2(d0), path_id(d1), zone(d2-d14), funding(d15)]
//   alt = [owner_20]
//
// After OP_8 OP_PICK OP_EQUALVERIFY (verify depth == zone.depth):
//   main = [path_id(d0), zone(d1-d13), funding(d14)]
//   alt = [owner_20]
//
// new_tail build via 8-field PICK ladder: zone[i] at d_i throughout.
// candidate_script wrap via 5 prepends: body at zone[5] = d5 throughout.
// Final HASH256 + EQUALVERIFY against zone.hashOutputs at zone[3] = d4
// (after candidate has been built and consumed).
export const PATH4_CONFISCATE_ASM = `
  OP_10 OP_PICK
  02 OP_AND
  02 OP_EQUALVERIFY

  ${authIdentityCheckPkhAsm(8)}

  OP_15 OP_ROLL
  OP_16 OP_SPLIT
  OP_SWAP

  OP_13 OP_PICK
  OP_EQUALVERIFY

  14 OP_SPLIT
  OP_SWAP
  OP_TOALTSTACK

  OP_2 OP_SPLIT
  01FF OP_EQUALVERIFY

  OP_8 OP_PICK
  OP_EQUALVERIFY

  OP_13 OP_PICK
  OP_13 OP_PICK
  OP_CAT
  OP_12 OP_PICK OP_CAT
  OP_11 OP_PICK OP_CAT
  OP_10 OP_PICK OP_CAT
  OP_9 OP_PICK OP_CAT
  OP_8 OP_PICK OP_CAT
  OP_7 OP_PICK OP_CAT

  6A OP_SWAP OP_CAT
  OP_6 OP_PICK OP_SWAP OP_CAT
  006D OP_SWAP OP_CAT
  OP_FROMALTSTACK OP_SWAP OP_CAT
  14 OP_SWAP OP_CAT

  ${OUTPUT_BYTES_WRAP_ASM}

  OP_HASH256
  OP_4 OP_PICK OP_EQUALVERIFY
`;

// ---------------------------------------------------------------------------
// §3.7 Path dispatcher (Wave D.1 rewrite)
// ---------------------------------------------------------------------------
// Nested OP_IF/OP_ELSE chain with explicit trailing OP_1 sentinel per branch
// (decision D.0.4). Pre-condition: path_id on top of main stack (depth 0 in
// the §2 canonical zone). Post-condition: sentinel OP_1 on top, zone below
// path_id unchanged, path_id consumed by OP_NIP.
//
// path_id range check (∈ [1..4]) is up-front via OP_WITHIN; the final OP_ELSE
// therefore degenerates to "must be path 4" with no extra ELSE clause. Paths
// 2/3/4 bodies are legacy A.2 altstack-centric ASM and are DEAD code in D.1
// (test scenario uses path_id=1 only). D.3 rewrites them against the new
// main-stack zone.
const DISPATCHER_ASM = `
  OP_DUP OP_1 OP_5 OP_WITHIN OP_VERIFY
  OP_DUP OP_1 OP_EQUAL OP_IF
    ${PATH1_ASM}
    OP_1
  OP_ELSE OP_DUP OP_2 OP_EQUAL OP_IF
    ${PATH2_REFRESH_ASM}
    OP_1
  OP_ELSE OP_DUP OP_3 OP_EQUAL OP_IF
    ${PATH3_FREEZE_ASM}
    OP_1
  OP_ELSE
    ${PATH4_CONFISCATE_ASM}
    OP_1
  OP_ENDIF OP_ENDIF OP_ENDIF
  OP_NIP
`;

// ---------------------------------------------------------------------------
// Assemble NORMAL_BODY_ASM (Wave D.1, refactored D.3-prep)
// ---------------------------------------------------------------------------
// `prefixZoneAsm(bodySize)` consumes scriptCode from altstack and produces
// the canonical §2 main-stack zone. Owner-sig is NOT verified in PREFIX
// (D.3 prep) — pubkey + sig stay at d14, d15, consumed by per-path SUFFIX
// auth check (`OWNER_IDENTITY_CHECK_ASM` for paths 1/2 owner-authorized,
// `authorityIdentityAsm(...)` for paths 3/4 authority-authorized).
//
// `prefixZoneAsm`'s compiled byte count is invariant in `bodySize`
// (fixed-width 2-byte LE push), enabling a 1-pass fixed-point compile.
const buildNormalBodyAsm = (bodySize: number): string => `
  ${COVENANT_PREIMAGE_ROLL_ASM}
  ${COVENANT_S_PREAMBLE_ASM}
  ${COVENANT_TAIL_ASM}
  ${SIGHASH_CHECK_ASM}
  ${PREIMAGE_PARSE_ASM}
  ${prefixZoneAsm(bodySize)}
  ${DISPATCHER_ASM}
`;

// First pass: measure body size with placeholder.
const MEASUREMENT_BODY_BYTES = (() => {
  const tail = asmToBytes(buildNormalBodyAsm(0));
  return BODY_MARKER_BYTES.length + tail.length;
})();

export const NORMAL_BODY_ASM = buildNormalBodyAsm(MEASUREMENT_BODY_BYTES);

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

// Invariant check: the measurement pass must match the final pass, since
// `prefixZoneAsm`'s compiled size is invariant in the bodySize value.
// A violation indicates the ASM builder broke the fixed-width push assumption
// (e.g., a value above 0x7FFF encoding with different semantics).
if (NORMAL_BODY_SIZE !== MEASUREMENT_BODY_BYTES) {
  throw new Error(
    `BNTP v2 Normal body: prefixZoneAsm compile size changed with bodySize. ` +
      `Measured=${MEASUREMENT_BODY_BYTES}, final=${NORMAL_BODY_SIZE}.`,
  );
}

// Back-compat re-export. Callers outside this file still reference
// `TAIL_CACHE_ASM` from the old A.2 design. D.5 will migrate Contract +
// Frozen to the new PREFIX and remove this placeholder.
export const TAIL_CACHE_ASM = tailCacheAsm(NORMAL_BODY_SIZE + 24);

/**
 * Per-section byte breakdown (for reporting). Each section is compiled in
 * isolation; the sum equals NORMAL_BODY_BYTES.length.
 */
export const NORMAL_BODY_SECTION_SIZES = {
  bodyMarker: BODY_MARKER_BYTES.length,
  covenantPreimageRoll: asmToBytes(COVENANT_PREIMAGE_ROLL_ASM).length,
  covenantPreamble: asmToBytes(COVENANT_S_PREAMBLE_ASM).length,
  covenantTail: asmToBytes(COVENANT_TAIL_ASM).length,
  sighashCheck: asmToBytes(SIGHASH_CHECK_ASM).length,
  preimageParse: asmToBytes(PREIMAGE_PARSE_ASM).length,
  prefixZone: asmToBytes(prefixZoneAsm(NORMAL_BODY_SIZE)).length,
  path1: asmToBytes(PATH1_ASM).length,
  path2Refresh: asmToBytes(PATH2_REFRESH_ASM).length,
  path3Freeze: asmToBytes(PATH3_FREEZE_ASM).length,
  path4Confiscate: asmToBytes(PATH4_CONFISCATE_ASM).length,
  // Dispatcher overhead = total dispatcher compiled size minus the inlined
  // path bodies (OP_IF/OP_ELSE/OP_ENDIF gates + path_id DUP/EQUAL chain +
  // trailing OP_1 sentinels + OP_NIP).
  dispatcher:
    asmToBytes(DISPATCHER_ASM).length -
    asmToBytes(PATH1_ASM).length -
    asmToBytes(PATH2_REFRESH_ASM).length -
    asmToBytes(PATH3_FREEZE_ASM).length -
    asmToBytes(PATH4_CONFISCATE_ASM).length,
} as const;
