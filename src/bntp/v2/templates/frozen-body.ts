import { asmToBytes } from "../../../script/build/asm-template-builder";

import {
  COVENANT_S_PREAMBLE_ASM,
  COVENANT_TAIL_ASM,
  SIGHASH_CHECK_ASM,
  PREIMAGE_PARSE_ASM,
  TAIL_CACHE_ASM,
  VARINT_SERIALIZE_ASM,
  authorityIdentityAsm,
} from "./shared-prefix";
/**
 * BNTP v2 Frozen template body ASM — Phase 1 A.3 scope.
 *
 * The Frozen template is the compliance-hold counterpart to Normal. It
 * removes every owner path (flex-transfer, refresh) and retains only the
 * authority-gated paths:
 *
 *   - Path 3 — unfreeze (§9.7): freezeAuth signs a spend producing exactly
 *     1 Normal output that byte-exact preserves amount, owner, depth, and
 *     every tail field of the source Frozen UTXO. The TARGET is Normal, so
 *     the locking script must reconstruct a Normal candidate-output script.
 *     Per spec §5.5.1 / decision #27, the Frozen body embeds a 32-byte
 *     constant `h_Normal = SHA256(NORMAL_BODY_BYTES)`; the unlocking pushes
 *     the full Normal body bytes (~2620b). The locking script computes
 *     `SHA256(pushed) == h_Normal` (EQUALVERIFY) and then uses the pushed
 *     bytes directly when concatenating the candidate output script.
 *
 *   - Path 4 — confiscate-from-frozen (§9.8): confiscAuth signs a spend
 *     producing exactly 1 Normal output with owner = `new_owner` (from the
 *     pushed tuple), new_depth = my_depth (PRESERVED per Step C Critical #1
 *     / decision #39 — confiscate is a pure ownership change), and all
 *     other tail fields preserved. Same h_Normal hash-commit + pushed-body
 *     pattern as path 3; only the dispatcher leg and the owner source differ.
 *
 * Shared infrastructure copied verbatim (not imported) from
 * `normal-body.ts`: body marker wrapping convention, OP_PUSH_TX covenant
 * (`s`-preamble + DER-tail), sighash-type check, DSTAS-style preimage parse,
 * scriptCode tail cache, authority-identity (PKH + MPKH) helper, FD-only
 * output-serialization varint helper. The source of truth for those blocks
 * is the Normal template; they are duplicated here because the Normal
 * template does not currently export them as named symbols (and the A.3
 * scope brief forbids modifying `normal-body.ts`). This duplication is
 * flagged in `docs/BNTP_V2_FROZEN_TEMPLATE_REPORT.md` §4 as a Phase 1B
 * refactor candidate — export the helpers from `normal-body.ts` and swap
 * these inline copies for imports.
 *
 * IMPORTANT — like `normal-body.ts`, this script is written to be
 * byte-measurable and structurally complete. It has NOT been executed on a
 * node; several stack-management sequences are best-effort reproductions
 * of the pseudo-ASM's intent. Execution correctness is Phase 1B work.
 *
 * References:
 *   - docs/BNTP_V2_SPEC.md §3, §4.1-4.2, §5.2, §5.5.1, §8.1, §8.2, §9.1,
 *     §9.7, §9.8, §13.6, §13.7, §15 decisions #27, #29, #36, #39, #41, #43
 *   - src/bntp/v2/templates/normal-body.ts (donor for shared helpers)
 *   - docs/BNTP_V2_NORMAL_TEMPLATE_A3_REPORT.md (byte-budget reference)
 */

// ---------------------------------------------------------------------------
// §3.1 Body marker `0xfe 0xff` (Frozen)
// ---------------------------------------------------------------------------
// Same wrapping convention as Normal: OP_PUSHDATA1 0x02 0xFE 0xFF OP_DROP (5b).
// The asm-template-builder auto-selects minimal push encoding; there is no ASM
// escape to force PUSHDATA1, so the marker is emitted as a literal byte
// prefix in `compileFrozenBody()` below.
const BODY_MARKER_BYTES = new Uint8Array([0x4c, 0x02, 0xfe, 0xff, 0x75]);

// ---------------------------------------------------------------------------
// §5.5.1 h_Normal placeholder (32-byte zero hex)
// ---------------------------------------------------------------------------
// Frozen body embeds a 32-byte SHA256 constant `h_Normal = SHA256(Normal body
// bytes)` per decision #27. At compile time we emit 32 zero bytes as a
// placeholder; the SDK deploy tool (Phase 1B) patches in the real
// `SHA256(NORMAL_BODY_BYTES)` post-assembly. Keeps byte count honest and
// mirrors Normal's `H_FROZEN_PLACEHOLDER_HEX` pattern.
export const H_NORMAL_PLACEHOLDER_HEX =
  "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------
// §3.2 OP_PUSH_TX covenant (duplicated from normal-body.ts)
// ---------------------------------------------------------------------------
// Standard generator-point covenant ported from the DSTAS donor. See
// normal-body.ts §3.2 for detailed commentary. Byte-identical to Normal's
// `COVENANT_S_PREAMBLE_ASM` + `COVENANT_TAIL_ASM`.

// ---------------------------------------------------------------------------
// §3.3 Sighash-type check (duplicated from normal-body.ts)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// §3.4 Preimage parse (duplicated from normal-body.ts)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// §3.5 ScriptCode tail extraction + cache (duplicated from normal-body.ts)
// ---------------------------------------------------------------------------
// The tail layout for Frozen is byte-identical to Normal per §5.2 — same 111b
// fixed prefix with tokenId, issuerPkh, amount, authorityFlags, freezeAuthHash,
// confiscAuthHash, attestation_depth, optionalData. The Frozen body marker is
// different (0xfeff vs 0x01ff) but the tail cache walks the scriptCode tail
// *after* OP_RETURN, so the marker difference does not affect this block.

// ---------------------------------------------------------------------------
// §4.X Shared helpers (VARINT + authority identity) — duplicated from
// normal-body.ts. See §4.X of that file for commentary.
// ---------------------------------------------------------------------------

// Generic authority identity + CHECKSIG(VERIFY) block. PKH or MPKH per flag
// bit. Decision #29 requires HASH160 match + explicit CHECKSIGVERIFY for PKH.
// Decision #41 requires explicit `m ≥ 1` check on MPKH branch. See
// `normal-body.ts` §4.X for full commentary; block is byte-identical to the
// post-A.3 version there.
//
// `flagMaskHex` for Frozen template usage:
//   - "04" for freezeAuth (bit 2) on path 3 (unfreeze)
//   - "08" for confiscAuth (bit 3) on path 4 (confiscate-from-frozen)

// ---------------------------------------------------------------------------
// §3.7 Path dispatcher — Frozen only has paths 3 and 4
// ---------------------------------------------------------------------------
// Verify path_id ∈ {3, 4} then dispatch. No paths 1/2/5/6 on Frozen (spec
// §9.1 table: Frozen uses only 3 and 4). Path_id is on top of the main stack
// at this point (pushed in unlocking before preimage).
//
// Leading `OP_DUP OP_3 OP_EQUAL OP_IF` gates path 3; `OP_ELSE` + `OP_DUP OP_4
// OP_EQUALVERIFY` gates path 4 (EQUALVERIFY rejects anything that isn't 4,
// since 3 was already consumed by the IF branch). Trailing `OP_DROP` removes
// the path_id byte from the stack after whichever leg ran.
const DISPATCHER_HEADER_ASM = `
  OP_DUP OP_3 OP_EQUAL OP_IF
`;

// ---------------------------------------------------------------------------
// §4.1 Path 3 — unfreeze SUFFIX (spec §9.7)
// ---------------------------------------------------------------------------
// Produces exactly 1 Normal output with:
//   - amount = my_amount (preserved)
//   - owner = my_owner (preserved)
//   - new_depth = my_depth (preserved — §4.2 rule 6)
//   - All other tail fields preserved byte-exact
//
// Per §5.5.1, the unlocking pushes `NORMAL_BODY_BYTES` (~2620b); the locking
// script SHA256s the pushed bytes and compares against the embedded
// `h_Normal` placeholder. On match, the pushed bytes are used verbatim as
// the candidate output's body block.
//
// Candidate Normal output script layout:
//   owner_push(14 ‖ owner_pkh) ‖ action_data(0x00) ‖ OP_2DROP(0x6d)
//     ‖ pushed_normal_body ‖ OP_RETURN(0x6a) ‖ reconstructed_tail
//
// Reconstructed tail for unfreeze = source's full tail with amount,
// attestation_depth, optionalData all preserved (pulled from altstack cache).
//
// Stack pre-condition on entry to this suffix (main, top-down):
//   [pushed_normal_body (~2620b), normal_output_tuple (amount || owner_pkh ||
//    new_depth || body_marker=0x01ff) possibly present but not used in the
//    preserve-only variant, ..., preimage, ...]
// We follow the freeze-path pattern: tuple is used only to sanity-check
// body_marker; all substantive fields are pulled from the source's tail cache.
const PATH3_UNFREEZE_ASM = `
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  01 OP_AND 01 OP_EQUALVERIFY

  ${authorityIdentityAsm("04")}

  OP_DEPTH OP_2 OP_SUB OP_PICK
  OP_SHA256
  ${H_NORMAL_PLACEHOLDER_HEX} OP_EQUALVERIFY

  OP_DEPTH OP_3 OP_SUB OP_PICK
  10 OP_SPLIT
  OP_OVER OP_BIN2NUM OP_0 OP_GREATERTHAN OP_VERIFY
  OP_SWAP OP_TOALTSTACK
  14 OP_SPLIT OP_SWAP
  OP_DUP OP_SIZE OP_NIP 14 OP_NUMEQUALVERIFY
  OP_TOALTSTACK
  OP_2 OP_SPLIT OP_SWAP OP_TOALTSTACK
  01FF OP_EQUALVERIFY
  OP_FROMALTSTACK
  14 OP_CAT
  006D OP_CAT
  OP_DEPTH OP_2 OP_SUB OP_PICK OP_CAT
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
// §4.2 Path 4 — confiscate-from-frozen SUFFIX (spec §9.8)
// ---------------------------------------------------------------------------
// Produces exactly 1 Normal output with:
//   - amount = my_amount (preserved)
//   - owner = new_owner (from pushed output tuple — confiscAuth chooses)
//   - new_depth = my_depth (PRESERVED per Step C Critical #1 / decision #39)
//   - All other tail fields preserved byte-exact
//
// Same h_Normal hash-commit + pushed-body pattern as path 3. Differs from
// path 3 only in (a) the authority flag checked (0x02 confiscatable, not
// 0x01 freezable), (b) the auth helper flag mask ("08" not "04"), and
// (c) the owner source (from tuple, not from tail cache).
//
// NOTE ON SPEC TEXT DRIFT: §9.8 prose says `new_depth = 0 rather than
// depth-preserved`. That prose is stale relative to spec decision #39 (Step C
// Critical #1) which mandates depth preservation on ALL confiscate paths
// (Normal path 4 AND Frozen path 4). We honor decision #39 here — depth is
// preserved via altstack pull, same as Normal's PATH4_CONFISCATE_ASM. Flag
// raised in the report (§4 spec gaps — NOT self-fixed in source).
//
// Output tuple layout (same as Normal path 4):
//   [amount 16b][new_owner 20b PKH — MPKH deferred per A.3.2][new_depth 2b
//   — NOTE: this byte-matches-but-is-IGNORED; we preserve my_depth from
//   altstack instead, matching Normal's Step C fix][body_marker 2b = 0x01ff]
const PATH4_CONFISC_FROM_FROZEN_ASM = `
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  02 OP_AND 02 OP_EQUALVERIFY

  ${authorityIdentityAsm("08")}

  OP_DEPTH OP_2 OP_SUB OP_PICK
  OP_SHA256
  ${H_NORMAL_PLACEHOLDER_HEX} OP_EQUALVERIFY

  OP_DEPTH OP_3 OP_SUB OP_PICK
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
  OP_DEPTH OP_2 OP_SUB OP_PICK OP_CAT
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
// §3.7 (continued) Dispatcher closure
// ---------------------------------------------------------------------------
// Closes the path-3 branch opened in DISPATCHER_HEADER_ASM and gates path 4.
// Trailing OP_DROP consumes the path_id byte.
const DISPATCHER_MIDDLE_ASM = `
  OP_ELSE
    OP_DUP OP_4 OP_EQUALVERIFY
    ${PATH4_CONFISC_FROM_FROZEN_ASM}
  OP_ENDIF
  OP_DROP
`;

// Export the path SUFFIX ASMs for test introspection / section-byte sanity.
export const PATH3_UNFREEZE_ASM_EXPORT = PATH3_UNFREEZE_ASM;
export const PATH4_CONFISC_FROM_FROZEN_ASM_EXPORT =
  PATH4_CONFISC_FROM_FROZEN_ASM;

// ---------------------------------------------------------------------------
// Assemble FROZEN_BODY_ASM
// ---------------------------------------------------------------------------
export const FROZEN_BODY_ASM = `
  ${COVENANT_S_PREAMBLE_ASM}
  ${COVENANT_TAIL_ASM}
  ${SIGHASH_CHECK_ASM}
  ${PREIMAGE_PARSE_ASM}
  ${TAIL_CACHE_ASM}
  ${DISPATCHER_HEADER_ASM}
  ${PATH3_UNFREEZE_ASM}
  ${DISPATCHER_MIDDLE_ASM}
`;

/**
 * Compile FROZEN_BODY_ASM to raw bytes. Prepends the body-marker PUSHDATA1
 * sequence (which asmToBytes cannot emit directly) and appends the ASM-compiled
 * body, yielding the full measurable body.
 */
export const compileFrozenBody = (): Uint8Array => {
  const tail = asmToBytes(FROZEN_BODY_ASM);
  const out = new Uint8Array(BODY_MARKER_BYTES.length + tail.length);
  out.set(BODY_MARKER_BYTES, 0);
  out.set(tail, BODY_MARKER_BYTES.length);
  return out;
};

export const FROZEN_BODY_BYTES: Uint8Array = compileFrozenBody();
export const FROZEN_BODY_SIZE: number = FROZEN_BODY_BYTES.length;

/**
 * Per-section byte breakdown (for reporting). Each section is compiled in
 * isolation; the sum equals FROZEN_BODY_BYTES.length.
 */
export const FROZEN_BODY_SECTION_SIZES = {
  bodyMarker: BODY_MARKER_BYTES.length,
  covenantPreamble: asmToBytes(COVENANT_S_PREAMBLE_ASM).length,
  covenantTail: asmToBytes(COVENANT_TAIL_ASM).length,
  sighashCheck: asmToBytes(SIGHASH_CHECK_ASM).length,
  preimageParse: asmToBytes(PREIMAGE_PARSE_ASM).length,
  tailCache: asmToBytes(TAIL_CACHE_ASM).length,
  dispatcherHeader: asmToBytes(DISPATCHER_HEADER_ASM).length,
  path3Unfreeze: asmToBytes(PATH3_UNFREEZE_ASM).length,
  path4ConfiscFromFrozen: asmToBytes(PATH4_CONFISC_FROM_FROZEN_ASM).length,
  dispatcherMiddle:
    asmToBytes(DISPATCHER_MIDDLE_ASM).length -
    asmToBytes(PATH4_CONFISC_FROM_FROZEN_ASM).length,
} as const;
