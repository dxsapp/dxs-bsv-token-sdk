/**
 * BNTP v2 — shared PREFIX ASM blocks (Phase 1B decision #51).
 *
 * All 3 templates (Normal, Contract, Frozen) share the same PREFIX pillars:
 * OP_PUSH_TX covenant (preamble + tail), sighash-type check, preimage parse,
 * and the scriptCode tail cache (tail layout is identical across templates
 * per spec §5.2). Additionally, `VARINT_SERIALIZE_ASM` and `authorityIdentityAsm`
 * helpers are shared across Normal (paths 2/3/4) and Frozen (paths 3/4) and
 * Contract (path 6).
 *
 * BSV Script has no jumps/calls — each template MUST inline these bytes in
 * its compiled body. Source-level duplication (~736b × 3 templates =
 * ~2200b of repeated TypeScript) is eliminated by exporting these constants
 * from a single module and importing in each template.
 *
 * **Zero body-size impact:** byte-for-byte identical to prior inline definitions.
 * Phase 1A bodies remain: Normal 2620b, Contract 3971b, Frozen 1282b.
 *
 * References:
 *   - spec §3.2 OP_PUSH_TX covenant (pseudo-ASM companion doc)
 *   - spec §5.2 tail layout (shared across templates)
 *   - spec §7.2 null-data format
 *   - spec §8.1 PKH CHECKSIGVERIFY; §8.2 MPKH + decision #41 m≥1 check
 *   - spec §13.6 post-Genesis consensus requirement
 *   - spec §15 decisions #29, #33, #41, #51
 */

// ---------------------------------------------------------------------------
// §3.2 OP_PUSH_TX covenant preamble (ported from DSTAS donor)
// ---------------------------------------------------------------------------
// Pre-covenant stack fix (Phase 1B Wave C.1, resolves execution bug found
// by Wave C verification): per spec §9.1 common unlocking layout, the
// unlocking pushes `... preimage, path_id, sig, pubkey` with pubkey on top.
// The covenant's OP_HASH256 needs the preimage on top of the main stack.
// `OP_3 OP_ROLL` brings the preimage (at depth 3: under pubkey, sig,
// path_id) to the top. `OP_DUP` duplicates it so that OP_HASH256 consumes
// one copy while the other remains on stack for the downstream
// SIGHASH_CHECK_ASM and PREIMAGE_PARSE_ASM blocks, both of which also
// expect the preimage on top. Cost: +3b on every template's PREFIX.
//
// Without this shim, OP_HASH256 hashes the owner_pubkey byte string and
// the covenant builds a sig for the wrong hash domain — CHECKSIGVERIFY
// at the covenant tail rejects. See `docs/BNTP_V2_EXECUTION_VERIFICATION_REPORT.md`
// for the full trace from Wave C.
export const COVENANT_PREIMAGE_ROLL_ASM = `
  OP_3 OP_ROLL OP_DUP
`;

// Computes `s` component of the DER signature from HASH256(preimage) via
// modular arithmetic against N/2 constant. Preamble is byte-identical across
// all 3 templates (no template-specific logic). Leaves stack in state
// consumed by COVENANT_TAIL_ASM.
export const COVENANT_S_PREAMBLE_ASM = `
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
export const COVENANT_TAIL_ASM = `
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

// §3.3 sighash-type check: 0x41 (SIGHASH_ALL | SIGHASH_FORKID).
// Phase 1B Wave C.2 fix: removed spurious `OP_NIP` after `OP_SIZE`. The old
// sequence `OP_DUP OP_SIZE OP_NIP OP_4 OP_SUB OP_SPLIT OP_NIP` consumed the
// preimage's duplicate prematurely, making the subsequent OP_SPLIT consume
// the original preimage — leaving no preimage on top for downstream
// PREIMAGE_PARSE_ASM. Correct sequence preserves preimage:
//   [preimage] → DUP → [p, p] → SIZE → [p, p, size] → 4 SUB → [p, p, size-4]
//   → SPLIT → [p, left, right] → NIP → [p, right]
//   → push 41000000 → [p, right, lit] → EQUALVERIFY → [p]
// Net: preimage preserved on top for PREIMAGE_PARSE_ASM. Body size −1b.
export const SIGHASH_CHECK_ASM = `
  OP_DUP OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP
  41000000 OP_EQUALVERIFY
`;

// §3.4 preimage parse (Phase 1B Wave C.3 rewrite).
//
// Pre-condition: main stack top = preimage (preserved by SIGHASH_CHECK).
// Post-condition: main stack — preimage consumed; altstack (top-down):
//   [scriptCode, hashOutputs, thisOutpoint, hashPrevouts]
// i.e. scriptCode on top — ready for TAIL_CACHE_ASM to FROMALTSTACK directly.
//
// Fixes vs prior agent-generated version:
//   (1) Varint dispatcher was written as push-opcode dispatcher
//       (0x4b/0x4c/0x4d/0x4e). The preimage scriptCodeLen is a Bitcoin
//       VARINT (0x00-0xFC direct, 0xFD+2b LE, 0xFE+4b LE, 0xFF+8b LE). This
//       rewrite uses the correct varint encoding, assuming scriptCode ∈
//       [253, 65535] bytes (always 0xFD marker for current BNTP v2
//       templates: Normal 2622b, Contract 3973b, Frozen 1284b). A future
//       oversized template would require widening to 0xFE case.
//   (2) Prior version's end-cleanup dropped scriptCode + hashOutputs +
//       outpoint from altstack, leaving only hashPrevouts — contradicting
//       the block's own docstring. This rewrite preserves all 4 and
//       reorders so scriptCode ends on alt top for downstream TAIL_CACHE.
//
// BIP143 preimage layout (what this block walks):
//   4b  nVersion        → discarded
//   32b hashPrevouts    → cached
//   32b hashSequence    → discarded
//   36b outpoint        → cached
//   varint scriptCodeLen (0xFD + 2b LE for our templates)
//   N b scriptCode      → cached
//   8b  nValue          → discarded (via 12-byte combined skip with nSeq)
//   4b  nSequence       → discarded
//   32b hashOutputs     → cached
//   4b  nLocktime       → discarded
//   4b  sighashType     → verified == 0x41000000 (SIGHASH_ALL | FORKID)
export const PREIMAGE_PARSE_ASM = `
  OP_4 OP_SPLIT OP_NIP
  20 OP_SPLIT OP_SWAP OP_TOALTSTACK
  20 OP_SPLIT OP_NIP
  24 OP_SPLIT OP_SWAP OP_TOALTSTACK
  OP_1 OP_SPLIT OP_SWAP FD OP_EQUALVERIFY
  OP_2 OP_SPLIT OP_SWAP 0000 OP_CAT OP_BIN2NUM
  OP_SPLIT OP_SWAP OP_TOALTSTACK
  0c OP_SPLIT OP_NIP
  20 OP_SPLIT OP_SWAP OP_TOALTSTACK
  04 OP_SPLIT OP_NIP
  41000000 OP_EQUALVERIFY
  OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
`;

// §3.5 scriptCode tail extraction + cache (7 fields + optionalData + owner
// pkh to altstack). Tail layout is identical across Normal/Contract/Frozen
// per spec §5.2.
//
// -- Phase 1B Wave C.4 rewrite --------------------------------------------
//
// The prior TAIL_CACHE_ASM (flagged "NOT yet execution-verified" by its
// original author) had several stack-order bugs. The first trace failure
// was in the leading push-opcode dispatcher: after `OP_1 OP_SPLIT` the
// stack is `[size, firstByte(1b), rest]` with `rest` on top, and the
// subsequent `00 OP_CAT OP_BIN2NUM` was numifying `rest` (the 2000+ byte
// tail) instead of `firstByte`. All three `OP_NUMEQUAL` dispatches
// (0x4b/0x4c/0x4d) consequently failed, falling through to the `OP_4
// OP_SPLIT` default branch, which tried to split a 2-byte scriptnum at
// position 4 → "OP_SPLIT out of range".
//
// Additional stack-order errors in the subsequent field walk made the
// block not worth patching incrementally. It is replaced with a simple,
// position-based walk driven by a compile-time `prefixBeforeTailSize`
// constant (passed by the caller — `normal-body.ts`, etc.).
//
// -- Preconditions --------------------------------------------------------
// main stack top-down: [pubkey, sig, path_id, ...]
// altstack top-down : [scriptCode, hashOutputs, thisOutpoint, hashPrevouts]
//
// -- scriptCode layout (spec §5.2) ---------------------------------------
//   [0x14 <20b owner_pkh>]              // PKH owner direct push (21 bytes)
//   [0x00 0x6d]                         // OP_0 action_data + OP_2DROP
//   [body]                              // NORMAL/CONTRACT/FROZEN body bytes
//   [0x6a]                              // OP_RETURN
//   [32b tokenId][20b issuerPkh][16b amount][1b flags]
//   [20b freezeAuthHash][20b confiscAuthHash][2b depth]
//   [optionalData (variable, may be empty)]
//
// `prefixBeforeTailSize` = 21 + 2 + |body| + 1 = |body| + 24, counting
// owner push (21b), OP_0 OP_2DROP (2b), body, OP_RETURN (1b). Tail starts
// at this offset within scriptCode.
//
// -- Postconditions -------------------------------------------------------
// main stack top-down: [pubkey, sig, path_id, ...]  (unchanged)
// altstack top-down :
//   [scriptCode,                         // preserved for downstream path
//    optionalData, depth, confiscAuthHash, freezeAuthHash, authorityFlags,
//    amount, issuerPkh, tokenId,         // 7 tail fields + optionalData,
//                                        // top-most field = last-walked
//    owner_pkh,                          // from variable prefix
//    hashOutputs, thisOutpoint, hashPrevouts]  (from PREIMAGE_PARSE)
//
// -- Scope limitation ----------------------------------------------------
// PKH owner only. MPKH owner (first byte 0x4c for PUSHDATA1) is rejected
// via OP_EQUALVERIFY on the 0x14 marker — TODO for a follow-up wave.
//
// -- Byte cost -----------------------------------------------------------
// This rewrite is larger than the broken original (~120b vs ~75b) because
// it skips push-opcode dispatch in favor of a single compile-time offset.
// Byte budget is secondary to correctness per task scope; the saved ~45b
// of the original were ill-spent since the block never executed.
export const tailCacheAsm = (prefixBeforeTailSize: number): string => {
  // Encode prefixBeforeTailSize as a 2-byte little-endian push. Using a
  // fixed-width 2-byte hex token keeps the compiled ASM length invariant
  // in the value, which matters because `NORMAL_BODY_SIZE` in turn depends
  // on this block's size — a 2-pass fixed-point compile converges trivially.
  const lo = prefixBeforeTailSize & 0xff;
  const hi = (prefixBeforeTailSize >> 8) & 0xff;
  const hex = (
    lo.toString(16).padStart(2, "0") + hi.toString(16).padStart(2, "0")
  ).toLowerCase();
  return `
    OP_FROMALTSTACK
    OP_DUP

    ${hex}
    OP_BIN2NUM
    OP_SPLIT
    OP_SWAP

    OP_1 OP_SPLIT
    OP_SWAP
    00 OP_CAT OP_BIN2NUM
    14 OP_NUMEQUALVERIFY

    14 OP_SPLIT
    OP_SWAP
    OP_TOALTSTACK

    OP_2 OP_SPLIT
    OP_SWAP
    006D OP_EQUALVERIFY

    OP_SIZE OP_1SUB OP_SPLIT
    OP_NIP
    6A OP_EQUALVERIFY

    20 OP_SPLIT OP_SWAP OP_TOALTSTACK
    14 OP_SPLIT OP_SWAP OP_TOALTSTACK
    10 OP_SPLIT OP_SWAP OP_TOALTSTACK
    OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK
    14 OP_SPLIT OP_SWAP OP_TOALTSTACK
    14 OP_SPLIT OP_SWAP OP_TOALTSTACK
    OP_2 OP_SPLIT OP_SWAP OP_TOALTSTACK
    OP_TOALTSTACK

    OP_TOALTSTACK
  `;
};

// Back-compat placeholder export. The caller MUST import `tailCacheAsm`
// and pass the real prefixBeforeTailSize. This constant is kept only so
// `normal-body.ts`' re-export line continues to typecheck; it produces
// an invalid script if inlined directly (offset = 0).
export const TAIL_CACHE_ASM = tailCacheAsm(0);

// ===========================================================================
// §3.5 + §3.6 + §3.7 — PREFIX Phases 5 + 6 + 7 (Wave D.1 rewrite, canonical)
// ===========================================================================
//
// Supersedes `tailCacheAsm` + `OWNER_IDENTITY_ASM` (their altstack-centric
// design was the class of bug surfaced by Wave C.1-C.5). See
// `docs/BNTP_V2_PREFIX_CONTRACT.md` for the full spec.
//
// -- Precondition (PREFIX Phases 1-4 already executed) ---------------------
//
//   main top-down = [pubkey, sig, path_id, ...unlocking_rest]
//   alt  top-down = [scriptCode, hashOutputs, thisOutpoint, hashPrevouts]
//
// -- Postcondition (canonical system zone per spec §2) ---------------------
//
//   main top-down =
//     [path_id,
//      hashPrevouts, thisOutpoint, hashOutputs,
//      owner_pkh, body,
//      optionalData, depth, confiscAuth, freezeAuth, authFlags,
//      amount, issuerPkh, tokenId,
//      ...unlocking_rest]
//   alt = []
//
// -- Algorithm --------------------------------------------------------------
//
// Phase 5: pull scriptCode from alt, split off owner prefix
//          (`0x14 ‖ owner_pkh(20) ‖ 0x00 0x6D`), verify marker, extract
//          owner_pkh, HASH160(pubkey)==owner_pkh, CHECKSIGVERIFY.
//          Stashes owner_pkh and remaining scriptCode to alt.
//
// Phase 6: pull scriptCode tail (past action_data), extract body using
//          compile-time `bodySize`, strip OP_RETURN marker, natural
//          OP_SPLIT walk of tail → 8 tail-derived values on main.
//
// Phase 7: drain alt (body, owner_pkh, hashOutputs, thisOutpoint,
//          hashPrevouts onto main), `OP_13 OP_ROLL` brings path_id to top.
//
// -- Design invariants ------------------------------------------------------
//
// * `bodySize` is encoded as a fixed-width 2-byte LE push, so this block's
//   compiled byte length is invariant in the value — enabling a trivial
//   1-pass fixed-point compile in the caller (see `normal-body.ts`).
// * PKH-only owner scope (Phase 5 marker check `14 OP_EQUALVERIFY` hard-
//   rejects MPKH owners). Decision D.0.3.
// * No intra-block altstack state leaks: altstack is empty on exit. Decision
//   D.0.1 / §5 invariant 1.
//
// -- Byte cost --------------------------------------------------------------
//
// Approximate: Phase 5 ~22b + Phase 6 ~22b + Phase 7 ~7b = ~51b total.
// Replaces previous ~144b (tailCacheAsm ~119b + OWNER_IDENTITY_ASM ~25b).
export const prefixOwnerAndZoneAsm = (bodySize: number): string => {
  // Fixed-width 2-byte little-endian hex push. Value is the compile-time
  // Normal-body byte length.
  const lo = bodySize & 0xff;
  const hi = (bodySize >> 8) & 0xff;
  const bodyLenHex = (
    lo.toString(16).padStart(2, "0") + hi.toString(16).padStart(2, "0")
  ).toLowerCase();
  return `
    OP_FROMALTSTACK
    OP_1 OP_SPLIT OP_SWAP
    14 OP_EQUALVERIFY
    14 OP_SPLIT OP_SWAP
    OP_DUP OP_TOALTSTACK
    OP_2 OP_PICK OP_HASH160 OP_EQUALVERIFY
    OP_TOALTSTACK
    OP_CHECKSIGVERIFY
    OP_FROMALTSTACK
    OP_2 OP_SPLIT OP_SWAP
    006D OP_EQUALVERIFY

    ${bodyLenHex} OP_BIN2NUM OP_SPLIT
    OP_SWAP OP_TOALTSTACK
    OP_1 OP_SPLIT OP_SWAP
    6A OP_EQUALVERIFY

    20 OP_SPLIT
    14 OP_SPLIT
    OP_16 OP_SPLIT
    OP_1 OP_SPLIT
    14 OP_SPLIT
    14 OP_SPLIT
    OP_2 OP_SPLIT

    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_FROMALTSTACK

    OP_13 OP_ROLL
  `;
};

// ===========================================================================
// §3.5 + §3.6 + §3.7 — PREFIX Phases 5 + 6 + 7 (D.3 prep — owner-sig
// extracted out of PREFIX into per-path SUFFIX).
// ===========================================================================
//
// Background (D.3 prep refactor):
//   The original `prefixOwnerAndZoneAsm` (D.1) baked owner-identity check
//   (HASH160(pubkey)==owner_pkh + CHECKSIGVERIFY) into PREFIX itself. That
//   was correct for path 1 (flex-transfer, owner-authorized) but wrong for
//   paths 3/4 where authority — not owner — is the signer per spec
//   §4.2 rule 4 / §9.4 / §9.5 (confiscate without owner consent is the
//   whole point of confiscation; freeze likewise).
//
//   `prefixZoneAsm` is the path-agnostic PREFIX: walks the owner-prefix
//   to extract owner_pkh into the §2 zone, but does NOT perform any sig
//   check. Paths 1 and 2 (owner-authorized) prepend `OWNER_IDENTITY_CHECK_ASM`
//   in their SUFFIX. Paths 3 and 4 (authority-authorized) call the more
//   general `authorityIdentityAsm(flagMask)` helper instead.
//
// -- Postcondition (delta from `prefixOwnerAndZoneAsm`) ----------------------
//
//   `prefixOwnerAndZoneAsm`:
//     main top-down = [path_id, zone(13), ...unlocking_rest]   (pubkey/sig consumed)
//
//   `prefixZoneAsm`:
//     main top-down = [path_id, zone(13), pubkey, sig, ...unlocking_rest]
//
//   The two extra items (pubkey, sig) sit at depths 14 and 15 — between
//   the zone and the witness — and are consumed by the path-specific
//   identity check at SUFFIX entry.
//
// -- Byte budget --------------------------------------------------------------
//
//   `prefixZoneAsm`: ~48b (8b smaller than `prefixOwnerAndZoneAsm` thanks
//   to the removed sig-check choreography). Net body change after
//   `OWNER_IDENTITY_CHECK_ASM` (10b) is added to PATH1_ASM: +2b.
export const prefixZoneAsm = (bodySize: number): string => {
  const lo = bodySize & 0xff;
  const hi = (bodySize >> 8) & 0xff;
  const bodyLenHex = (
    lo.toString(16).padStart(2, "0") + hi.toString(16).padStart(2, "0")
  ).toLowerCase();
  return `
    OP_FROMALTSTACK
    OP_1 OP_SPLIT OP_SWAP
    14 OP_EQUALVERIFY
    14 OP_SPLIT OP_SWAP
    OP_TOALTSTACK
    OP_2 OP_SPLIT OP_SWAP
    006D OP_EQUALVERIFY

    ${bodyLenHex} OP_BIN2NUM OP_SPLIT
    OP_SWAP OP_TOALTSTACK
    OP_1 OP_SPLIT OP_SWAP
    6A OP_EQUALVERIFY

    20 OP_SPLIT
    14 OP_SPLIT
    OP_16 OP_SPLIT
    OP_1 OP_SPLIT
    14 OP_SPLIT
    14 OP_SPLIT
    OP_2 OP_SPLIT

    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_FROMALTSTACK

    OP_15 OP_ROLL
  `;
};

// Owner-identity check (PKH-only) for path 1 (flex-transfer) and path 2
// (refresh) SUFFIX entry. Consumes pubkey and sig from depths 14/15
// (inserted by `prefixZoneAsm`), restoring the legacy `prefixOwnerAndZoneAsm`
// post-state where path_id sits at d0 and witness at d14+.
//
// Pre-state (post-`prefixZoneAsm`):
//   main top-down = [path_id, hashPrev, thisOut, hashOut, owner_pkh,
//                    body, optData, depth, confiscAuth, freezeAuth,
//                    authFlags, amount, issuerPkh, tokenId,
//                    pubkey, sig, ...witness, M]
//
// Post-state:
//   main top-down = [path_id, hashPrev, thisOut, hashOut, owner_pkh,
//                    body, optData, depth, confiscAuth, freezeAuth,
//                    authFlags, amount, issuerPkh, tokenId,
//                    ...witness, M]
//
// Sequence:
//   OP_14 OP_ROLL          : pubkey (d14) → top; items 0..13 shift +1
//   OP_DUP OP_HASH160       : compute hash160(pubkey); leaves [hash, pubkey,
//                             path_id, hashPrev, ..., owner_pkh(d6), ...]
//   OP_6 OP_PICK            : copy zone.owner_pkh (at d6) to top
//   OP_EQUALVERIFY          : verify hash == owner_pkh; restores [pubkey, ...
//                             path_id, ..., owner_pkh(d4), ..., sig(d15), ...]
//   OP_15 OP_ROLL           : sig (d15) → top
//   OP_SWAP                 : `OP_CHECKSIGVERIFY` pops pubKey first then
//                             sigWithType; need pubkey on top, sig below.
//                             Without SWAP the eval throws
//                             "OP_CHECKSIGVERIFY missing FORKID" because the
//                             sig bytes get parsed as a pubkey and the pubkey
//                             bytes' last byte (lacking the 0x40 FORKID bit)
//                             gets parsed as the sighashType.
//   OP_CHECKSIGVERIFY       : verify sig over preimage authorization
//
// Byte budget: 11b. Replaces ~9b of inline sig-check from old PREFIX —
// net +2-3b per body, in exchange for path-conditional auth dispatch.
export const OWNER_IDENTITY_CHECK_ASM = `
  OP_14 OP_ROLL
  OP_DUP OP_HASH160
  OP_6 OP_PICK OP_EQUALVERIFY
  OP_15 OP_ROLL
  OP_SWAP
  OP_CHECKSIGVERIFY
`;

// Output serialization helper — FD-only varint (candidate scripts always
// land in [0xFD..0xFFFF] range per decision #38; single-branch saves ~120b
// vs 3-branch generic varint per A.2.5 retro-opt).
//
// Pre-state (top-first): [C, X]
//   - C = candidate locking-script bytes (the locking script being committed).
//   - X = "below" accumulator (allows multi-output composition; for single-
//         output paths X is just the empty bytes left below by setup).
//
// Post-state (top-first): [X ‖ sats(8) ‖ FD ‖ size_le_2b ‖ C]
//   - sats(8) = `0100000000000000` (1 satoshi LE per BNTP v2 dust convention)
//   - varint  = 0xFD ‖ size_le_2b (BSV varint for [0xFD..0xFFFF])
//
// Phase 1B audit (Wave D.2c-trailer): the original Phase 1A implementation
// produced `X ‖ C ‖ FD ‖ 0100 ‖ size_C_scriptnum` — wrong byte order AND a
// hardcoded `0100` literal (the first 2 bytes of the sats-1 push) used in
// place of size_le_2b. The bug was masked because paths 2/3/4 are dead code
// in the D.1 dispatcher (only path_id=1 is exercised end-to-end via the
// D.2c pipeline). See tests/bntp-v2-shared-prefix-varint-audit.test.ts for
// the standalone correctness contract; the post-fix implementation mirrors
// the verified D.2c.2 inline reconstruction in normal-body.ts.
//
// Implementation walks:
//   OP_DUP OP_SIZE OP_NIP   : extract size_C as scriptnum (top, leaves C+X below)
//   OP_2 OP_NUM2BIN         : encode size as exactly 2-byte LE
//   FD OP_SWAP OP_CAT       : prepend FD → varint = FD ‖ size_le_2b
//   OP_SWAP OP_CAT          : prepend varint to C → varint ‖ C
//   <sats> OP_SWAP OP_CAT   : prepend sats(8) → sats ‖ varint ‖ C
//   OP_CAT                  : prepend X (consume final stack item below) →
//                             X ‖ sats ‖ varint ‖ C
//
// Byte budget unchanged from Phase 1A helper (23b → 23b); correctness
// rectified. NUM2BIN(2) requires scriptLen ≤ 32767 (signed scriptnum
// fits in 2 bytes); BNTP candidate scripts are well within this bound
// (~2000-3000b for the Normal template). Magnetic-opcodes flag must be
// set in the script eval context (it is — see DEFAULT_FLAGS).
export const VARINT_SERIALIZE_ASM = `
  OP_DUP OP_SIZE OP_NIP
  OP_2 OP_NUM2BIN
  FD OP_SWAP OP_CAT
  OP_SWAP OP_CAT
  0100000000000000 OP_SWAP OP_CAT
  OP_CAT
`;

// Generic authority identity + CHECKSIG(VERIFY) block.
// `flagMaskHex` discriminates PKH vs MPKH via authorityFlags bit:
//   - 0x04 for freezeAuth (bit 2)
//   - 0x08 for confiscAuth (bit 3)
//   - 0x10 for issuer      (bit 4)
// Post-A.3.1: MPKH range check `OP_1 OP_6 OP_WITHIN` allows n ∈ {1..5}.
export const authorityIdentityAsm = (flagMaskHex: string) => `
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  ${flagMaskHex} OP_AND 00 OP_EQUAL
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
