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

// §3.5 scriptCode tail extraction + cache (7 fields to altstack).
// Tail layout is identical across Normal/Contract/Frozen per spec §5.2.
export const TAIL_CACHE_ASM = `
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

// Output serialization helper — FD-only varint (candidate scripts always
// land in [0xFD..0xFFFF] range per decision #38; single-branch saves ~120b
// vs 3-branch generic varint per A.2.5 retro-opt).
export const VARINT_SERIALIZE_ASM = `
  0100000000000000 OP_SWAP
  OP_SIZE OP_SWAP
  OP_ROT OP_SWAP
  FD OP_CAT OP_SWAP OP_2 OP_SPLIT OP_DROP OP_CAT
  OP_SWAP OP_CAT OP_CAT
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
