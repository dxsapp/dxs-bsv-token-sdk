# BNTP NormalBase Template — Pseudo-ASM (Phase 0.1)

**Status:** Phase 0.1 draft. Opcode-depth pseudo-ASM with careful byte counting, produced after the Option A pivot (`BNTP_CRITICAL_REVIEW.md` §8, `BNTP_SERIES_V1_SPEC.md` §3.2). Replaces §§3-9 of `BNTP_TEMPLATE_NORMAL_ASM.md` in the post-Option-A world. Byte counts are best-effort estimates derived from DSTAS 1.0.4 patterns + Phase 0 Normal pseudo-ASM minus attestation, plus the 128b whitelist bump.

**Scope:** NormalBase body only. Covers PREFIX ‖ WHITELIST ‖ SUFFIX between `OP_2DROP` and `OP_RETURN` (spec §5). Variable prefix (owner, action_data) and tail (seriesId, tokenId, redemptionPkh, issuerPkh, authFlags, freezeAuthHash, confiscAuthHash, optionalData) are NOT part of the body but are discussed where the SUFFIX consumes them.

**Out of scope:** `NormalSwapOnRamp` pseudo-ASM (Phase 0.2 — `BNTP_TEMPLATE_NORMAL_SWAP_ONRAMP_ASM.md`). Frozen / SwapReady / Contract bodies (later phases).

---

## 1. Overview

- **Target body size (G4 gate):** ≤ 3000b PASS, ≤ 3200b PASS-with-margin, 3200-3400b PIVOT, > 3400b ABORT.
- **Sections:**
  - PREFIX (constant per template) — body marker, covenant, sighash check, preimage parse, scriptCode caching, path dispatcher.
  - WHITELIST (constant per series) — 128 bytes of `h_NormalBase ‖ h_NormalSwapOnRamp ‖ h_Frozen ‖ h_SwapReady` (§5.3). Zero-placeholder at template-design time; populated at series deployment. Excluded from `h_NormalBase` computation (self-reference avoidance per `BNTP_WHITELIST_COMMITMENT_PROOF.md`).
  - SUFFIX (constant per template) — per-path branches (paths 1..6) that reconstruct candidate outputs, run output-verification helper, close hashOutputs covenant.
- **Body marker:** `0x01 0xff` at offset 0 of PREFIX (§7.4). Present as the first two raw bytes of the body via a 2-byte data push + OP_DROP (see §3.1).
- **Path_id range (NormalBase):** 1..6. Dispatch rejects path_id ∉ {1, 2, 3, 4, 5, 6}. Path 7 (swap-exec) lives in SwapReady, not here.
- **Paths:**
  - 1 — transfer/split (owner-sig → 1..4 NormalBase outputs)
  - 2 — merge-K (K ∈ [2, 4]) (owner-sig → 1..2 NormalBase outputs via anchor/follower)
  - 3 — prepare-swap-transition (owner-sig → 1 NormalSwapOnRamp output, value/owner preserved) — **NEW in Phase 0.1, replaces old expensive path 3**
  - 4 — freeze (freeze-authority sig → 1 Frozen output)
  - 5 — confiscate (confisc-authority sig → 1 NormalBase output with new owner)
  - 6 — redeem (issuer sig → P2PKH redemption + 0..3 NormalBase remainders)
- **Per-path output-template restriction (§7.2, S2 AMR #3):** each branch narrows the whitelist subset acceptable for its token-leg outputs.
  - Path 1 → only `h_NormalBase`
  - Path 2 (anchor) → only `h_NormalBase`; (follower) only verifies anchor's prev-tx output is NormalBase same-token.
  - Path 3 → only `h_NormalSwapOnRamp` (marker 0x02ff)
  - Path 4 → only `h_Frozen` (marker 0xfeff)
  - Path 5 → only `h_NormalBase` (marker 0x01ff, new owner)
  - Path 6 → P2PKH output 0 + only `h_NormalBase` for remainders

This document replaces §§3-9 of `BNTP_TEMPLATE_NORMAL_ASM.md`. Sections §§1-2 of the old doc (preamble, variable prefix) are substantively the same and summarized here.

---

## 2. Variable prefix (before OP_2DROP) — not part of body

Not counted toward body size. Listed for completeness (spec §5.1-§5.2):

| Push             | Size                                                                                              | Content                    |
| ---------------- | ------------------------------------------------------------------------------------------------- | -------------------------- |
| Owner push       | 21 bytes for 20b PKH (`OP_PUSH20 ‖ pkh`), or 37..172 bytes for MPKH preimage (`OP_PUSHDATA1 LEN`) | Spender identity           |
| Action data push | 1 byte (`OP_0`) for NormalBase                                                                    | State discriminator = 0x00 |
| `OP_2DROP`       | 1 byte                                                                                            | Drop both variable pushes  |

Common case (20b PKH + OP_0 + OP_2DROP): **23 bytes**, not counted in body.

---

## 3. PREFIX (start of body)

The PREFIX holds everything needed before per-path branches: body-marker emission, OP_PUSH_TX covenant, sighash explicit check, preimage parse, own-scriptCode extraction + caching (tail + WHITELIST + counterpartyScript), and path_id dispatcher.

### 3.1 Body marker `0x01 0xff` (§7.4)

```
OP_PUSHDATA1 0x02 0x01 0xFF      // emit 2-byte NormalBase marker as data at body offset 0
OP_DROP                           // marker is a byte-pattern for external verification, not runtime-used here
```

- `4c 02 01 ff 75` = **5 bytes**.

**Note:** the marker serves the output-verification helper (§6) on _candidate_ output scripts — it is not branched on for self-execution. Placing it at body offset 0 is the normative rule from §7.4, enforced by pseudo-ASM producing these bytes unconditionally as the first two executable-data bytes of the body.

Subtotal: **5b**.

### 3.2 OP_PUSH_TX covenant (inherited DSTAS pattern; spec §13)

Generator-point covenant: signature with `r = G.x`, dynamic `s` computed from `HASH256(preimage)`, verified against one of two pre-computed pubkeys `038ff83d…` / `023635…` with parity branching.

```
// ... compute s from HASH256(preimage) ...
// ... assemble DER signature r ‖ s ‖ sighashType 0x41 ...
OP_IF  <pubkey_even>  OP_ELSE  <pubkey_odd>  OP_ENDIF
OP_CHECKSIGVERIFY
```

Bytes (reusing Phase 0 §3.2 estimate, DSTAS audit §5.1.A optimized):

- Two embedded pubkeys: 2 × (push33 + 33) = 68b
- DER construction (SPLITs, SIZE checks, 0x02/0x20 tags, sighash byte append): ~280b
- CHECKSIGVERIFY: 1b

Subtotal: **~350b**.

### 3.3 Sighash-type explicit check (§15 resolved #3)

```
<preimage>                        // already on stack, duplicated by covenant block
OP_SIZE OP_SWAP
4 OP_SUB OP_SPLIT OP_NIP          // take last 4 bytes (sighashType LE)
<0x41000000>                      // SIGHASH_ALL | SIGHASH_FORKID, little-endian
OP_EQUALVERIFY
```

- 4-byte literal push (1 + 4 = 5b) + 7 opcodes = **12b**.

Subtotal: **12b**.

### 3.4 Preimage parse (inherited DSTAS pattern, optimized)

Extract from preimage:

- `hashPrevouts` (32b, offset 4)
- `thisOutpoint` (36b, offset 68)
- `scriptCode` (varint-prefixed, offset 104+)
- `satoshis` (8b LE, offset scriptCode_end + 0)
- `hashOutputs` (32b, offset scriptCode_end + 8 + 4)

DSTAS used ~300b; audit §5.1.A eliminates ~120b of redundant endian flips; §5.1.B removes ~60b of 4-byte-varint handling.

Optimized estimate: **~180b** (same as Phase 0 §3.5).

Subtotal: **180b**.

### 3.5 Own-scriptCode extraction + caching (tail + WHITELIST + counterpartyScript)

NormalBase needs access to:

- Own `WHITELIST` bytes (128b at fixed offset after PREFIX) — for output-verification byte-match (§6) and the 4-hash membership check.
- Own `tail` bytes (seriesId 32b + tokenId 32b + redemptionPkh 20b + issuerPkh 20b + authFlags 1b + freezeAuthHash 20b + confiscAuthHash 20b + optionalData var) — for tail-consistency (§7.3) and authority dispatch (paths 4, 5, 6).
- Own `counterpartyScript` (= scriptCode minus owner + action_data + OP_2DROP prefix, up to OP_RETURN) — for merge-K prev-tx reconstruction (§5.2).
- Own `owner_field` (20b PKH or MPKH preimage) — for CHECKSIG identity check.

```
<scriptCode>
OP_DUP OP_TOALTSTACK              // cache full scriptCode
// 1. Split off owner-push prefix (OP_PUSH20 + 20b OR OP_PUSHDATA1 + len + preimage)
1 OP_SPLIT OP_SWAP                // peek first byte
OP_DUP 0x14 OP_EQUAL
OP_IF                             // P2PKH case (20b owner)
  OP_DROP 20 OP_SPLIT              // split off 20b
  OP_SWAP OP_DROP                  // drop owner for this cache path; re-read from stack by identity check
OP_ELSE                           // OP_PUSHDATA1 + len + preimage (MPKH)
  0x4c OP_EQUALVERIFY
  1 OP_SPLIT OP_BIN2NUM            // read pushdata length byte
  OP_DUP OP_ROT OP_SPLIT           // split off <len> bytes of MPKH preimage
  OP_SWAP OP_DROP
OP_ENDIF
// stack now: remainder_scriptCode (starts with 0x00 action_data + 0x6d OP_2DROP + body_marker + ...)
// 2. Strip action_data (OP_0 = 0x00 for NormalBase) + OP_2DROP
1 OP_SPLIT OP_SWAP <0x00> OP_EQUALVERIFY
1 OP_SPLIT OP_SWAP <0x6d> OP_EQUALVERIFY
// stack now: body = body_marker ‖ PREFIX_tail ‖ WHITELIST ‖ SUFFIX
// 3. Skip past our known-PREFIX-length (constant, resolved at template-assembly time) → get WHITELIST ‖ SUFFIX
<PREFIX_len> OP_SPLIT
// stack: PREFIX_bytes, WHITELIST‖SUFFIX
OP_DROP                           // discard PREFIX duplicate (already embedded)
128 OP_SPLIT OP_SWAP               // split off WHITELIST
OP_TOALTSTACK                      // stash WHITELIST on altstack for later (§6)
// stack: SUFFIX_bytes, ... — drop SUFFIX, we don't need it directly
OP_DROP
// 4. Now pop full scriptCode again from altstack and walk to OP_RETURN for tail cache
OP_FROMALTSTACK                   // WHITELIST back (we need tail separately; keep WHITELIST for shared helper)
// re-grab full scriptCode from altstack
OP_FROMALTSTACK                   // scriptCode again
// ... extract counterpartyScript = everything between (owner+action_data+2DROP) and OP_RETURN
// ... extract tail = everything after OP_RETURN, cap at known fixed 145b + optionalData-varint
```

This is heavier than Phase 0's "just extract owner" since we need three cached items. Subtotal breakdown:

| Caching step                                          | Bytes |
| ----------------------------------------------------- | ----- |
| Owner-push strip (P2PKH + MPKH branch)                | ~60   |
| Action_data + OP_2DROP strip                          | ~10   |
| Skip PREFIX (fixed-length split)                      | ~10   |
| Extract + cache WHITELIST (128b → altstack)           | ~12   |
| Walk to OP_RETURN for counterpartyScript boundary     | ~25   |
| Cache counterpartyScript (altstack)                   | ~8    |
| Tail extraction (skip OP_RETURN, 145b + optionalData) | ~25   |
| Cache tail (altstack, handling optionalData varint)   | ~30   |

Subtotal: **~180b** (vs Phase 0's ~120b for owner-only + ~60b tail cache = 180b combined — equivalent, just regrouped).

**OPEN QUESTION #1:** Can we skip the WHITELIST altstack round-trip and instead use a fixed-offset `OP_SPLIT` on scriptCode on demand inside §6 (called K times in path 2)? Trades 12b one-time save against ~30b extra per §6 invocation. With §6 invoked ≤ 4× in the worst path (path 1 transfer-to-4), fresh-extract per invocation is +120b worst case. Keep altstack cache (conservative). Flagged for Phase 1 micro-optimization.

### 3.6 Owner identity check

After the covenant's CHECKSIGVERIFY (§3.2) the signature was verified under one of the parity pubkeys — but that pubkey is NOT the owner's; it's the generator-point parity. Owner identity must be re-verified:

```
<owner_pubkey>                    // from unlocking (already on stack below preimage)
OP_HASH160
<owner_field_from_scriptCode_cache>
OP_EQUALVERIFY
```

For MPKH owner (rare; requires flag in tail — note: v1 spec §5.2 doesn't explicitly call out owner MPKH, only issuer/authority MPKH):

- For NormalBase, owner is always 20b PKH or MPKH preimage; **treat MPKH owner as out-of-scope for v1** (no flag bit allocated in §5.5 for owner MPKH, only issuer/auth MPKH).

Subtotal: **~5b** (push + HASH160 + push + EQUALVERIFY = ~5b when `owner_field` is already cached on altstack).

### 3.7 Path_id range check + dispatcher

```
// Stack at this point: ..., preimage, path_id (from unlocking)
OP_DUP <1> <7> OP_WITHIN OP_VERIFY   // path_id ∈ [1, 7) = {1..6}
// Chain of 6 OP_DUP <N> OP_EQUAL OP_IF ... OP_ENDIF branches
OP_DUP <1> OP_EQUAL OP_IF … §5.1 … OP_ENDIF
OP_DUP <2> OP_EQUAL OP_IF … §5.2 … OP_ENDIF
OP_DUP <3> OP_EQUAL OP_IF … §5.3 … OP_ENDIF
OP_DUP <4> OP_EQUAL OP_IF … §5.4 … OP_ENDIF
OP_DUP <5> OP_EQUAL OP_IF … §5.5 … OP_ENDIF
OP_DUP <6> OP_EQUAL OP_IF … §5.6 … OP_ENDIF
OP_DROP                              // consume path_id
```

- Range check: `OP_DUP <1> <7> OP_WITHIN OP_VERIFY` = 5b
- 6 dispatch headers: 6 × 5b = 30b
- Trailing `OP_DROP`: 1b

Subtotal: **~36b**.

### 3.8 PREFIX totals

| Sub-block                          | Bytes   |
| ---------------------------------- | ------- |
| Body marker (§3.1)                 | 5       |
| OP_PUSH_TX covenant (§3.2)         | 350     |
| Sighash-type check (§3.3)          | 12      |
| Preimage parse (§3.4)              | 180     |
| ScriptCode extraction cache (§3.5) | 180     |
| Owner identity check (§3.6)        | 5       |
| Path_id dispatcher (§3.7)          | 36      |
| **PREFIX subtotal**                | **768** |

Close to Phase 0's 703b; +65b is the extra counterpartyScript + WHITELIST caching for 128b whitelist support and merge-K reuse.

`**OPEN QUESTION #2:**` Spec §12.1 estimates PREFIX at ~1100b for NormalBase, but the table's PREFIX column appears to include per-path logic staged inside dispatcher branches (lines 1021). This doc splits PREFIX-common (§3, ~768b) from per-path bodies (§5). Budget interpretation: "body total ≤ 3000b" is what matters; sub-column allocations are indicative only.

---

## 4. WHITELIST placeholder (128b; normative offset §5.3.1)

- **Size:** 128 bytes (4 × 32b) = `h_NormalBase ‖ h_NormalSwapOnRamp ‖ h_Frozen ‖ h_SwapReady`. Zero-placeholder at compile time; replaced byte-wise at series deployment.
- **Offset:** immediately after PREFIX. **Normative rule §5.3.1** — output verification (§6) depends on this.
- **Encoding:** emitted as pure data via `OP_PUSHDATA1 0x80 <128 raw bytes> OP_DROP` — 2 (push op + len) + 128 (data) + 1 (drop) = **131 bytes**.
- **NOT included** in `h_NormalBase` hash preimage (§5.3 clarification, S2 AMR #1).

Total WHITELIST section: **131 bytes**.

(Phase 0 used 99b for 96b whitelist; +32 bytes of data alone takes us to 131b.)

---

## 5. SUFFIX — per-path branches

SUFFIX sits after WHITELIST. Each path_id branch (§3.7 dispatcher) executes its own logic block, which includes (as appropriate) candidate output reconstruction, shared output-verification helper (§6) invocation, hashOutputs covenant closure, anti-dust check (§7), and path-specific authority/identity verification beyond the common owner sig (§3.6).

### 5.1 Path 1 — transfer/split (§9.2)

**Approach (post-S1 AMR #2):** unlocking pushes FULL candidate locking scripts (one per token-leg output), NOT tuple components. SDK builder derives script bytes from `(owner, action_data, body_constants, tail)` at signing time. SUFFIX verifies the pushed script + satoshis against the covenant.

```
// Stack at dispatch: ..., preimage, path_id == 1, unlocking extras already bound
// Extras from unlocking (reverse-pushed):
//   candidate_script_1..candidate_script_N  (N ∈ [1, 4])
//   candidate_satoshis_1..candidate_satoshis_N
//   output_count N
//   null_data_script? (optional, up to 1)
//   change_script + change_satoshis? (optional P2PKH)
//   funding_outpoint 36b

// Path 1 logic (unrolled for N up to 4 via branch skeleton):

OP_DUP <output_count> OP_1 <5> OP_WITHIN OP_VERIFY    // N ∈ [1, 4]

// Initialize accumulators on altstack: Σsat_out = 0, hashOutputs_preimage = empty
<0> OP_TOALTSTACK                                      // running satoshis_out
<empty> OP_TOALTSTACK                                  // running output bytes

// Unrolled loop × 4 (early-exit on i >= N via OP_IF chain):
// For each i in 1..4:
OP_DUP <i> OP_GREATERTHANOREQUAL OP_IF
  // pop candidate_satoshis_i, candidate_script_i from stack
  // (7a) anti-dust check:
  OP_DUP <1> OP_GREATERTHANOREQUAL OP_VERIFY           // sat ≥ 1
  // (7b) accumulate into hashOutputs buffer:
  //   output_serialized = satoshis (8b LE) ‖ varint(len(script)) ‖ script
  ... CAT chain ...
  // (7c) invoke §6 helper with (candidate_script, expected_marker = 0x01ff, allowed_hashes = {h_NormalBase})
  <CALL §6 with marker_mask=path1>
  // (7d) tail consistency: tail within candidate_script == this.tail (cached)
  <CALL §7.3 tail match>
  OP_ADD OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK          // update Σsat_out
OP_ENDIF

// After 4 unrolled iterations:
OP_FROMALTSTACK                                        // reconstructed outputs concat
// Append optional null-data output, if present:
OP_DUP <null_present_flag> OP_IF
  OP_SWAP OP_CAT                                        // append null-data script
OP_ENDIF
// Append optional change output (P2PKH/P2MPKH):
OP_DUP <change_present_flag> OP_IF
  ... push change_script + satoshis ...
  OP_CAT
OP_ENDIF

// Covenant closure: HASH256(reconstructed_outputs) == preimage.hashOutputs
OP_HASH256
<hashOutputs_from_preimage_cache> OP_EQUALVERIFY

// Conservation: Σsat_out == satoshis_in (+ change satoshis)
OP_FROMALTSTACK                                        // Σsat_out
<satoshis_in_from_preimage>
OP_EQUALVERIFY                                          // ignoring change-from-funding-input semantics (see note)
```

**Note (change semantics):** in transfer/split the token-leg Σ must equal `satoshis_in`; change is funded by the funding P2PKH input, not from BNTP value. The script's conservation check is over token-leg outputs only; change bytes still participate in the hashOutputs reconstruction but not in Σsat_out. This matches §9.2 output-class rules.

**Budget (path 1):**

| Sub-block                                                           | Bytes |
| ------------------------------------------------------------------- | ----- |
| Output-count range check + accumulator init                         | ~15   |
| Per-output iteration body (anti-dust + serialize + §6 + tail match) | ~100  |
| Unrolled × 4 outputs                                                | 400   |
| Null-data append branch                                             | ~25   |
| Change-output append branch                                         | ~40   |
| HashOutputs covenant closure                                        | ~10   |
| Conservation check                                                  | ~10   |

Path 1 total: **~500b** (slightly under Phase 0's 520b — savings from tighter tuple-vs-script unification per S1 AMR #2).

### 5.2 Path 2 — merge-K (§9.3 + `BNTP_ANCHOR_FOLLOWER_ALGORITHM.md`)

Anchor/follower position determination via `hashPrevouts` binding over `all_outpoints ‖ funding_outpoint`. See S3 doc for full correctness argument.

```
// Stack at dispatch: ..., preimage, path_id == 2, extras:
//   anchor branch extras: follower_i pieces + vouts + piece_counts (× followerCount),
//                         followerCount, all_outpoints (36×K), funding_outpoint,
//                         output_tuples × (1..2 Normal outs), change?, null-data?
//   follower branch extras: anchor pieces + vout + piece_count, all_outpoints, funding_outpoint, selfPosition

// (A) Shared section — always executed for path 2:
// Verify all_outpoints binding:
<all_outpoints> <funding_outpoint> OP_CAT
OP_HASH256
<hashPrevouts_from_preimage_cache> OP_EQUALVERIFY          // 10b

// Compute K_STAS = |all_outpoints| / 36
<all_outpoints> OP_SIZE <36> OP_DIV
OP_DUP <2> <5> OP_WITHIN OP_VERIFY                          // K ∈ [2, 4]
OP_TOALTSTACK                                                // stash K_STAS

// Scan all_outpoints for my_outpoint (from preimage offset 68) → selfPosition
<preimage> <68> OP_SPLIT OP_NIP <36> OP_SPLIT OP_DROP        // extract my_outpoint
// Unrolled 4× byte-compare against all_outpoints[0..4]
// Produces selfPosition ∈ {0, 1, 2, 3} + exactly-one-match invariant
<scan unrolled>                                              // ~70b

// (B) Dispatch on selfPosition:
OP_DUP <0> OP_EQUAL
OP_IF
  // (B1) Anchor branch — §5.2 of S3
  <followerCount from unlocking>
  OP_DUP <1> <4> OP_WITHIN OP_VERIFY                          // ∈ [1, 3]
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK                        // copy K_STAS
  <1> OP_SUB
  OP_EQUALVERIFY                                              // followerCount == K_STAS - 1 (S3 AMR #3)

  // For i in 1..followerCount (unrolled up to 3 iterations):
  //   reconstruct follower_i_prev_tx: splice(pieces[0] ‖ counterpartyScript ‖ pieces[1] ‖ ... )
  //   HASH256 over reconstructed
  //   expected_txid = all_outpoints[i*36 .. i*36+32]
  //   OP_EQUALVERIFY
  //   parse output at follower_i_mergeVout: extract (sat_i, script_i)
  //   script_i must match §6 helper (marker 0x01ff, hash ∈ {h_NormalBase})
  //   tail fields match this.tail (same token)
  //   Σ_sat += sat_i
  <anchor loop unrolled × 3>                                  // ~400b (see below)

  // Reconstruct 1..2 Normal output_tuples (see path 1 loop shape for mechanics):
  <output reconstruction × 2>                                  // ~200b
  // Conservation: Σ(this.sat + Σfollowers) == Σouts
  ... ~15b ...
  // HashOutputs covenant closure: ~10b
OP_ELSE
  // (B2) Follower branch — §2.4 of S3
  // selfPosition ∈ [1, 3] (already in-range by scan invariant)
  <anchor_pieces, anchor_piece_count, anchor_mergeVout from unlocking>
  // reconstruct anchor_prev_tx: splice(pieces ‖ this.counterpartyScript ‖ ...)
  // HASH256
  // expected_txid = all_outpoints[0..32]
  // OP_EQUALVERIFY
  // parse output at anchor_mergeVout: extract (sat_0, script_0)
  // script_0 must match §6 helper (marker 0x01ff, hash ∈ {h_NormalBase})
  // tail fields match this.tail (same token)
  <follower reconstruction block>                              // ~330b (see below)
  // No conservation, no hashOutputs closure (anchor does it, S3 §2.5)
OP_ENDIF
```

**Budget (path 2):**

| Sub-block                                                                                             | Bytes           |
| ----------------------------------------------------------------------------------------------------- | --------------- |
| all_outpoints binding + K_STAS derive + range check                                                   | ~40             |
| my_outpoint scan (unrolled × 4, exactly-one-match)                                                    | ~70             |
| Dispatch branch headers (OP_IF / OP_ELSE / OP_ENDIF)                                                  | ~5              |
| **(B1) Anchor branch**                                                                                |                 |
| followerCount range + cross-check                                                                     | ~15             |
| Per-follower reconstruction (pieces ‖ counterpartyScript splice + HASH256 + txid match) × 1 iteration | ~130            |
| Output extraction at mergeVout + §6 + tail match per follower                                         | ~30             |
| Unrolled × 3 iterations (i=1,2,3, gated on followerCount)                                             | 3 × ~150 = ~450 |
| Σ_sat accumulator + OP_ADD chain                                                                      | ~10             |
| Output reconstruction × 2 (output tuples, similar to path 1)                                          | ~200            |
| Conservation check                                                                                    | ~15             |
| HashOutputs covenant closure                                                                          | ~10             |
| **Anchor subtotal**                                                                                   | **~700**        |
| **(B2) Follower branch**                                                                              |                 |
| Anchor prev-tx reconstruction (pieces + HASH256 + txid match)                                         | ~200            |
| Output extraction at anchor_mergeVout                                                                 | ~40             |
| §6 invocation on extracted script                                                                     | ~20             |
| Tail match                                                                                            | ~40             |
| **Follower subtotal**                                                                                 | **~300**        |
| **Shared section (A + dispatch + both branches live in body)**                                        | ~115            |

Path 2 total (body contains BOTH branches; only one runs per invocation): **~1115b**.

`**OPEN QUESTION #3:**` (carried from Phase 0 §5.2) Can anchor and follower share the "reconstruct prev tx + HASH256 + txid-match" helper via `OP_IF` fall-through? DSTAS partially does. Potential savings ~100-200b. Budget conservative: NO sharing. Flagged for Phase 1 optimization pass.

### 5.3 Path 3 — prepare-swap-transition (§9.4.1) — **NEW in Phase 0.1**

Owner-initiated state rename from NormalBase to NormalSwapOnRamp. No issuer involvement, no royalty, no attestation. Value, owner, and all tail fields preserved. Target output marker: `0x02ff` (NormalSwapOnRamp).

```
// Stack: ..., preimage, path_id == 3, extras:
//   nso_candidate_script (full NSO locking script bytes, covered by covenant)
//   nso_candidate_satoshis
//   null_data? (optional)
//   change? (optional, P2PKH)
//   funding_outpoint 36b

// Owner sig already verified in §3.2 (generator-point) + §3.6 (HASH160 match).

// (1) Anti-dust:
<nso_candidate_satoshis>
OP_DUP <1> OP_GREATERTHANOREQUAL OP_VERIFY                    // 4b

// (2) Satoshis preserved: nso_candidate_satoshis == this.satoshis (from preimage cache):
<satoshis_from_preimage_cache> OP_EQUALVERIFY                 // 5b

// (3) Owner preserved: nso_candidate_script's owner prefix == this.owner (cached):
//     Split off nso_candidate_script's first 21 bytes (P2PKH owner push), compare to this.owner_field prefix.
OP_DUP <21> OP_SPLIT                                           // 3b
OP_SWAP <owner_field_prefix_from_cache> OP_EQUALVERIFY         // 4b (cached)

// (4) Body marker in nso_candidate_script == 0x02ff:
//     After owner push (21b) + action_data (OP_0 = 1b) + OP_2DROP (1b), the next 2 bytes are body marker.
//     We already have remainder after the SPLIT above. Skip 2b action_data+2DROP:
<2> OP_SPLIT OP_SWAP                                            // split off 0x00 0x6d
<0x006d> OP_EQUALVERIFY                                          // ~5b
// Next 2 bytes are body marker (but they are actually inside a push... spec §7.4 treats them as data bytes at offset 0 of body, so the push wrapper OP_PUSHDATA1 0x02 prefix is present first)
// Actually: body starts with `4c 02 01 ff 75` per §3.1 (5 bytes total). Marker is at offset 2-3.
<5> OP_SPLIT                                                    // split PREFIX marker prefix = 4c 02 01 ff 75
OP_SWAP <0x4c0202ff75> OP_EQUALVERIFY                            // ~8b — explicit NSO marker bytes including push wrapper + OP_DROP

// (5) Invoke §6 helper (restricted to h_NormalSwapOnRamp only):
<CALL §6 with allowed_hashes = {h_NSO}>                         // cost counted in §6, invocation ~5b

// (6) Tail consistency: candidate.tail == this.tail byte-exact (same token, same series):
<CALL §7.3 tail match>                                           // invocation ~5b

// (7) Reconstruct hashOutputs preimage:
//   output_0 = nso_candidate satoshis (8b LE) ‖ varint(len) ‖ nso_candidate_script
//   + optional null-data_1
//   + optional change_2
<output serialization + optional tail appends>                   // ~40b (incl. null-data / change branches)

// (8) Covenant closure:
OP_HASH256 <hashOutputs_from_preimage_cache> OP_EQUALVERIFY      // ~10b
```

**Budget (path 3):**

| Sub-block                                          | Bytes |
| -------------------------------------------------- | ----- |
| Anti-dust                                          | 4     |
| Satoshis preservation                              | 5     |
| Owner preservation (21b prefix EQUALVERIFY)        | 10    |
| Body marker 0x02ff check (+ push wrapper)          | 15    |
| §6 helper invocation (counted once in §6 subtotal) | 5     |
| §7.3 tail-match invocation (counted once)          | 5     |
| Output serialization + null-data / change branches | 40    |
| HashOutputs closure                                | 10    |

Path 3 total: **~94b** + ~110b for output-serialization helper bytes duplicated here = **~200b**.

Within the predicted 150-250b range (Phase 0 path 3 was 695b).

`**OPEN QUESTION #4:**` The body marker check in (4) hinges on the NSO body marker encoding matching `4c 02 02 ff 75` byte-for-byte at offset 0 of NSO body. This is a normative byte-equality requirement — ensure `BNTP_TEMPLATE_NORMAL_SWAP_ONRAMP_ASM.md` (Phase 0.2) emits body marker via the exact same `OP_PUSHDATA1 0x02 <marker> OP_DROP` encoding. Otherwise the byte-match rejects legitimate NSO outputs.

`**SPEC AMENDMENT REQUEST #1:**` `BNTP_SERIES_V1_SPEC.md` §7.4 should explicitly require that the body-marker encoding opcode sequence (`OP_PUSHDATA1 0x02 <marker_2b> OP_DROP` = 5 bytes) be byte-identical across all series templates. Without this lock, §7.2 step 3 (dispatch-on-marker) is fragile.

### 5.4 Path 4 — freeze (§9.5)

Authority-sig path. Produces exactly 1 Frozen output (marker 0xfeff), owner/satoshis/token preserved.

```
// Stack: ..., preimage, path_id == 4, extras:
//   frozen_candidate_script (full)
//   frozen_candidate_satoshis
//   null_data? change?
//   funding_outpoint

// (1) Flags check: bit 0 (freezable) set
<flags_from_tail_cache> <0x01> OP_AND <1> OP_EQUALVERIFY         // ~8b

// (2) Authority-signature path:
//     Covenant CHECKSIGVERIFY in §3.2 verified a sig, but not against auth identity.
//     The "auth_sig" used here is the OWNER-SLOT sig from the unlocking scaffold (§9.1),
//     repurposed — in path 4 unlocking, [sig, pubKey] are the FREEZE AUTHORITY's.
//     Script verifies HASH160(pubKey) == freezeAuthHash_from_tail.
//     (This replaces §3.6's owner-identity check for paths 4, 5, 6 — the identity check
//      has to be path-aware. See §3.6 note below.)
<pubKey_from_unlocking>
OP_HASH160
<freezeAuthHash_from_tail_cache>
OP_EQUALVERIFY                                                    // 5b
// MPKH branch (flags bit 2): unlocking pushes [OP_0, sig_1..sig_m, mpkh_preimage] instead
<flags_from_tail_cache> <0x04> OP_AND <0> OP_EQUAL
OP_IF
  // single-sig path — already covered by covenant CHECKSIGVERIFY over preimage
OP_ELSE
  // MPKH path: parse mpkh_preimage, CHECKMULTISIGVERIFY against preimage
  <MPKH verification block>                                        // ~150b
OP_ENDIF

// (3) Anti-dust, Owner preservation, Satoshis preservation — SAME shape as path 3:
<anti-dust + sat-preserve + owner-preserve>                        // ~15b

// (4) Body marker in candidate: 0xfeff (Frozen):
<marker byte-match 4c 02 feff 75>                                  // ~15b

// (5) §6 invocation restricted to h_Frozen:
<CALL §6>                                                           // ~5b

// (6) Tail match (same-token paths preserve tail):
<CALL §7.3>                                                         // ~5b

// (7) Output serialization + HashOutputs closure:
<output serialize + HASH256 + EQUALVERIFY>                          // ~50b
```

**Budget (path 4):**

| Sub-block                                  | Bytes |
| ------------------------------------------ | ----- |
| Flags bit 0 check                          | 8     |
| Authority identity (HASH160 + EQUALVERIFY) | 5     |
| MPKH branch (authority flags bit 2)        | 150   |
| Single-sig branch wrapper (OP_IF chain)    | 10    |
| Anti-dust + owner + sat preserve           | 15    |
| Body marker 0xfeff check                   | 15    |
| §6 + §7.3 invocations                      | 10    |
| Output serialize + HashOutputs closure     | 50    |

Path 4 total: **~263b** (Phase 0 estimate 330b; savings from tighter byte-count accounting and marker-check consolidation).

`**OPEN QUESTION #5:**` §3.6 assumes the identity HASH160 match is against `owner_field_from_scriptCode`, but paths 4, 5, 6 need to match against `freezeAuthHash`, `confiscAuthHash`, `issuerPkh` respectively. The cleanest fix: DEFER the HASH160 identity check from PREFIX §3.6 into each path branch (paths 1, 2, 3 use owner; 4 uses freezeAuthHash; 5 uses confiscAuthHash; 6 uses issuerPkh). Current §3.6 budget (5b) is kept in PREFIX as "covenant CHECKSIGVERIFY done" placeholder, and per-path identity hashes are added 5b each into the path budget. Net impact: +20b (paths 3-6 each add 5b; path 1, 2 use owner identity already covered by the covenant-side pubkey slot, which is ambiguous). Documented; actual structure resolved in Phase 1 ASM.

### 5.5 Path 5 — confiscate (§9.5)

Shape is identical to path 4, with these differences:

- Flags bit 1 (confiscatable) instead of bit 0
- Identity match vs `confiscAuthHash` instead of `freezeAuthHash`
- MPKH branch flag bit 3 instead of bit 2
- Output marker 0x01ff (NormalBase) instead of 0xfeff (Frozen)
- Owner is ALLOWED to change (authority picks new owner)
- Tail otherwise preserved

Same byte shape as path 4 minus the "owner preserved" check: **~255b**.

### 5.6 Path 6 — redeem (§9.6)

Issuer-sig path. Produces P2PKH(redemptionPkh) at output 0 + 0..3 NormalBase remainders.

```
// Stack: ..., preimage, path_id == 6, extras:
//   p2pkh_redeem_satoshis
//   remainder_candidate_script_1..3  (R ∈ [0, 3])
//   remainder_candidate_satoshis_1..3
//   R (remainder count)
//   null_data? change?
//   funding_outpoint

// (1) Issuer identity:
<pubKey_from_unlocking>
OP_HASH160
<issuerPkh_from_tail_cache>
OP_EQUALVERIFY                                                    // 5b
// MPKH branch on flags bit 4:
<flags & 0x10 ... MPKH verify ...>                                 // ~150b

// (2) Output 0 = P2PKH(redemptionPkh):
//     Build expected scriptPubKey = OP_DUP OP_HASH160 OP_PUSH20 <redemptionPkh> OP_EQUALVERIFY OP_CHECKSIG
//     = 76 a9 14 <20b> 88 ac = 25 bytes
<redemptionPkh_from_tail_cache>
<0x76a914> OP_SWAP OP_CAT <0x88ac> OP_CAT                          // 15b
// output_0_serialized = p2pkh_redeem_satoshis (8b LE) ‖ 0x19 ‖ scriptPubKey
<p2pkh_redeem_satoshis>
<varint=0x19> OP_CAT OP_CAT                                         // 10b
// (3) Anti-dust on P2PKH:
OP_OVER <1> OP_GREATERTHANOREQUAL OP_VERIFY                         // ~5b (via altstack dup)

// (4) Remainder loop (unrolled × 3, R from unlocking, range [0, 3]):
<R> OP_DUP <0> <4> OP_WITHIN OP_VERIFY                              // 5b
// For each i in 1..3:
OP_DUP <i> OP_GREATERTHANOREQUAL OP_IF
  // pop remainder_candidate_script_i, remainder_candidate_satoshis_i
  // Anti-dust, body marker 0x01ff, §6 (h_NormalBase only), §7.3 tail match
  // Serialize remainder output → concat into output buffer
  <remainder per-iteration block>                                    // ~90b per iteration
  OP_ADD                                                              // accumulate Σ
OP_ENDIF
// × 3 iterations = ~270b

// (5) Conservation: p2pkh_satoshis + Σ remainder_satoshis == this.satoshis (from preimage cache)
<Σ> <p2pkh_redeem_satoshis> OP_ADD
<satoshis_from_preimage_cache> OP_EQUALVERIFY                        // ~10b

// (6) Append optional null-data / change to output buffer
<null-data / change branches>                                         // ~30b

// (7) HashOutputs closure
OP_HASH256 <hashOutputs_cache> OP_EQUALVERIFY                         // ~10b
```

**Budget (path 6):**

| Sub-block                                                            | Bytes          |
| -------------------------------------------------------------------- | -------------- |
| Issuer identity (HASH160 + EQUALVERIFY)                              | 5              |
| MPKH branch (flags bit 4)                                            | 150            |
| Branch wrapper                                                       | 10             |
| P2PKH output assembly                                                | 25             |
| P2PKH output serialize + anti-dust                                   | 15             |
| Remainder range check + loop header                                  | 10             |
| Remainder per-iteration (anti-dust + marker + §6 + tail + serialize) | ~90 × 3 = ~270 |
| Conservation check                                                   | 15             |
| Null-data / change append branches                                   | 30             |
| HashOutputs closure                                                  | 10             |

Path 6 total: **~540b** (Phase 0: 575b; minor savings from marker check consolidation).

### 5.7 Per-path output-marker gating summary (§7.2, S2 AMR #3)

| Path | Allowed target markers                                        | Allowed h_X values   |
| ---- | ------------------------------------------------------------- | -------------------- |
| 1    | 0x01ff                                                        | {h_NormalBase}       |
| 2    | 0x01ff (outputs); 0x01ff checked on anchor prev-tx output too | {h_NormalBase}       |
| 3    | 0x02ff                                                        | {h_NormalSwapOnRamp} |
| 4    | 0xfeff                                                        | {h_Frozen}           |
| 5    | 0x01ff                                                        | {h_NormalBase}       |
| 6    | (output 0 = P2PKH); 0x01ff for remainders                     | {h_NormalBase}       |

This is enforced inside each path's §6 invocation by passing a path-specific allowed-hash mask. The mask is typically 1 hash per path (single-template target). Mask dispatch is implemented as `OP_DUP <h_expected> OP_EQUAL` directly, avoiding the 4-hash OR-chain when possible. Small optimization: paths 1, 2, 5 all use h_NormalBase and can share one hash-match block within §6.

---

## 6. Output verification helper (§7) — shared across paths

Called per token-leg candidate output. Called from paths 1, 2 (anchor + follower), 3, 4, 5, 6.

```
// Input: candidate_scriptPubKey on stack, allowed_hash_mask (OR expected-body-marker) in operand slot
// Output: verified candidate is a legitimate series-member with correct marker

// (1) Peel off owner push (variable width) + action_data + OP_2DROP:
OP_DUP <1> OP_SPLIT                                               // first byte = push opcode
OP_SWAP OP_DUP <0x14> OP_EQUAL
OP_IF
  // P2PKH case: 20 more bytes
  OP_DROP <20> OP_SPLIT OP_NIP
OP_ELSE
  <0x4c> OP_EQUALVERIFY
  <1> OP_SPLIT OP_BIN2NUM OP_DUP OP_ROT OP_SPLIT OP_NIP
OP_ENDIF
// Stack: <action_data+2DROP+body>
<1> OP_SPLIT OP_SWAP <0x00> OP_EQUALVERIFY                        // action_data = OP_0 for Normal/NSO (other action_data sizes handled externally for Frozen/SwapReady targets)
<1> OP_SPLIT OP_SWAP <0x6d> OP_EQUALVERIFY                         // OP_2DROP

// (2) Body marker check (expected_marker passed in from path):
//     Body starts with `4c 02 <marker> 75` (5 bytes)
<5> OP_SPLIT OP_SWAP
<expected_marker_5b> OP_EQUALVERIFY                                // includes push wrapper + OP_DROP

// (3) Split body into PREFIX ‖ WHITELIST ‖ SUFFIX:
<PREFIX_remaining_len> OP_SPLIT                                     // split PREFIX_remaining (after marker)
OP_SWAP OP_TOALTSTACK                                               // stash PREFIX_remaining
<128> OP_SPLIT                                                      // WHITELIST | SUFFIX
// Stack: WHITELIST, SUFFIX

// (4) WHITELIST byte-match against this.WHITELIST (cached on altstack in §3.5):
OP_FROMALTSTACK                                                     // get this.WHITELIST (re-stash PREFIX_remaining first)
OP_EQUALVERIFY                                                      // 128-byte EQUALVERIFY

// (5) Reconstruct PREFIX_full = marker_bytes ‖ PREFIX_remaining:
OP_FROMALTSTACK                                                     // PREFIX_remaining
<marker_prefix_5b> OP_SWAP OP_CAT                                   // = full PREFIX bytes

// (6) Compute h_candidate = SHA256(PREFIX ‖ SUFFIX):
OP_SWAP OP_CAT                                                       // PREFIX ‖ SUFFIX
OP_SHA256                                                            // 32-byte h_candidate

// (7) Check h_candidate ∈ allowed_hashes:
//     For single-hash paths (paths 1, 3, 4, 5, 6): direct EQUALVERIFY against the one allowed hash.
//     For multi-hash cases (not used in NormalBase): OR-chain.
<allowed_hash_from_whitelist_slot>                                   // passed from path
OP_EQUALVERIFY
```

**Budget (§6):**

| Sub-block                                | Bytes |
| ---------------------------------------- | ----- |
| Owner push strip (P2PKH + MPKH branch)   | ~45   |
| Action data + OP_2DROP strip             | ~12   |
| Body marker 5-byte check                 | ~10   |
| PREFIX/WHITELIST/SUFFIX splits           | ~20   |
| WHITELIST byte-match (128b EQUALVERIFY)  | ~5    |
| PREFIX reconstruction + CAT              | ~10   |
| SHA256 + hash-match                      | ~10   |
| Plumbing (altstack stash/restore, SWAPs) | ~30   |

§6 body: **~142b**.

Plus a **~140b** for tail-consistency helper (§7.3, called alongside §6 by all same-token paths):

- Seven tail fields × ~15b/field = ~105b
- Varint handling for optionalData = ~30b

Shared section total: **~280b** (§6 + tail-match; Phase 0 had 280b for same bundle).

---

## 7. Anti-dust check

Per §15 resolved question #4: enforce `satoshis ≥ 1` per token-leg output.

```
<satoshis>
OP_DUP <1> OP_GREATERTHANOREQUAL OP_VERIFY
```

- 4 opcodes, ~5 bytes per invocation. Inlined per-output in §5.1 (×4), §5.2 (×K-1 anchor + ×1 follower), §5.3 (×1), §5.4 (×1), §5.5 (×1), §5.6 (×3+1 P2PKH).

Total inline cost counted inside each path's per-output block. No separate helper.

---

## 8. Size summary

| Section                                                                    | Bytes                              |
| -------------------------------------------------------------------------- | ---------------------------------- |
| **PREFIX (§3)**                                                            |                                    |
| Body marker 0x01ff                                                         | 5                                  |
| OP_PUSH_TX covenant                                                        | 350                                |
| Sighash-type check                                                         | 12                                 |
| Preimage parse                                                             | 180                                |
| ScriptCode extraction + cache (owner, WHITELIST, counterpartyScript, tail) | 180                                |
| Owner identity stub (see OPEN QUESTION #5)                                 | 5                                  |
| Path_id dispatcher (6 paths)                                               | 36                                 |
| **PREFIX subtotal**                                                        | **768**                            |
| **WHITELIST (§4)**                                                         |                                    |
| 128b placeholder + push wrapper + OP_DROP                                  | 131                                |
| **WHITELIST subtotal**                                                     | **131**                            |
| **SUFFIX per-path (§5)**                                                   |                                    |
| Path 1 — transfer/split                                                    | 500                                |
| Path 2 — merge-K (anchor + follower + shared A)                            | 1115                               |
| Path 3 — prepare-swap-transition                                           | 200                                |
| Path 4 — freeze                                                            | 263                                |
| Path 5 — confiscate                                                        | 255                                |
| Path 6 — redeem                                                            | 540                                |
| **Path subtotal**                                                          | **2873**                           |
| **SUFFIX shared (§6 + tail-match)**                                        |                                    |
| Output verification helper (§6)                                            | 142                                |
| Tail consistency helper (§7.3)                                             | 140                                |
| **Shared subtotal**                                                        | **282**                            |
| **GRAND TOTAL BODY**                                                       | **768 + 131 + 2873 + 282 = 4054b** |

### 8.1 Comparison to Phase 0 monolithic Normal (for sanity)

| Component | Phase 0 Normal | NormalBase (this doc) | Δ        |
| --------- | -------------- | --------------------- | -------- |
| PREFIX    | 703            | 768                   | +65      |
| WHITELIST | 99             | 131                   | +32      |
| Path 1    | 520            | 500                   | −20      |
| Path 2    | 1060           | 1115                  | +55      |
| Path 3    | 695            | 200                   | **−495** |
| Path 4    | 330            | 263                   | −67      |
| Path 5    | 320            | 255                   | −65      |
| Path 6    | 575            | 540                   | −35      |
| Shared §6 | 280            | 282                   | +2       |
| **Total** | **4582**       | **4054**              | **−528** |

Path 3 savings (~495b) are the main pivot win. The 128b whitelist (+32b) and merge-K shared-helper bump (+55b due to 128b-aware §6 plumbing) eat a bit back. Net savings: ~528b.

### 8.2 Honest verdict vs §12.1 spec target

| Aspect          | Spec §12.1 target | This doc's estimate | Δ          |
| --------------- | ----------------- | ------------------- | ---------- |
| NormalBase body | ~3000b            | **~4054b**          | **+1054b** |

**4054b is in the ABORT band (>3400b).** This is the same overall bloat shape Phase 0 surfaced for full Normal (~4640b), reduced proportionally by the path-3 savings. The fundamental pressure points remain:

1. **Merge-K path 2 = 1115b (27% of total body).** The anchor's 3-iteration unrolled reconstruction loop + output verification + conservation is irreducible at K=4. This alone locks NormalBase near 3000-3400b floor regardless of other optimizations.
2. **OP_PUSH_TX covenant = 350b (8.6%).** Inherited from DSTAS; can drop ~50-100b via Phase 4 optimization (shared across templates via OP_CODESEPARATOR per §15a #3) but not in Phase 0.1 pseudo-ASM.
3. **Path 6 redeem = 540b (13%).** Unrolled 3-remainder + issuer MPKH branch. Could drop K-remainder to 1 (no-remainder redeem only) saving ~180b, but that contradicts §9.6 semantics.
4. **Paths 4+5 = 518b (12.8%).** Each carries a full MPKH branch (~150b each = 300b of the 518b). Spec §8.2 requires MPKH support for authority. Cannot drop without spec change.

---

## 9. Assumptions & open questions

Carried from Phase 0 + new Phase 0.1:

`**OPEN QUESTION #1 (§3.5):**` WHITELIST altstack cache vs fresh-extract per §6 invocation. +12b one-time vs +30b per call. Keeping altstack cache (conservative). Phase 1 to measure real-world opcode counts.

`**OPEN QUESTION #2 (§3.8):**` Spec §12.1 estimates PREFIX ~1100b but splits per-path differently. This doc uses PREFIX-common (~768b) + separate path bodies. Interpretation is consistent with the "body total ≤ 3000b" gate; sub-column allocations are indicative only.

`**OPEN QUESTION #3 (§5.2):**` Anchor + follower branches could share prev-tx reconstruction helper via `OP_IF` fall-through. ~100-200b potential saving. Not included in this budget.

`**OPEN QUESTION #4 (§5.3):**` NSO body marker encoding must byte-match path 3's expected bytes. Locked normatively via SPEC AMENDMENT REQUEST #1 below.

`**OPEN QUESTION #5 (§5.4):**` §3.6 identity-hash check is owner-centric; paths 4, 5, 6 need authority/issuer identity. Net +20b (not in current PREFIX budget). Resolution: defer identity-hash to per-path body (already reflected in paths 4, 5, 6 totals).

`**OPEN QUESTION #6 (§5.3):**` Path 3 assumes owner CHECKSIG is fully handled by PREFIX §3.2 covenant + §3.6 identity. Verify no path-specific sig semantics (e.g., rate-limiting, timestamp) are needed. Spec §9.4.1 currently lists only owner sig + output/tail invariants, so this holds.

`**SPEC AMENDMENT REQUEST #1 (§5.3, §7.4):**` `BNTP_SERIES_V1_SPEC.md` §7.4 should explicitly require all series templates to emit their body marker via byte-identical `OP_PUSHDATA1 0x02 <marker_2b> OP_DROP` sequence (5 bytes, `4c 02 XX YY 75`). This enables §6's body-marker byte-match on candidate outputs without ambiguous encodings.

`**SPEC AMENDMENT REQUEST #2 (§8.2 verdict):**` The realistic NormalBase body size under the current feature set (6 paths including full K=4 merge + 3-remainder redeem + MPKH on all authority paths) is ~4000b, not ~3000b as spec §12.1 claims. Either (a) revise the G4 gate target to ≤ 4200b to match reality, OR (b) drop features: K=4→K=2 merge cap (~300b), remove MPKH branch (~450b), drop redeem remainders (~270b), paths 4+5 merge (~100b). See §8.2 for per-item savings. Recommendation: accept G4 PIVOT and drop K=4→K=2 (defers 3-way/4-way merge to v1.x).

`**SPEC AMENDMENT REQUEST #3 (§12.1 MPKH in body):**` Whether full MPKH authority branches MUST live inside NormalBase or can be delegated to a separate MPKH-only template variant. Deferring to NormalBase-MPKH would cut ~450b from NormalBase. Adds 1 template in whitelist (+32b across all templates). Net save ~400b at scale.

### Assumptions

1. Unlocking pushes FULL candidate locking scripts (S1 AMR #2 resolved in §15 #10).
2. BIP143 preimage byte offsets are fixed to BSV convention (hashPrevouts @ 4, thisOutpoint @ 68). Per §15a #4 — TODO in `BNTP_INVARIANTS.md`.
3. Owner for NormalBase is always single-PKH (20b); owner MPKH not supported in v1. Authority/issuer MPKH supported via flags.
4. Counterparty script extractability per `BNTP_ANCHOR_FOLLOWER_ALGORITHM.md` §7 assumption 2.
5. Body marker 0x01ff (NormalBase) emitted as `4c 02 01 ff 75` at body offset 0.
6. Per-path HASH160 identity dispatch deferred from PREFIX §3.6 to each path body (OQ #5).
7. Anti-dust `satoshis ≥ 1` inlined per-output; no separate helper.

---

## Gate verdict

**ABORT**

### Rationale

The NormalBase body estimate after the Option A pivot lands at **~4054b**, which is:

- **+1054b over the G4 PASS target of 3000b**
- **+854b over the G4 PASS-with-margin cap of 3200b**
- **+654b over the G4 PIVOT cap of 3400b**

Per `BNTP_CRITICAL_REVIEW.md` §5.1 and spec §12.1 budget gates, this places the design firmly in the **ABORT** band (> 3400b).

### Where the bloat lives (restating §8.2)

1. **Merge-K path 2 = 1115b (27%).** Unavoidable for K=4; even K=2-only is ~700b.
2. **OP_PUSH_TX covenant = 350b.** Inherited; not reducible in Phase 0.1.
3. **Path 6 redeem + paths 4/5 authority MPKH branches = ~1020b combined.** Required by spec §8.2, §9.6.
4. **Path 1 transfer/split = 500b.** Unrolled 4 outputs; halving to 2 outputs saves ~200b.
5. **Path 3 savings already realized** (695b → 200b) — no further easy wins there.

### Pivot proposal (per spec §12.1 PIVOT band)

**Feature-drop options to reach 3200b PASS-with-margin:**

| Drop                                            | Est. savings | New NormalBase | Breaks spec feature?                       |
| ----------------------------------------------- | ------------ | -------------- | ------------------------------------------ |
| K=4 → K=2 only in path 2                        | ~400b        | ~3650b         | §4.2 rule 1; revert to N-2 variant only    |
| Drop MPKH for authority (paths 4, 5)            | ~300b        | ~3750b         | §8.2                                       |
| Drop MPKH for issuer (path 6)                   | ~150b        | ~3900b         | §8.4                                       |
| Cap split to N=2 (path 1)                       | ~200b        | ~3850b         | §9.2 "Output count 1..4"                   |
| Redeem remainders → 0 (path 6 only emits P2PKH) | ~280b        | ~3770b         | §9.6 "optional NormalBase remainders 0..3" |
| **Combined (K=2 + no-MPKH-auth + split-N=2)**   | **~900b**    | **~3150b**     | Breaks §4.2, §8.2, §9.2                    |

**Combined save needed to reach PASS (3000b):** ~1050b. Requires dropping 3 features from above table (e.g., K=4, MPKH-auth, split-to-4).

### Recommendation to gate reviewer

Given the ABORT-band result, two viable responses:

1. **Accept PIVOT + scope reduction (preferred).** Revise spec §4.2 rule 1 to K ∈ [2, 2] for Phase 0.1 PoC (effectively 2-merge only), defer K ∈ [3, 4] to v1.x. Revise §9.2 "Output count 1..4" to "1..2" for Phase 0.1. Keep MPKH authority + issuer + redeem remainders as-is. Estimated new NormalBase body ≈ 3450b — still in PIVOT band (3200-3400b). One more cut needed: drop MPKH for issuer only (path 6) saves 150b → ~3300b → still PIVOT band. Probably requires dropping MPKH authority for one of {freeze, confisc} too. This accumulates into a meaningfully restricted Phase 0.1 PoC.

2. **Revise G4 target (spec amendment).** Accept that the current feature set cannot hit 3000b. Revise spec §12.1 NormalBase target to 4200b (realistic with all features). This matches what Phase 0 Normal showed (4640b was achievable with 6 paths; Option A brought it to 4054b). UTXO total would be ~4400b (body + tail + action_data) — still 30%+ over DSTAS 1.0.4's ~3050b. This means the "reduce per-UTXO bytes by ~20%" design goal (§1.4) is NOT met for NormalBase. Other templates (Frozen, SwapReady) still achieve significant savings; per-UTXO average across a portfolio may still meet the goal. Recommend an explicit budget revision discussion.

3. **Pursue Option B (drop prepare-swap entirely).** Moving prepare-swap out of NormalBase (Phase 0.1 pivot) only saves 495b; main bloat (merge-K + MPKH) is orthogonal. Option B doesn't help here.

### Gate verdict

**ABORT** relative to the G4 gate as specified (≤ 3400b).

Strongly recommend accepting SPEC AMENDMENT REQUEST #2 (revise G4 target to ~4200b) OR PIVOT via feature reduction (K=2-only merge + drop one MPKH branch). The current monolithic NormalBase + full feature set + BSV Script opcode costs are fundamentally incompatible with a 3000b body target.

Phase 0.1 NormalBase pseudo-ASM deliverable is complete. No implementation should proceed until gate verdict is reconciled with spec.
