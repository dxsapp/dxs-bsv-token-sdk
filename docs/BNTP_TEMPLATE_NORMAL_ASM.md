# BNTP Normal Template — Pseudo-ASM

Status: Phase 0 draft (slice S1). Not final — pseudo-ASM is opcode-level sketch, not implementable script. Byte counts are best-effort estimates derived from DSTAS 1.0.4 patterns minus optimizations in `DSTAS_LOCKING_SCRIPT_AUDIT.md` §5.

Covers: Normal template body only. Body = PREFIX ‖ WHITELIST ‖ SUFFIX between OP_2DROP and OP_RETURN (spec §5). Variable prefix (owner, action_data) and tail (seriesId, tokenId, …) are NOT part of the body but are discussed where the SUFFIX consumes them.

---

## 1. Overview

- **Target body size budget:** ≤ 2400 bytes (gate G1 PASS threshold per `slices.md`).
- **Sections:**
  - PREFIX (constant per template) — starts with body marker, holds covenant verification, preimage parse, path dispatcher, and the path-body opcodes that precede output verification.
  - WHITELIST (constant per series) — 96 bytes of 0x00 placeholder. Populated at series deployment with `h_Normal ‖ h_Frozen ‖ h_SwapReady`. Excluded from `h_Normal` computation (self-reference avoidance per spec §5.3).
  - SUFFIX (constant per template) — output reconstruction + whitelist byte-match + body-hash check + tail consistency + anti-dust + final covenant closure (`HASH256(reconstructed) == hashOutputs`).
- **Body marker:** `0x01 0xff` at offset 0 of PREFIX (spec §7.4). Present as two raw bytes (pushed as a 2-byte literal via `OP_PUSHDATA1 02 01 FF` or as the sequence `01 01 ff` — see Note-1 below).
- **Path_id range:** 1..6 for Normal (§9.1 table). Values 7, 8 belong to SwapReady/Contract and are rejected here.

**Note-1 (body marker encoding):** spec §7.4 says "body marker values are frozen at v1 spec lock". To be usable by the verification SUFFIX (which will `OP_DUP OP_SPLIT` the candidate body), the marker must appear as literal bytes at a fixed offset. The cleanest encoding is to emit the marker as a 2-byte DATA push `OP_PUSHDATA 0x02 0x01 0xFF` (`4c 02 01 ff`, 4 bytes on-chain) at the top of PREFIX, then immediately `OP_DROP` it. The script uses the marker ONLY during output verification on _candidate_ output scripts — it does not branch on its own marker. `**OPEN QUESTION:**` is 4 bytes total (push+drop) acceptable, or should we inline the marker as non-executable `OP_NOP`-padded data? Spec says "2b"; a push with explicit drop is closer to 4–5b. Budget assumes 5b (pushdata op + len + 2-byte marker + drop).

---

## 2. Variable prefix (before OP_2DROP) — not part of body

Not counted toward body size. Listed here for completeness (spec §5.1 + §5.2):

| Push             | Size                                                                                                        | Content                      |
| ---------------- | ----------------------------------------------------------------------------------------------------------- | ---------------------------- |
| Owner push       | 21 bytes for 20b PKH (`OP_PUSH20 ‖ pkh`) or 37..172 bytes for MPKH preimage (`OP_PUSHDATA1 LEN ‖ preimage`) | Spender identity             |
| Action data push | 1 byte (`OP_0`) for Normal                                                                                  | State discriminator = 0x00   |
| `OP_2DROP`       | 1 byte                                                                                                      | Drop the two variable pushes |

Total variable-prefix overhead for the common case (20b PKH, Normal): **23 bytes**, not counted in body.

---

## 3. PREFIX (start of body)

The PREFIX contains everything needed before output reconstruction: body-marker emission, covenant (OP_PUSH_TX), sighash type check, preimage parse, and path dispatch into per-path logic blocks. The per-path logic (paths 1..6) also sits in PREFIX, each gated by `OP_IF`; output verification is reused from SUFFIX.

### 3.1 Body marker (§7.4)

```
OP_PUSHDATA1 0x02 0x01 0xFF      // emit 2-byte marker 0x01FF as data
OP_DROP                           // marker not used at runtime in self-script
```

Bytes: **5** (1 pushdata op + 1 length + 2 marker + 1 drop).

### 3.2 OP_PUSH_TX covenant (inherited DSTAS pattern; spec §13)

The generator-point covenant pattern: signature with `r = G.x`, dynamic `s` computed from `HASH256(preimage)`, verified against one of two precomputed pubkeys `038ff83d…` / `023635…` with parity branching. Source of `~400b` in DSTAS.

```
// Target pubkey selection by s-parity (inherited from DSTAS)
... compute s from HASH256(preimage) ...
... construct DER-signature  r‖s  with appended sighashType=0x41 ...
OP_IF  <pubkey_even>  OP_ELSE  <pubkey_odd>  OP_ENDIF
OP_CHECKSIGVERIFY
```

Bytes (optimized per audit §5 — reusing DSTAS mechanics with hash-reversal elimination):

- Two embedded pubkeys: 2 × (push + 33) = 68
- DER construction (SPLITs, SIZE checks, CATs, 0x02/0x20 tags, sighash byte append): ~280
- CHECKSIGVERIFY: 1

Estimate: **~350b** (DSTAS had ~400b; removing 2 of the 4 hash-reversal blocks saves ~200b per audit §5.1.A, but much of that lived in preimage parsing/output reconstruction, not in the covenant itself — conservatively keep ~350b for the covenant block proper).

### 3.3 Sighash-type explicit check (§15 Q3, accepted)

```
<preimage>                        // already on stack from unlocking
OP_DUP                            // duplicate for subsequent parsing
OP_SIZE OP_SWAP                   // push size, move preimage under it
4 OP_SUB OP_SPLIT OP_NIP          // take last 4 bytes (sighashType LE)
0x41000000 OP_EQUALVERIFY         // expect SIGHASH_ALL | SIGHASH_FORKID = 0x41 LE
```

Bytes: **~12** (4 literal byte sighash push is 5b; the rest 7 ops). Budget: **12b**.

### 3.4 Path_id range check + dispatch

```
// Stack at this point: ..., preimage, path_id
OP_DUP OP_1 OP_6 OP_WITHIN OP_VERIFY   // Normal supports path_id ∈ [1, 5]... wait, [1, 6]
                                        // OP_WITHIN is [min, max), so need OP_7 as upper
OP_DUP OP_1 OP_7 OP_WITHIN OP_VERIFY   // correct: path_id ∈ {1,2,3,4,5,6}
```

Actual dispatch uses a chain of `OP_DUP OP_N OP_EQUAL OP_IF …` branches for paths 1..6, each calling shared sub-blocks.

Bytes:

- Range check: `OP_DUP OP_1 OP_7 OP_WITHIN OP_VERIFY` = 5b
- Dispatch chain (6 paths): each `OP_DUP OP_N OP_EQUAL OP_IF … OP_ENDIF` header = ~5b, × 6 = 30b
- Final `OP_DROP` (consume path_id after last branch) = 1b

Dispatcher overhead: **~36b**.

### 3.5 Common preimage parsing (inherited DSTAS pattern, optimized)

Extract from preimage: `version(4)‖hashPrevouts(32)‖hashSequence(32)‖outpoint(36)‖scriptCode(varint+N)‖satoshis(8)‖sequence(4)‖hashOutputs(32)‖locktime(4)‖sighashType(4)`.

DSTAS used ~300b here including all OP_SPLIT/OP_NIP/OP_SWAP chains, varint-skip for scriptCode. Audit §5.1.B saves ~60-80b via 4-byte-varint elimination; §5.1.A saves another ~200b if txid/hash endianness is kept native (spec assumes unlocking pushes BE, so these reversals can go).

Optimized estimate: **~180b** for parsing into named stack items:

- hashPrevouts (32)
- outpoint = prevoutTxid ‖ prevoutVout (36) — keep combined for merge position check
- scriptCode — used ONLY to extract owner field and WHITELIST reference; can be done once, not recomputed
- satoshis (8 LE)
- hashOutputs (32)

Bytes: **~180b** (vs DSTAS ~300b).

### 3.6 Owner field extraction from scriptCode (§9.2 check 5)

```
// From scriptCode (starts with OP_PUSH20 + 20b PKH for common case,
//                 or OP_PUSHDATA1 + len + preimage for MPKH)
// Pop first byte, branch on 0x14 (PUSH20) vs 0x4c (PUSHDATA1)
<scriptCode>
1 OP_SPLIT                        // separate first byte (push opcode)
OP_SWAP OP_DUP 0x14 OP_EQUAL
OP_IF                             // P2PKH case: next 20 bytes are owner_pkh
  OP_DROP 20 OP_SPLIT OP_SWAP OP_DROP  // stack: owner_20b, remaining_scriptCode
OP_ELSE                           // 0x4c: OP_PUSHDATA1, next byte = length
  0x4c OP_EQUALVERIFY
  1 OP_SPLIT                      // take length byte
  OP_BIN2NUM OP_DUP OP_SPLIT      // split length-of-preimage bytes
  ... hash preimage → owner_pkh ...
OP_ENDIF
```

Bytes: ~50b for the common P2PKH case plus ~70b MPKH branch = **~120b**.

### 3.7 PREFIX totals

| Sub-block                  | Bytes   |
| -------------------------- | ------- |
| Body marker                | 5       |
| OP_PUSH_TX covenant        | 350     |
| Sighash type check         | 12      |
| Path_id range + dispatch   | 36      |
| Preimage parse             | 180     |
| Owner field extract        | 120     |
| **PREFIX common subtotal** | **703** |

Per-path logic sits inside dispatch branches below but is budgeted in §5 (SUFFIX side) since output reconstruction dominates. PREFIX "common" total ≈ **~700b**.

---

## 4. WHITELIST placeholder

- **Size:** 96 bytes, hard-coded zeros at compile time.
- **Offset:** immediately after PREFIX (fixed).
- **Population:** at series deployment, replaced byte-wise with `h_Normal ‖ h_Frozen ‖ h_SwapReady`, each `h_X = SHA256(PREFIX_X ‖ SUFFIX_X)` per spec §5.3.
- **Encoding:** emitted as pure data via `OP_PUSHDATA1 0x60 <96 raw bytes> OP_DROP` so the 96 bytes are executable-context no-op data. Actual on-chain layout: `4c 60 <96B> 75` = **99 bytes**.
- **NOT included** in the `h_Normal` hash preimage (to break the self-reference loop; see `BNTP_WHITELIST_COMMITMENT_PROOF.md` (slice S2) for soundness argument).

`**OPEN QUESTION:**` Exact encoding choice — push+drop (99b) vs embedding in post-OP_RETURN tail (0b body, but requires every output-verification access to re-read past OP_RETURN). Budget uses push+drop (99b) because SUFFIX needs to SHA256 over (PREFIX ‖ SUFFIX) and will need to SKIP these 99 bytes by fixed offset. An alternative encoding as a series of three 32-byte pushes separated by `OP_DROP` is 3 × (33+1) = 102b. Pick 99b for budget.

**Total WHITELIST section: 99 bytes.**

---

## 5. SUFFIX — spend path dispatch + output verification

SUFFIX is invoked per path (from §3.4 dispatch). Most paths share a common output-verification sub-block (§6). This section walks each of the 6 Normal paths.

### 5.1 Path 1 — Transfer/split (§9.2)

**Inputs on stack (from unlocking, already below preimage):** N × output_tuple (satoshis, owner, action_data, body_marker), null-data push (optional), funding_txid, funding_vout.

```
// Dispatch: path_id == 1
// Assumes preimage already parsed (§3.5): hashOutputs, satoshis_in, owner_pkh on stack.

// Owner-sig path: verify sig was already covered by CHECKSIGVERIFY in §3.2
// Additionally verify HASH160(pubkey) == owner_pkh_from_scriptCode
<pubKey> OP_HASH160 <owner_pkh_from_scriptCode> OP_EQUALVERIFY          // 4b

// N loop — up to 4 outputs (spec §9.2 "Output count: 1..4")
//   Can't loop in Script → unrolled × 4 with early-exit via OP_IF chain
//   Each output:
//     - pop (satoshis, owner, action_data, body_marker)
//     - require body_marker == 0x01FF (Normal-only on path 1)
//     - build output_scriptPubKey = owner_push ‖ action_data_push ‖ OP_2DROP ‖ body_marker ‖ PREFIX ‖ WHITELIST ‖ SUFFIX ‖ OP_RETURN ‖ tail
//     - emit output_scriptPubKey into a running CAT buffer
//     - accumulate satoshis_out + check satoshis ≥ 1 (anti-dust §7)
//     - run output-verification sub-block (§6) = body-hash check + whitelist-match

// Each of 4 output branches: ~180b (tuple pop + body_marker check + assembly + conservation add + anti-dust).
// Shared PREFIX/WHITELIST/SUFFIX push bytes: the template body itself embeds them as constants.
//   Emitting the constants into a candidate output requires either (a) pushing a constant copy
//   again as explicit data, or (b) using OP_CODESEPARATOR trickery (fragile — avoided).
//   Budget option (a): hardcoded data pushes of known-good PREFIX/SUFFIX are 2 × ~2 × 1050b... NO — would blow budget.
//   Correct approach: the template DOES NOT rebuild the full target script.
//     It instead relies on output-verification sub-block (§6), which runs on the ACTUAL bytes
//     that hashOutputs covers. Unlocking pushes the candidate output scripts in full; the SUFFIX
//     checks them structurally (whitelist byte-match + body hash against embedded whitelist).

// Revised path 1 (unlocking pushes candidate output scripts in full, not fragments):
//   for each output i:
//     pop candidate_scriptPubKey (full locking script of the i-th token-leg output)
//     pop candidate_satoshis
//     run §6 output verification on candidate_scriptPubKey   // whitelist match + h_X check
//     require body_marker prefix in candidate == 0x01FF      // Normal-only
//     require tail fields match this.tail (§7.3)
//     accumulate Σsats_out, check ≥1
```

Revised Path 1 budget (per output iteration): ~120b (without §6, which is shared).

- Candidate scriptPubKey pop + structural split: 30b
- body_marker check (Normal-only): 6b
- §6 invocation (inlined, see §6): 0b here (counted once in §6)
- tail field match (owner-managed paths): ~50b (call into §7.3 helper)
- anti-dust + conservation: ~8b per output
- Pushdata-varint decoding for candidate script length: ~15b (reused)

Path 1 per-output: **~110b**, × 4 (unrolled for split 1→4) = **~440b**.

Plus:

- Null-data optional output handling: 30b
- Change output handling (P2PKH/P2MPKH): 40b
- Final conservation: `Σ satoshis_out == satoshis_in` → 4b

Path 1 total: **~520b**.

### 5.2 Path 2 — Merge-K (§9.3)

This slice defers the anchor/follower position-determination algorithm to slice S3 (`BNTP_ANCHOR_FOLLOWER_ALGORITHM.md`). From this doc's perspective, path 2 has the following script structure (shown as where-to-hook):

```
// Stack: preimage, followerCount, all_input_outpoints (36b × K), selfPosition/anchor-data, ...
// followerCount ∈ [1, 3] only on anchor path; followers push selfPosition ∈ [1, 3].

// (A) Input position determination — see S3
//   Verifies: HASH256(all_input_outpoints ‖ funding_outpoint) == hashPrevouts (from preimage)
//   Extracts: this.outpointIndex ∈ [0, K-1]
//   Branches: if index == 0 → anchor; else → follower

OP_IF   // anchor branch
  // For each i in 1..followerCount (unrolled for K ∈ {2,3,4} → up to 3 iterations):
  //   Reconstruct follower_i_prev_tx from pieces ‖ this.counterpartyScript
  //     (counterparty-script extraction inherited DSTAS pattern — §6 calls SHA256 over
  //      extracted slice to verify match; see S3 for exact reconstruction loop)
  //   HASH256(reconstructed) == hashPrevouts.txid[i]
  //   Extract output at follower_i_mergeVout → scriptPubKey + satoshis
  //   Run §6 output-verification on that scriptPubKey (verifies Normal same-series)
  //   Verify tail fields match (same tokenId, redemptionPkh, issuerPkh, authority, optionalData)
  //   Accumulate satoshis_follower_i
  // Conservation: Σ (this.sat + Σ sat_follower_i) == Σ sat_out
  // Output verification: up to 2 Normal outputs (merge N→1..2, spec §9.3)
OP_ELSE  // follower branch
  // Reconstruct anchor_prev_tx from pieces ‖ this.counterpartyScript
  // HASH256(reconstructed) == hashPrevouts.txid[0]
  // Extract anchor's output at anchor_mergeVout → verify Normal same-token
  // No conservation — delegate to anchor
  // Still verify owner sig (done in §3.2 + §3.6)
OP_ENDIF
```

**Budget (path 2):**

- S3 hook (anchor/follower determination): ~100b per §9.3.17 "trusted only because its hash matches hashPrevouts"
- Anchor reconstruction × 3 (unrolled for K up to 4, each iteration branches on followerCount):
  - counterparty-script reconstruction from pieces (DSTAS-inherited, ~200b per iteration but much shared across iterations via a single unrolled helper)
  - hashPrevouts.txid[i] verification: 40b
  - merge-vout extraction + §6 call: ~80b
  - tail-match per follower: 50b
  - total per-iteration: ~150b × 3 = 450b
- Follower branch: 1 reconstruction ~200b + hash-check 40b + §6 call 80b + tail-match 50b = **~370b**
- Branch merge + output verification for up to 2 Normal outputs (merges can output 1 or 2 legs): 2 × 110b = 220b
- Conservation check: 20b

Path 2 total: **~1060b** (both anchor and follower branches both present; only one runs per invocation, but both are in the body).

`**OPEN QUESTION:**` Is there a way to share the reconstruction helper between anchor and follower via `OP_IF` fall-through? DSTAS does partial sharing. If yes, save ~100-200b. Budget assumes NO sharing (conservative).

### 5.3 Path 3 — Prepare-swap with issuer attestation (§9.4)

Per spec §9.4 this path is the biggest within Normal because it adds issuer-attestation verification on top of the output reconstruction.

```
// Stack: preimage (parsed), owner_pkh, swap_output_tuple (sat, owner, descriptor 62b, marker 0xFEFF... wait, 0x0FFF for SwapReady)
// + issuer_pubkey, issuer_attestation_sig, attestation_timestamp (8b LE),
// + royalty_satoshis, funding_outpoint, null-data?

// (1) Owner sig — already verified via CHECKSIGVERIFY in §3.2 + §3.6

// (2) Reconstruct attestation_msg = tokenId(32) ‖ thisOutpoint(36) ‖ timestamp(8)
<tokenId_from_own_tail>            // read from own scriptCode — see note below
<outpoint_from_preimage>           // already on stack
<attestation_timestamp>            // from unlocking
OP_CAT OP_CAT                       // → 76-byte msg
OP_HASH256                          // → 32-byte attestation_hash

// (3) Check issuer identity
<issuer_pubkey> OP_HASH160
<issuerPkh_from_own_tail>            // read from own scriptCode
// If flags bit 4 (MPKH issuer) → branch:
<flags_from_own_tail> 0x10 OP_AND
OP_IF    // MPKH path
  // mpkh_preimage already on stack in lieu of issuer_pubkey
  OP_HASH160 OP_EQUALVERIFY
  // parse m from preimage[0], parse n from preimage[-1]
  // OP_CHECKMULTISIGVERIFY against preimage-derived pubkey set + attestation_hash
OP_ELSE  // single-sig path
  OP_EQUALVERIFY
  // CHECKSIGVERIFY against attestation_hash
  // BSV doesn't CHECKSIG over arbitrary hash directly — need generator-point trick
  // Budget: ~200b for "CHECKSIG-over-arbitrary-msg" pattern
OP_ENDIF

// (4) Output verification — exactly 1 SwapReady output (body_marker 0x0FFF)
//   Reuse §6 with marker-match == 0x0FFF
//   Verify: swap_descriptor 62b, first byte 0x01, requestedScriptHash 32b,
//           requestedPkh 20b, rateNum 4b, rateDenom 4b, reserved 1b = 0x00
//   Verify: swap_output_satoshis == this.satoshis (no value transfer)
//   Verify: owner preserved, same token

// (5) Royalty output: find output at index ≥1 with scriptPubKey = P2PKH(issuerPkh),
//     satoshis ≥ royaltyMin (embedded constant, §15 Q9)
//   This requires scanning the hashOutputs reconstruction for a matching output.
//   Since we rebuild hashOutputs from pushed outputs anyway, budget ~60b for the scan.

// (6) HashOutputs covenant closure — §6
```

**Budget (path 3):**

- Issuer identity check (both paths): 30b common + 200b single-sig attestation-sig verify (CHECKSIG-over-arbitrary-msg via generator-point construction) + 150b MPKH branch = ~380b
- Attestation message build + HASH256: 15b
- Tail-field reads (tokenId, issuerPkh, flags): need to access bytes AFTER OP_RETURN in this UTXO's scriptCode — that's in scriptCode extraction: ~50b
- SwapReady output verification (§6 + marker + descriptor): ~170b
- Royalty output detection: 60b
- Owner preserved + satoshis preserved: 20b

Path 3 total: **~695b**.

`**SPEC AMENDMENT REQUEST:**` Spec §9.4 requires CHECKSIG against `attestation_hash` (arbitrary message), which is not a native Bitcoin opcode — Script's `OP_CHECKSIG` always hashes the preimage internally. BNTP needs a second generator-point-style covenant _just for the attestation_: compute `s` from `attestation_hash` + fixed `r`, build DER, run CHECKSIGVERIFY against `issuer_pubkey`. Budget adds ~200b for this second generator-point block. Consider whether spec §9.4 step 8 should document this explicitly or whether a simpler scheme (e.g., attestation is over the full preimage with some tokenId binding in the preimage's nullData output) would save bytes.

### 5.4 Path 4 — Freeze (§9.5)

```
// Stack: auth_pubkey, auth_sig, preimage, funding_outpoint, null-data?, frozen_output_tuple

// (1) Check flags bit 0 (freezable)
<flags_from_own_tail> 0x01 OP_AND OP_VERIFY    // 6b

// (2) Authority sig check against freezeAuthHash
<auth_pubkey> OP_HASH160
<freezeAuthHash_from_own_tail> OP_EQUALVERIFY
// auth_sig already verified via CHECKSIGVERIFY in §3.2 — covered.
// OR MPKH branch if flags bit 2 — ~150b

// (3) Exactly 1 Frozen output (body_marker 0xFEFF):
//   Run §6 with marker-match == 0xFEFF
//   Verify owner/satoshis/tail unchanged (same-token)

// (4) HashOutputs covenant closure — §6
```

Budget:

- Flags check: 6b
- Authority identity + single-sig/MPKH branch: 30b + 150b = 180b
- Output verification (§6 call + marker + tail preservation): 130b
- Owner unchanged check: 10b

Path 4 total: **~330b**.

### 5.5 Path 5 — Confiscate (§9.5)

Similar shape to path 4, but uses confiscation authority and allows owner change. Roughly identical size.

```
// (1) Check flags bit 1 (confiscatable)
<flags_from_own_tail> 0x02 OP_AND OP_VERIFY

// (2) Authority check vs confiscAuthHash (MPKH branch on flags bit 3)

// (3) Exactly 1 Normal output (marker 0x01FF), satoshis preserved, new owner free

// (4) §6 closure
```

Path 5 total: **~320b**.

### 5.6 Path 6 — Redeem (§9.6)

```
// Stack: issuer_pubkey, issuer_sig, preimage, funding_outpoint, null-data?,
//        Normal_remainder_tuples × (0..3), p2pkh_sats

// (1) Issuer identity (§8.4): HASH160(issuer_pubkey) == issuerPkh (or MPKH branch on flags bit 4)

// (2) Output 0 = P2PKH(redemptionPkh)
//   Build scriptPubKey = OP_DUP OP_HASH160 0x14 <redemptionPkh_from_own_tail> OP_EQUALVERIFY OP_CHECKSIG
//   Emit into hashOutputs buffer

// (3) Outputs 1..R (R ∈ 0..3): Normal, same token (§6 + marker 0x01FF + tail-match)
//   Each remainder: ~110b (like path 1)

// (4) Σ (p2pkh_sats + Σ remainder.sat) == this.satoshis

// (5) §6 closure
```

Budget:

- Issuer identity (single-sig + MPKH): 180b (same as path 4 authority)
- P2PKH output build: 50b (standard P2PKH layout with redemptionPkh from tail)
- Remainder outputs × 3 (unrolled, optional): 3 × 110b = 330b — but only one unrolled block with 3 early-exits
- Conservation: 15b

Path 6 total: **~575b**.

---

## 6. Output verification sub-block (§7) — shared across paths

This is the most byte-heavy shared helper. Called per candidate token-leg output.

```
// Input: candidate_scriptPubKey on stack
// Output: verified membership in {Normal, Frozen, SwapReady}, tail-consistent

// (1) Extract owner push + action_data push + OP_2DROP marker
//     variable-width pops — requires pushdata-length decoding (DSTAS-inherited)
OP_DUP 1 OP_SPLIT                       // first byte = push opcode (0x14 or 0x4c...)
... decode owner push length ...        // ~15b (4-byte varint branch removed per audit §5.1.B)
OP_DUP 0x6d OP_EQUALVERIFY             // expect OP_2DROP (0x6d) after pushes
1 OP_SPLIT OP_NIP                      // consume 2DROP
// Now stack has the body (starts with body_marker)

// (2) Read body_marker (2 bytes)
2 OP_SPLIT OP_SWAP                     // marker, body_without_marker
OP_DUP <expected_marker> OP_EQUALVERIFY  // path-specific expected marker

// (3) Extract PREFIX (fixed length given marker → template identified)
//     Since WHITELIST is at a known fixed offset from body start (post-PREFIX),
//     split body at offset (PREFIX_len + 96) to get PREFIX‖WHITELIST | SUFFIX
<PREFIX_len> OP_SPLIT                  // PREFIX | (WHITELIST ‖ SUFFIX)
OP_SWAP                                // save PREFIX
96 OP_SPLIT                            // WHITELIST | SUFFIX

// (4) Whitelist byte-match: candidate.WHITELIST == this.WHITELIST
<this_WHITELIST_96b_constant>          // read from own scriptCode (offset known)
OP_EQUALVERIFY                         // 96-byte compare

// (5) Compute h_candidate = SHA256(PREFIX ‖ SUFFIX) — exclude WHITELIST
OP_SWAP OP_CAT                         // reattach PREFIX‖SUFFIX
OP_SHA256                              // 32 bytes

// (6) Check h_candidate ∈ {h_Normal, h_Frozen, h_SwapReady}:
//   Read 3 hashes from this.WHITELIST (already on stack as constant):
OP_DUP <h_Normal_from_whitelist> OP_EQUAL
OP_SWAP <h_Frozen_from_whitelist> OP_EQUAL
OP_BOOLOR
OP_SWAP <h_SwapReady_from_whitelist> OP_EQUAL
OP_BOOLOR
OP_VERIFY

// (7) Tail consistency (§7.3):
//   Extract tail from scriptCode — seriesId, tokenId, redemptionPkh, issuerPkh,
//   authFlags, freezeAuth, confiscAuth, optionalData.
//   Compare byte-exact to this.tail read from own scriptCode (same offsets).
//   Exception: swap-exec allows different tokenId — not in Normal.
```

**Budget:**

- Owner/action_data/2DROP extraction: 35b
- Body marker check: 10b
- PREFIX/WHITELIST/SUFFIX splits: 15b
- Whitelist byte-match (96-byte EQUALVERIFY): 5b (3-byte push of length + OP_EQUALVERIFY — the literal 96 bytes come from already-on-stack `this.WHITELIST`, which is part of own scriptCode, extracted once and cached)
- SHA256 of PREFIX‖SUFFIX: 5b
- Hash-in-3-set check: 15b
- Tail consistency (7 fields × ~15b per field = 105b, with varint-handling for optionalData ~30b): **135b**
- Caching `this.WHITELIST` + `this.tail` from own scriptCode (done once at PREFIX time, ~60b)

§6 body total: **~280b** (excluding per-path invocation overhead).

Since §6 is referenced by paths 1, 2 (anchor × K), 3, 4, 5, 6 but the code is physically once in SUFFIX, count **280b once**.

---

## 7. Anti-dust check (§15 Q4)

```
<candidate_satoshis>
OP_DUP 1 OP_GREATERTHANOREQUAL OP_VERIFY  // require sats ≥ 1
```

4 opcodes, 4 bytes per check. Invoked per token-leg output. Included inline in §5.1/5.2/5.3/5.4/5.5/5.6 per-output iteration budgets (already counted at ~4-8b each).

---

## 8. Size summary

| Section                                    | Bytes                     |
| ------------------------------------------ | ------------------------- |
| **PREFIX common (§3)**                     |                           |
| Body marker                                | 5                         |
| OP_PUSH_TX covenant                        | 350                       |
| Sighash type check                         | 12                        |
| Path dispatcher                            | 36                        |
| Preimage parse                             | 180                       |
| Owner field extract                        | 120                       |
| Scriptcode tail cache                      | 60                        |
| **PREFIX subtotal**                        | **763**                   |
| **WHITELIST (§4)**                         |                           |
| 96-byte placeholder + push/drop            | 99                        |
| **WHITELIST subtotal**                     | **99**                    |
| **SUFFIX path-specific (§5)**              |                           |
| Path 1 — transfer/split                    | 520                       |
| Path 2 — merge-K (anchor+follower+S3 hook) | 1060                      |
| Path 3 — prepare-swap + issuer attestation | 695                       |
| Path 4 — freeze                            | 330                       |
| Path 5 — confiscate                        | 320                       |
| Path 6 — redeem                            | 575                       |
| **Path subtotal (all 6)**                  | **3500**                  |
| **SUFFIX shared (§6)**                     |                           |
| Output verification helper                 | 280                       |
| **Body SHARED total**                      | **763 + 99 + 280 = 1142** |
| **All paths total**                        | **3500**                  |
| **GRAND BODY TOTAL**                       | **~4642 bytes**           |

---

## 8a. Size verdict against budget

Budget: ≤ 2400b → gate G1 PASS threshold.
Raw estimate: **~4640b**. This is **~2× the budget**.

### Where the bloat lives

1. **Path 2 (merge-K): 1060b** — anchor+follower + reconstruction loop (up to 3 followers). Biggest single line item.
2. **Path 3 (prepare-swap): 695b** — issuer attestation requires a second generator-point-style CHECKSIG over an arbitrary hash.
3. **Path 6 (redeem): 575b** — unrolled 3 remainders.
4. **Path 1 (transfer/split): 520b** — unrolled 4 outputs.

### Optimization levers (Phase 1 work, not Phase 0)

- **Share output-verification helper across all 4 Normal outputs in path 1 via a tight unrolled micro-helper** — saves ~100-200b (currently counted per-output).
- **Merge path 4 + path 5 branches** — both are "1 output, authority sig, preserve sats" with minor diffs. Save ~100-200b.
- **Merge path 1 output-loop with path 6 remainder-loop** — both emit Normal outputs. Save ~200-300b.
- **Defer prepare-swap to a separate template** — spec §3 treats prepare-swap as on Normal, but moving it to a dedicated "NormalSwappable" template (or even requiring the token to transition Normal → SwapReady-only via a distinct path owned by a separate script) removes ~700b from Normal. See pivot proposal below.
- **Drop MPKH branch support in Normal authority/issuer paths** — would break §8.2 / flags bits 2/3/4 but saves ~400b. NOT recommended (spec explicit).
- **Shared reconstruction helper between anchor and follower in path 2** — save ~200b (already flagged as OPEN QUESTION in §5.2).

Realistic target after Phase 1 optimization: **~3600-3800b**, still above the 2400b budget.

---

## 9. Assumptions & open questions

`**OPEN QUESTION #1:**` Body-marker encoding — push+drop (5b) vs inline non-executable bytes. §1 Note-1.

`**OPEN QUESTION #2:**` WHITELIST encoding — push+drop (99b) vs three 32-byte pushes (102b) vs pre-OP_RETURN inline. §4.

`**OPEN QUESTION #3:**` Can §5.2 share reconstruction helper between anchor and follower branches via OP_IF fall-through? Potential savings ~200b. §5.2.

`**OPEN QUESTION #4:**` §5.3 / path 3 issuer attestation — spec §9.4 says "CHECKSIGVERIFY against attestation_hash". Bitcoin Script doesn't support CHECKSIG-over-arbitrary-message natively; requires a second generator-point covenant block (~200b). Is there a cheaper scheme that binds tokenId/outpoint/timestamp into the normal preimage-covered data somehow (e.g., require a specific null-data output encoding tokenId‖timestamp, and check that output's bytes are consistent with the claimed attestation)? Would save ~200b if feasible. Flagged as **SPEC AMENDMENT REQUEST** in §5.3.

`**OPEN QUESTION #5:**` Royalty minimum — spec §15 Q9 defers. If embedded as a template-body constant, that's another 9b (push op + 8b varint). Budget assumes 9b (absorbed into path 3's ~695b estimate).

`**SPEC AMENDMENT REQUEST #1:**` §9.4 step 8 should either document the generator-point pattern for attestation-hash signing, OR redesign the attestation mechanism to sit inside the normal preimage covenant (e.g., require a null-data output `OP_FALSE OP_RETURN <tokenId> <outpoint> <timestamp>` that the issuer's sighash-covered signature implicitly commits to). The latter eliminates the need for a second CHECKSIG pattern.

`**SPEC AMENDMENT REQUEST #2:**` §9.2 unlocking format: current spec says output tuples are `[satoshis, owner_field, new_action_data, body_marker]` — but for whitelist+body-hash verification (§7) to work, the SUFFIX needs the FULL candidate locking script bytes, not tuple components. The tuple-vs-full-script decision significantly affects size. Recommend spec be explicit that unlocking pushes full candidate scripts; the SDK builder derives them from (owner, action_data, this_body, this_tail) — see §5.1 note inside doc.

`**SPEC AMENDMENT REQUEST #3:**` Spec §5 / §7 does not mandate an offset for WHITELIST within body. Making WHITELIST always at offset `(|PREFIX|, |PREFIX|+96)` is implicit — recommend spec lock this offset as a normative rule.

---

## Gate verdict

**PIVOT**

### Rationale

The pseudo-ASM estimate for a single `Normal` template supporting all 6 spend paths (transfer/split, merge-K with K∈[2,4], prepare-swap with issuer attestation, freeze, confiscate, redeem) lands at **~4640b**, nearly 2× the 2400b budget. Even with the aggressive Phase 1 optimizations listed in §8a (combining output loops, sharing reconstruction helpers, eliminating redundant endian flips), the realistic floor is ~3600b — still 50% over budget.

The three biggest line items are:

1. **Merge-K logic (~1060b)** — both anchor and follower in one template. Unavoidable if single Normal supports merge at all; spec §3.2 explicitly chose single-variant Normal over Normal-K split.
2. **Prepare-swap with issuer attestation (~695b)** — the dual-CHECKSIG requirement (owner + issuer-over-arbitrary-hash) is inherently expensive. Moving this to a dedicated template removes it from Normal.
3. **Authority paths (freeze + confiscate, ~650b combined)** — shared logic between them; could merge to save ~150b.

### Concrete pivot proposal

**Split Normal into two templates:** `NormalBase` (paths 1, 2, 4, 5, 6) and `NormalSwapOnRamp` (path 3 only). Delta estimate:

| Template           | Paths            | Est. body                                                                           |
| ------------------ | ---------------- | ----------------------------------------------------------------------------------- |
| `NormalBase`       | 1, 2, 4, 5, 6    | ~3200b (− path 3 = 695b, +50b extra dispatch trimming from 6→5 paths)               |
| `NormalSwapOnRamp` | 3 (prepare-swap) | ~1300b (PREFIX-common 763b + WHITELIST 99b + path 3 695b − dispatch overhead saved) |

Both templates exceed 2400b individually but are closer to budget. `NormalBase` at ~3200b implies the merge-K anchor+follower block alone consumes ~1/3 of the budget. Further reduction would require:

- Splitting merge-K anchor and follower into separate templates (anchor-only `NormalMerge4Anchor`, follower-only `NormalMerge4Follower`), with type discrimination at unlocking time.
- Capping merge at K=2 (lose K=3,4 support). Reduces §5.2 by ~400b. Combined with above → `NormalBase` ~2600-2800b, still over budget.

**Realistic outcome:** the 2400b budget as stated in `slices.md` is **likely not achievable** for a monolithic Normal supporting all 6 paths, even with aggressive optimization. A more realistic budget is **~3000-3200b per Normal variant**, with the swap on-ramp factored out.

### Recommendation to gate reviewer

Accept a PIVOT that:

1. Moves prepare-swap (path 3) out of Normal into a dedicated transition template.
2. Refines the size budget on `BNTP_CRITICAL_REVIEW.md` to reflect ~3000b for `NormalBase`.
3. Defers the "~2000b body" claim in spec §12.1 to a post-optimization Phase 4 goal, not a Phase 0 gate.

If the reviewer rejects the pivot and insists on 2400b per template, the only viable path is to drop path 3 entirely from Normal (swap on-ramp becomes a separate `SwapContract` template, entered via explicit tx), which is effectively the same pivot.

**Gate verdict: PIVOT.** Phase 0 S1 deliverable is complete, but the size budget fails and a scope-reduction decision is required before Phase 1 PoC implementation.
