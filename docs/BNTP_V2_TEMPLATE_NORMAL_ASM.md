# BNTP v2 Normal Template — Pseudo-ASM

**Status:** Phase 0 v2 draft. Opcode-depth pseudo-ASM with careful byte counting for the BNTP v2 Normal template body. Derived by diff against v1 NormalBase (`BNTP_TEMPLATE_NORMALBASE_ASM.md`, 4054b) with v2 spec (`BNTP_V2_SPEC.md`) semantics overlaid.

**Scope:** Normal body only — from first byte after `OP_2DROP` to `OP_RETURN`. Variable prefix (owner push + action_data) and tail (111b fixed + optionalData) are not part of the body but are referenced by the SUFFIX.

---

## 1. Overview

- **Target body (G5 gate, v2):** ≤ 2000b PASS, ≤ 2300b PASS-with-margin, 2300-2800b PIVOT, > 2800b ABORT.
- **Body marker:** `0x01 0xff` (Normal). Emitted via `OP_PUSHDATA1 0x02 0x01 0xff OP_DROP` = 5 bytes at body offset 0 (§5 of spec, unchanged convention vs v1).
- **Paths (4, not 6):**
  1. **flex-transfer** — unified N→M owner spend, amount conservation in-script, depth `max(inputs)+1`.
  2. **refresh** — owner + issuer attestation, exactly 1 input → exactly 2 Normal outputs (user + royalty), depth reset to 0.
  3. **freeze** — freezeAuth sig, exactly 1 Frozen output (marker `0xfeff`), depth preserved.
  4. **confiscate** — confiscAuth sig, exactly 1 Normal output, new owner, depth reset to 0.
- **No path 5 (redeem)** — spec §9.6 end decision: collapse redeem into flex-transfer to issuer's owner. No `redemptionPkh` in tail. (If that decision ever reverses, a path 5 clone of path 4's shape plus P2PKH output adds ≈ 200-300b.)
- **Key deltas vs v1 NormalBase:**
  - NO WHITELIST block (−131b body; −128b data; no §6 hash-match plumbing).
  - NO anchor/follower (merge-K path 2) — replaced by pushed `amounts_in_array` + `all_input_outpoints` bound via `hashPrevouts` (−~700b).
  - NO redeem path (−540b).
  - NEW amount-in-tail conservation: extract 16b uint128 from tail, sum inputs (pushed), sum outputs, compare (+~150b across path 1).
  - NEW depth counter logic: extract uint16 from tail, verify `new_depth ≥ max_input_depth + 1` in path 1; `= 0` in paths 2 and 4; `= my_depth` in path 3 (+~50b).
  - NEW MPKH owner (flag bit 5) — owner identity may be 20b PKH OR `HASH160(MPKH preimage)` with m-of-n CHECKMULTISIGVERIFY (+~30b in owner branch, vs v1 owner-always-PKH).

### 1.1 Path dispatcher

Path_id is pushed by unlocking (per §9.1 common stack layout). Normal supports {1, 2, 3, 4}. Path_id 5 (redeem) and 6 (contract issue) are out of scope here; dispatcher range-check is `[1, 4]`.

```
OP_DUP <1> <5> OP_WITHIN OP_VERIFY                 // path_id ∈ [1, 4]
OP_DUP <1> OP_EQUAL OP_IF  ...§4.1... OP_ENDIF
OP_DUP <2> OP_EQUAL OP_IF  ...§4.2... OP_ENDIF
OP_DUP <3> OP_EQUAL OP_IF  ...§4.3... OP_ENDIF
OP_DUP <4> OP_EQUAL OP_IF  ...§4.4... OP_ENDIF
OP_DROP
```

Range check 5b + 4 × 5b dispatch headers + 1b trailing drop = **~26b** (vs v1's 36b for 6 paths; saves 10b).

---

## 2. Variable prefix (before OP_2DROP) — not part of body

| Push             | Size                             | Content             |
| ---------------- | -------------------------------- | ------------------- |
| Owner push       | 21b (20b PKH) or 37..172b (MPKH) | Spender identity    |
| Action data push | 1b (`OP_0` for Normal)           | State discriminator |
| `OP_2DROP`       | 1b                               | Drop both           |

Common PKH case: **23b**, not counted in body. Note v2 adds owner-MPKH as a first-class option (flag bit 5 in tail); encoding shape is the same `OP_PUSHDATA1 <len> <mpkh_preimage>`.

---

## 3. PREFIX (common across paths)

### 3.1 Body marker `0x01 0xff`

```
OP_PUSHDATA1 0x02 0x01 0xFF OP_DROP
```

- `4c 02 01 ff 75` = **5b** (same as v1).

### 3.2 OP_PUSH_TX covenant

Standard generator-point covenant (identical to v1 §3.2; DSTAS pattern). Dynamic `s` from `HASH256(preimage)`, DER assembly, parity-branched pubkey, `OP_CHECKSIGVERIFY`.

- Two embedded pubkeys: 2 × 34 = 68b
- DER construction (SPLITs, SIZE, tags, sighash append): ~280b
- CHECKSIGVERIFY: 1b

Subtotal: **~350b**.

### 3.3 Sighash-type explicit check (`== 0x41`)

```
<preimage last 4 bytes> <0x41000000> OP_EQUALVERIFY
```

- Extract last 4 bytes: `OP_SIZE OP_SWAP 4 OP_SUB OP_SPLIT OP_NIP` = 6b + 5b literal push = 11b; EQUALVERIFY 1b.

Subtotal: **12b**.

### 3.4 Preimage parse

Extract and cache:

- `hashPrevouts` (32b @ offset 4)
- `thisOutpoint` (36b @ offset 68)
- `scriptCode` (varint-prefixed @ offset 104+)
- `satoshis` (8b LE, after scriptCode end)
- `hashOutputs` (32b, after satoshis + 4b sequence)

DSTAS-optimized pattern — same as v1.

Subtotal: **~180b**.

### 3.5 ScriptCode tail extraction + cache

v2 tail is simpler than v1 (no seriesId, no redemptionPkh, no whitelist commitment). We need to cache **7 fields** from the 111b fixed tail plus optional-data tail boundary:

| Field             | Offset in tail (bytes) | Size |
| ----------------- | ---------------------- | ---- |
| tokenId           | 0                      | 32b  |
| issuerPkh         | 32                     | 20b  |
| amount            | 52                     | 16b  |
| authorityFlags    | 68                     | 1b   |
| freezeAuthHash    | 69                     | 20b  |
| confiscAuthHash   | 89                     | 20b  |
| attestation_depth | 109                    | 2b   |
| optionalData      | 111+                   | var  |

Pseudo-ASM (walk scriptCode from OP_RETURN forward, splitting fields into altstack):

```
// scriptCode already extracted by §3.4; find OP_RETURN
<scriptCode> <OP_RETURN_offset> OP_SPLIT OP_NIP          // tail_bytes
OP_DUP OP_TOALTSTACK                                      // full tail cached
<32> OP_SPLIT OP_TOALTSTACK                               // tokenId → altstack
<20> OP_SPLIT OP_TOALTSTACK                               // issuerPkh
<16> OP_SPLIT OP_TOALTSTACK                               // amount (uint128 LE)
<1>  OP_SPLIT OP_TOALTSTACK                               // authorityFlags
<20> OP_SPLIT OP_TOALTSTACK                               // freezeAuthHash
<20> OP_SPLIT OP_TOALTSTACK                               // confiscAuthHash
<2>  OP_SPLIT OP_TOALTSTACK                               // attestation_depth
// remainder = optionalData (may be empty)
OP_TOALTSTACK                                              // optionalData
OP_DROP                                                    // discard scriptCode leftover (script body before tail, cached separately for §5 reconstruction)
```

- Per OP_SPLIT + push of length byte + OP_TOALTSTACK ≈ 5b. 7 field splits = ~35b.
- OP_RETURN offset split (scriptCode includes body; locate OP_RETURN via known PREFIX+SUFFIX length OR `OP_SIZE` minus fixed-tail walk): ~25b.
- Owner-push strip (v2 needs this for owner identity check, and must branch on PKH vs MPKH since v2 supports MPKH owner): ~60b.
- Action_data (OP_0) + OP_2DROP strip: ~10b.
- Body-before-tail cache (counterpartyScript-equivalent for output reconstruction in §5): ~25b.
- Plumbing (SWAPs, DUPs, altstack juggling): ~25b.

Subtotal: **~180b** (roughly parity with v1's 180b despite dropping WHITELIST — offset by needing to cache 7 tail fields vs v1's 5, plus amount & depth being new).

### 3.6 Owner identity check (PKH or MPKH, flag bit 5)

After §3.2 covenant verified a sig under the generator-point parity pubkey (covenant mechanism), we must re-verify the owner's actual sig.

```
<authorityFlags_from_cache> <0x20> OP_AND <0> OP_EQUAL   // flag bit 5 cleared → PKH owner
OP_IF
  // PKH path: owner_pubkey HASH160 equals owner_field
  <owner_pubkey>  OP_HASH160  <owner_field_from_cache>  OP_EQUALVERIFY
  // single-sig CHECKSIG is NOT redone here — covenant §3.2 already verified sig against preimage;
  // the sig owner signed is the same one whose pubkey matches HASH160(owner). This is standard pattern.
OP_ELSE
  // MPKH owner path
  // Unlocking: [OP_0, sig_1..sig_m, mpkh_preimage] + owner-pubkey slot unused
  <mpkh_preimage> OP_HASH160 <owner_field_from_cache> OP_EQUALVERIFY
  // Parse m, n from preimage; CHECKMULTISIGVERIFY against preimage-derived pubkeys
  <MPKH parse + CHECKMULTISIGVERIFY block>
OP_ENDIF
```

- PKH branch body: ~10b (2 pushes + HASH160 + EQUALVERIFY).
- MPKH branch body: ~60-80b (HASH160 + EQUALVERIFY + preimage parse + CHECKMULTISIGVERIFY). This is a smaller MPKH block than paths 4/5/6's in v1 because we're re-using the preimage-bound sig from the covenant via the CHECKMULTISIG opcode — cost scales with m pubkey extractions.
- Branch header (`IF/ELSE/ENDIF` + flag AND + OP_EQUAL): ~15b.

Subtotal: **~80b** (vs v1's 5b stub — v2 adds MPKH owner, bit 5 new).

**Note on path-specific identity:** paths 3 and 4 use freezeAuth / confiscAuth pubkeys, not owner. Following v1 OQ #5 convention, PREFIX §3.6 runs the OWNER identity check unconditionally, and paths 3, 4 re-verify their own authority identity in-branch. This wastes a HASH160 on path 3, 4 spends (~10b), but keeps PREFIX simple. Alternative: defer identity entirely to branches (saves ~10b but adds ~10b per owner path). Kept in PREFIX.

### 3.7 Path_id range check + dispatcher

See §1.1 — **~26b** total.

### 3.8 PREFIX totals

| Sub-block                                                     | Bytes   |
| ------------------------------------------------------------- | ------- |
| Body marker (§3.1)                                            | 5       |
| OP_PUSH_TX covenant (§3.2)                                    | 350     |
| Sighash-type check (§3.3)                                     | 12      |
| Preimage parse (§3.4)                                         | 180     |
| ScriptCode + tail cache (§3.5; 7 fields incl. amount & depth) | 180     |
| Owner identity incl. MPKH branch (§3.6)                       | 80      |
| Path dispatcher 4 paths (§3.7)                                | 26      |
| **PREFIX subtotal**                                           | **833** |

Slightly above the 700-800b informal target, driven by owner MPKH (+75b vs v1 PKH-only stub).

---

## 4. SUFFIX — per-path branches

### 4.1 Path 1 — flex-transfer (BIGGEST path)

**Unlocking layout (spec §9.2):**

```
[output_tuples... M × (amount 16b, owner var, new_depth 2b, body_marker 2b)]
[amounts_in_array (N × 16b)]
[all_input_outpoints (N × 36b)]
[selfPosition 1b, 0..N-1]
[max_input_depth 2b]                        // user-pushed, cross-input verified
[null-data script?]
[funding_outpoint 36b]
[preimage]
[OP_1]
[owner_sig, owner_pubkey]                   // or MPKH form
```

**Script logic:**

```
// (a) hashPrevouts binding — each input sees same all_input_outpoints + funding_outpoint
<all_input_outpoints> <funding_outpoint> OP_CAT
OP_HASH256
<hashPrevouts_from_preimage_cache> OP_EQUALVERIFY                       // ~10b

// (b) N = |all_input_outpoints| / 36; range N ≥ 1
<all_input_outpoints> OP_SIZE <36> OP_DIV
OP_DUP <1> OP_GREATERTHANOREQUAL OP_VERIFY
OP_TOALTSTACK                                                            // stash N
                                                                         // ~15b

// (c) selfPosition bound: all_input_outpoints[selfPosition*36 .. +36] == thisOutpoint
<selfPosition> <36> OP_MUL
<all_input_outpoints> OP_SWAP OP_SPLIT OP_NIP <36> OP_SPLIT OP_DROP
<thisOutpoint_from_preimage_cache> OP_EQUALVERIFY                        // ~20b

// (d) amounts_in_array[selfPosition] == my_amount (from tail cache)
<selfPosition> <16> OP_MUL
<amounts_in_array> OP_SWAP OP_SPLIT OP_NIP <16> OP_SPLIT OP_DROP
<my_amount_from_cache> OP_EQUALVERIFY                                    // ~20b

// (e) M = output_tuples count (from unlocking, explicit push or derived)
<M> OP_DUP <1> <5> OP_WITHIN OP_VERIFY                                   // M ∈ [1, 4]   ~5b

// (f) max_input_depth sanity: my_depth ≤ max_input_depth
<my_depth_from_cache>
<max_input_depth>
OP_LESSTHANOREQUAL OP_VERIFY                                              // ~6b
// (each input checks this — collectively, max is accurately enforced across the tx)

// (g) AMOUNT CONSERVATION — SUM amounts_in_array, compare to SUM output.amount
// Unrolled sum over amounts_in_array (up to N = can be variable — we bound N ≤ 8 practically):
// Realistically: unroll N up to 4 for symmetric merge; for N > 4 push a total as well + re-sum check.
// For G5 estimate, assume N ≤ 4 unrolled:
<0> OP_TOALTSTACK                                                         // Σin accumulator
// for i in 0..3: if i < N, Σin += amounts_in_array[i] (16b LE → ScriptNum via OP_BIN2NUM)
//   per iteration: extract slice, BIN2NUM, OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
<loop × 4 unrolled with i < N gate>                                       // ~25b × 4 = 100b

// Same for output amounts, parsed from output_tuples:
<0> OP_TOALTSTACK                                                         // Σout accumulator
<loop × 4 unrolled with i < M gate>                                       // ~25b × 4 = 100b

// Compare:
OP_FROMALTSTACK OP_FROMALTSTACK OP_EQUALVERIFY                            // ~3b
                                                                          // conservation total ≈ 205b

// (h) Output reconstruction (unrolled × 4, gated on M):
// For each output tuple i:
//   - Parse (amount 16b, owner var, new_depth 2b, body_marker 2b) from tuple
//   - Anti-dust: amount ≥ 1 (uint128 treated as script num on lower bytes; practically: OP_NOT OP_NOT check non-zero, ~6b)
//   - Marker check: body_marker == 0x01ff (for flex-transfer all outputs are Normal)
//   - new_depth ≥ max_input_depth + 1, uint16 bound (≤ 65535)
//   - Build candidate locking script: [owner_push + OP_0 + OP_2DROP] ‖ [body marker + PREFIX + SUFFIX identical to this template] ‖ [OP_RETURN + reconstructed tail]
//     Reconstructed tail = tokenId ‖ issuerPkh ‖ amount ‖ authorityFlags ‖ freezeAuthHash ‖ confiscAuthHash ‖ new_depth ‖ optionalData
//     All fields from MY tail cache EXCEPT amount (from tuple) and new_depth (from tuple).
//   - Serialize output: satoshis (anti-dust 1 sat fixed) (8b LE) ‖ varint(len) ‖ candidate_script
//   - Append to hashOutputs buffer
<per-output block>
   // anti-dust on amount                                               ~6b
   // marker == 0x01ff                                                   ~6b
   // depth check (new_depth ≥ max_input_depth + 1, ≤ 65535)            ~10b
   // candidate script reconstruction via OP_CAT from cached pieces     ~60b
   //   - owner_push (var)                                              ~20b
   //   - action_data + OP_2DROP constants                              ~5b
   //   - body constants (cached via §3.5 — body_before_tail bytes)     ~10b
   //   - tail reconstruction with amount/depth substituted             ~30b
   // output serialization (satoshis + varint + script) + accumulate    ~20b
// = ~100-110b per output
<unroll × 4 with M-gate>                                                  // 4 × ~105b = ~420b

// (i) Append optional null-data + hashOutputs covenant closure
<null-data append branch>                                                 // ~20b
OP_HASH256 <hashOutputs_cache> OP_EQUALVERIFY                             // ~10b
```

**Budget (path 1):**

| Sub-block                                       | Bytes  |
| ----------------------------------------------- | ------ |
| hashPrevouts binding (a)                        | 10     |
| N range derive (b)                              | 15     |
| selfPosition outpoint match (c)                 | 20     |
| amounts_in_array[selfPosition] == my_amount (d) | 20     |
| M range check (e)                               | 5      |
| max_input_depth lower-bound (f)                 | 6      |
| Amount conservation sum unrolled ×4+×4 (g)      | 205    |
| Output reconstruction per-tuple (h) — 4 × ~105b | 420    |
| Output serialize + accumulate in h              | (in h) |
| Null-data append + hashOutputs closure (i)      | 30     |

Path 1 total: **~731b**.

Below the informal 900-1100b target — because:

1. No anchor/follower prev-tx reconstruction (v1's biggest merge cost).
2. Amount check via pushed array + script conservation is cheap (205b) vs v1's satoshi conservation which had zero logic (SIGHASH_ALL did it).
3. Output reconstruction is symmetric across all M ≤ 4 (same loop shape).

**OPEN QUESTION #1 (depth propagation across inputs):** spec §9.2 notes "each input script verifies its own depth, not other inputs'." Our implementation:

- Each input verifies `my_depth ≤ max_input_depth` (pushed value).
- Output reconstruction verifies `new_depth ≥ max_input_depth + 1`.

Because `amounts_in_array` and `all_input_outpoints` are pushed by unlocking AND bound via `hashPrevouts`, they are consistent across all inputs. But `max_input_depth` is NOT part of that binding — it's pushed freely. If attacker pushes `max_input_depth = 0` when actual max is 5, input scripts with depth ≤ 0 accept (none would — at least the input with depth 5 fails `my_depth ≤ 0`). So the constraint IS enforced collectively: the tx can only succeed if every input's depth ≤ pushed value. Any under-reported value fails some input. Conservative answer is pushed value ≥ all input depths. Output gets that pushed value + 1 as minimum. Safe. **Flagged for protocol-review; may need `max_input_depth` to be part of a hash bound via `all_input_depths` array instead.**

**SPEC AMENDMENT REQUEST #1:** pin `max_input_depth` semantics: either (a) push it as above (simpler, 0b bind cost, but attacker can over-report leading to legitimate output depth inflation), or (b) push `all_input_depths` N × 2b and bind via `hashPrevouts`-adjacent hash. (a) is safe for the protocol invariant "depth ≥ max + 1", just not strict-equal. Recommend (a) with a note that depth may inflate above true max (benign — it only ages the token faster, which is conservative).

### 4.2 Path 2 — refresh (with issuer attestation)

**Unlocking (spec §9.3):**

```
[refreshed_output_tuple]  // amount = my_amount − royalty, owner = my_owner, new_depth=0, marker=0x01ff
[royalty_output_tuple]    // amount = royalty, owner = issuerPkh, new_depth=0, marker=0x01ff
[null-data script bytes]  // OP_FALSE OP_RETURN <tokenId> <thisOutpoint> <issuerPubkey>
[change?]
[funding_outpoint]
[preimage]
[OP_2]
[issuer_sig, issuer_pubkey]   // or MPKH form
[owner_sig, owner_pubkey]     // covenant already verified in §3.2
```

**Script logic:**

```
// (a) Exactly 2 BNTP outputs expected — implicit in unlocking having 2 tuples.
// (b) Output 0 reconstruction: amount = my_amount − royalty, owner = my_owner, depth = 0
<my_amount_from_cache> <royalty_from_unlocking> OP_SUB                     // new amount
<expected output 0: my owner, this amount, depth 0, marker 0x01ff, other tail fields preserved>
<reconstruct + serialize output 0>                                         // ~110b (similar to path 1 per-output)

// (c) Output 1 reconstruction: amount = royalty, owner = issuerPkh, depth = 0
<expected output 1: issuer owner push = issuerPkh (P2PKH-style owner field in BNTP), amount = royalty, depth 0, marker 0x01ff>
<reconstruct + serialize output 1>                                         // ~110b
// NB: if issuer is MPKH, owner field on royalty UTXO is also MPKH preimage. Complication — see OQ #2.

// (d) Conservation: my_amount == refreshed.amount + royalty.amount
<refreshed.amount> <royalty.amount> OP_ADD
<my_amount_from_cache> OP_EQUALVERIFY
// + both positive (≥1): two anti-dust checks inline in (b), (c).
                                                                            // ~8b

// (e) Null-data verification at index 2:
//   script = 6a (OP_RETURN) prefixed; or 00 6a (OP_FALSE OP_RETURN); parse per format
//   tokenId (32b) == my.tokenId
//   thisOutpoint (36b) == my.thisOutpoint (from preimage)
//   issuer_pubkey (33b) → HASH160 → == my.issuerPkh (or MPKH form)
<null-data parse: skip OP_FALSE + OP_RETURN + push opcodes, split into 3 fields>  // ~40b
<tokenId field> <my_tokenId_from_cache> OP_EQUALVERIFY                             // ~3b
<thisOutpoint field> <my_thisOutpoint_from_cache> OP_EQUALVERIFY                   // ~3b
// Issuer pubkey → PKH or MPKH handling
<authorityFlags_from_cache> <0x10> OP_AND <0> OP_EQUAL                             // bit 4
OP_IF
  <pubkey_field_from_null_data> OP_HASH160 <my_issuerPkh_from_cache> OP_EQUALVERIFY
OP_ELSE
  // MPKH: field is the MPKH preimage, not a single pubkey — complication
  <pubkey_field> OP_HASH160 <my_issuerPkh_from_cache> OP_EQUALVERIFY
OP_ENDIF
                                                                                   // ~30b

// (f) Issuer CHECKSIGVERIFY against preimage (standard covenant — already done in §3.2 for one sig;
//     refresh needs BOTH owner AND issuer to sign SIGHASH_ALL. Covenant §3.2 uses the parity-pubkey
//     indirectly; owner sig is verified via §3.6; issuer sig needs explicit check here:
<issuer_sig> <issuer_pubkey_from_null_data> <preimage_from_cache> OP_CHECKSIGVERIFY
// MPKH issuer: CHECKMULTISIGVERIFY with sigs/preimage from unlocking + pubkeys derived from null-data MPKH preimage
<flag bit 4 branch for MPKH issuer>                                               // ~60b incl. PKH fallback

// (g) hashOutputs covenant closure including null-data + optional change
<output 0 ‖ output 1 ‖ null-data ‖ change?>                                       // CAT chain ~25b
OP_HASH256 <hashOutputs_cache> OP_EQUALVERIFY                                      // ~10b
```

**Budget (path 2):**

| Sub-block                                            | Bytes |
| ---------------------------------------------------- | ----- |
| Output 0 reconstruction (refreshed, incl. anti-dust) | 110   |
| Output 1 reconstruction (royalty, incl. anti-dust)   | 110   |
| Conservation check                                   | 8     |
| Null-data parse (3 fields, skip OP_FALSE OP_RETURN)  | 40    |
| tokenId + thisOutpoint equals                        | 6     |
| Issuer pubkey → HASH160 match (+ MPKH branch)        | 30    |
| Issuer CHECKSIGVERIFY (+ MPKH branch ~60)            | 70    |
| Output concat + hashOutputs closure                  | 35    |

Path 2 total: **~409b**.

Above the informal 300-400b target — pushed up by the two full output reconstructions (always present on refresh; no gating) and the explicit issuer signature verification which wasn't needed on flex-transfer.

**OPEN QUESTION #2 (issuer MPKH royalty owner):** royalty output's owner field is `issuerPkh` but when issuer is MPKH (flag bit 4), the "owner" encoding on the royalty UTXO is either (i) a plain 20b PKH where the PKH = `HASH160(MPKH preimage)`, or (ii) the MPKH preimage itself. Option (i) is smaller and matches the tail's `issuerPkh` semantic directly. Option (ii) would require pushing the preimage in unlocking and HASH160-matching — larger. Recommend option (i): royalty UTXO's owner field is the 20b `issuerPkh` directly; spend requires whoever controls the MPKH to provide the preimage at spend time, which is a separate matter. **Keeping option (i) in the estimate; ~0b impact.**

### 4.3 Path 3 — freeze

**Unlocking (spec §9.4):**

```
[frozen_output_tuple]  // amount=my_amount, owner=my_owner, new_depth=my_depth, marker=0xfeff
[null-data?]
[funding_outpoint]
[preimage]
[OP_3]
[freezeAuth_sig, freezeAuth_pubkey]   // or MPKH form
```

**Script logic:**

```
// (a) authorityFlags bit 0 (freezable) set
<authorityFlags_from_cache> <0x01> OP_AND <1> OP_EQUALVERIFY              // ~8b

// (b) Authority identity: HASH160(freezeAuth_pubkey) == freezeAuthHash (PKH) or HASH160(preimage) (MPKH bit 2)
<authorityFlags_from_cache> <0x04> OP_AND <0> OP_EQUAL
OP_IF
  // PKH: pubkey is the freezeAuth pubkey; already "covenant-sig-verified" in §3.2
  <freezeAuth_pubkey> OP_HASH160 <freezeAuthHash_from_cache> OP_EQUALVERIFY
OP_ELSE
  // MPKH: preimage push + CHECKMULTISIGVERIFY
  <freezeAuth_mpkh_preimage> OP_HASH160 <freezeAuthHash_from_cache> OP_EQUALVERIFY
  <MPKH parse + CHECKMULTISIGVERIFY block>
OP_ENDIF
                                                                           // PKH ~10b, MPKH branch ~60b, header ~15b ≈ 85b total

// (c) Output 0 = Frozen UTXO with: marker=0xfeff, amount=my_amount, owner=my_owner, depth=my_depth, all tail preserved
// Reconstruct expected_output:
<frozen output reconstruction>                                             // ~110b
//   - Frozen body body_before_tail is DIFFERENT than Normal's (different template)
//   - In v1, this was handled via WHITELIST hash match + marker check. v2 without whitelist must
//     push Frozen's full body (or a pinned hash) in locking constants at template-compile time.
//   - SIMPLEST: bake the Frozen body hash as a 32b constant into this template (embed 32b + OP_CAT).
//     Expected script: owner_push(my) ‖ OP_0 ‖ OP_2DROP ‖ Frozen_body ‖ OP_RETURN ‖ tail_preserved
//     Verify via HASH256/SHA256 match of the candidate push.
//   - ~30b for PKH owner reconstruction, ~30b for tail reconstruction, +30b for Frozen body concat = ~100b + ~10b serialize

// (d) hashOutputs closure (1 output + null-data? + change?)
<output serialize ‖ null-data append ‖ change append>                      // ~30b
OP_HASH256 <hashOutputs_cache> OP_EQUALVERIFY                              // ~10b
```

**Budget (path 3):**

| Sub-block                                        | Bytes |
| ------------------------------------------------ | ----- |
| authorityFlags bit 0 check                       | 8     |
| Freeze authority identity incl. MPKH branch      | 85    |
| Frozen output reconstruction (owner/amount/tail) | 110   |
| Output serialization + optional appends          | 30    |
| hashOutputs closure                              | 10    |

Path 3 total: **~243b**. In the 200-300b target band.

**OPEN QUESTION #3 (Frozen body embedding):** without WHITELIST, how does Normal know what the valid Frozen body bytes are? Three options:

- (α) Embed the Frozen body (estimated ~600b per spec §11.1) verbatim — blows body to 2800b. REJECT.
- (β) Embed `SHA256(Frozen body)` (32b constant). Spend-time: reconstruct candidate, `SHA256`, compare. Adds 32b constant + ~5b match = 37b. Same for path 4/1 output verification when target is different template.
- (γ) Embed a commitment to just the Frozen body's `body_before_tail` length (template-assembly-time constant) and verify that the candidate output's body section starts with a specific marker, trusting that the template hashes are deployed separately.

**Recommendation: option (β)** — SHA256 hash of Frozen body as 32b constant inside Normal body. Off-chain deployer pins both bodies together. This is a 32b embed cost for path 3 AND for Contract→Normal in path 6 issue (not in scope here). Flex-transfer and confiscate produce Normal-same outputs and reuse this template's OWN body bytes via the `body_before_tail` cache — no separate hash needed for same-template outputs.

Path 3 budget revised with +32b embed: **~275b** (Frozen SHA256 hash inside reconstruction step).

### 4.4 Path 4 — confiscate

**Unlocking (spec §9.5):**

```
[normal_output_tuple]   // amount=my_amount, owner=new_owner, new_depth=0, marker=0x01ff
[null-data?]
[funding_outpoint]
[preimage]
[OP_4]
[confiscAuth_sig, confiscAuth_pubkey]  // or MPKH form
```

**Script logic:**

```
// (a) authorityFlags bit 1 (confiscatable) set
<authorityFlags_from_cache> <0x02> OP_AND <1> OP_EQUALVERIFY              // ~8b

// (b) Confisc authority identity (flag bit 3 for MPKH)
<authorityFlags bit 3 MPKH branch, symmetric to path 3 (b)>                // ~85b

// (c) Output 0: Normal UTXO with marker=0x01ff, amount=my_amount, owner=new_owner, depth=0
// Reconstruction uses THIS template's own body (no extra hash embed needed — same template)
<normal output reconstruction with new_owner from tuple>                   // ~80b (smaller: reuse body_before_tail cache)
//   - new_owner push (var, from tuple)
//   - action_data OP_0 + OP_2DROP + body_before_tail (cached)
//   - OP_RETURN + reconstructed tail (amount=my_amount, depth=0, others preserved)

// (d) hashOutputs closure
<output serialize + optional appends>                                       // ~30b
OP_HASH256 <hashOutputs_cache> OP_EQUALVERIFY                               // ~10b
```

**Budget (path 4):**

| Sub-block                                    | Bytes |
| -------------------------------------------- | ----- |
| authorityFlags bit 1 check                   | 8     |
| Confisc authority identity incl. MPKH branch | 85    |
| Normal output reconstruction (new owner)     | 80    |
| Output serialize + optional appends          | 30    |
| hashOutputs closure                          | 10    |

Path 4 total: **~213b**. In the 200-300b target band.

---

## 5. Shared output verification / tail reconstruction helper

In v1, the §6 helper ran per candidate output and included: owner-push strip, action_data strip, body marker check, WHITELIST byte-match (128b), SHA256(PREFIX ‖ SUFFIX), hash-in-whitelist match. Cost: ~142b plus tail-match helper ~140b = 282b.

**v2 does NOT need a body-hash/WHITELIST match** because there is no closed forward state. Each path reconstructs the expected output bytes directly (using this template's own body for same-template outputs, or an embedded SHA256 hash constant for cross-template like Frozen) and compares byte-wise or hash-wise.

**What's left in v2 shared helper:**

- Tail reconstruction subroutine — given `new_amount`, `new_depth`, `new_owner` (optional), emit expected tail bytes = `tokenId ‖ issuerPkh ‖ new_amount ‖ authFlags ‖ freezeAuthHash ‖ confiscAuthHash ‖ new_depth ‖ optionalData` (all from cache except the 3 substitutable fields). This is called in path 1 (×4 per output), path 2 (×2), path 3 (×1), path 4 (×1).

Inline cost per call: ~30b (7 CATs + substitutes). Could be extracted as a helper block + jump — but BSV Script has no jump, so inlining is the only option. No helper extraction savings.

**Shared helper body as separate section: 0b** — all logic inlined per-path.

Counted inside each path budget above. The "shared helper" line in v1's table becomes empty in v2.

### 5.1 Anti-dust

`amount ≥ 1` on each token output. In v2, amount is a uint128 (16b), not satoshis. Non-zero check: `OP_BIN2NUM OP_0 OP_GREATERTHAN OP_VERIFY` ≈ 5-6b. Inlined in every output reconstruction block (already counted).

---

## 6. Size summary

| Section                               | Bytes    |
| ------------------------------------- | -------- |
| **PREFIX (§3)**                       |          |
| Body marker 0x01ff                    | 5        |
| OP_PUSH_TX covenant                   | 350      |
| Sighash-type check                    | 12       |
| Preimage parse                        | 180      |
| ScriptCode + tail cache (7 fields)    | 180      |
| Owner identity (PKH + MPKH branch)    | 80       |
| Path dispatcher (4 paths)             | 26       |
| **PREFIX subtotal**                   | **833**  |
| **SUFFIX (§4)**                       |          |
| Path 1 — flex-transfer                | 731      |
| Path 2 — refresh                      | 409      |
| Path 3 — freeze (incl. Frozen SHA256) | 275      |
| Path 4 — confiscate                   | 213      |
| **SUFFIX subtotal**                   | **1628** |
| **Shared helper (§5)**                | 0        |
| **GRAND TOTAL BODY**                  | **2461** |

---

## 7. Comparison to v1 NormalBase

| Component                                | v1 NormalBase | v2 Normal | Δ         |
| ---------------------------------------- | ------------- | --------- | --------- |
| PREFIX                                   | 768           | 833       | +65       |
| WHITELIST                                | 131           | 0         | **−131**  |
| Path 1 (v1: transfer/split 520 = 500+20) | 500           | 731       | +231      |
| Path 2 (v1: merge-K 1115 / v2: refresh)  | 1115          | 409       | **−706**  |
| Path 3 (v1: prep-swap 200 / v2: freeze)  | 200           | 275       | +75       |
| Path 4 (v1: freeze 263 / v2: confiscate) | 263           | 213       | −50       |
| Path 5 (v1: confiscate 255 / v2: —)      | 255           | 0         | **−255**  |
| Path 6 (v1: redeem 540 / v2: —)          | 540           | 0         | **−540**  |
| Shared helper (§6 + tail-match)          | 282           | 0         | **−282**  |
| **Total**                                | **4054**      | **2461**  | **−1593** |

Expected "big wins" verified:

- No whitelist: **−131b** ✔ (matches prediction)
- No anchor/follower: **−706b** on the path-2 line alone (v1 merge-K → v2 refresh; but the real diff is "v1 merge 1115b subsumed into v2 path-1 flex-transfer 731b + refresh 409b = 1140b, vs v1 paths 1+2 total = 1615b"). Net save ~475b. ✔
- No redeem path: **−540b** ✔
- Amount conservation via pushed array: **+205b** inside path 1 (slightly higher than predicted +150b, because the LE uint128 → ScriptNum conversions and unrolled ×4+×4 sums are bulky).
- MPKH owner: **+75b** in PREFIX ≈ matches prediction.
- Shared helper removal: **−282b** (no WHITELIST hash plumbing).

Predicted net was −1200b → ~2850b. Actual **−1593b → ~2461b**. Bigger win than predicted, primarily from:

1. Shared helper fully removed (vs expectation of shrink, not full removal).
2. Path 1's flex-transfer replaces BOTH v1 transfer AND merge, combining 1615b → 731b (halved).
3. Removing path 5 (redeem) entirely rather than trimming it.

---

## 8. Gate verdict

**v2 Normal body estimate: ~2461b**

Target bands:

- **PASS** ≤ 2000b
- **PASS-with-margin** ≤ 2300b
- **PIVOT** 2300-2800b
- **ABORT** > 2800b

**Verdict: PIVOT (barely).** 2461b is 161b above PASS-with-margin and 461b above PASS.

### 8.1 Where the excess lives

1. **Amount conservation (path 1): 205b.** Unrolled ×4 + ×4 LE-uint128-to-ScriptNum conversions. Likely trimmable to ~120b by sharing the summation subroutine between input and output, or by using 8-byte amounts (int64) instead of uint128. If spec loosens to uint64 amount: −80b. If we cap N, M ≤ 2 in PoC: −100b (both loops halve).
2. **Owner identity MPKH branch (§3.6): 80b.** Can defer MPKH owner to a separate template variant (Normal-MPKH-owner) saving ~60b, or drop MPKH owner from v2 Phase 1 and re-add later.
3. **Path 1 output reconstruction ×4 (420b).** If we cap M ≤ 2 in PoC, save ~210b.
4. **OP_PUSH_TX covenant (350b).** Inherited from DSTAS/v1. DSTAS audit §5.1.A shows ~50b possible savings via OP_CODESEPARATOR sharing — not included. If applied: −50b.

### 8.2 PIVOT plan to reach PASS ≤ 2000b

| Cut                                                          | Savings | New total |
| ------------------------------------------------------------ | ------- | --------- |
| uint64 amount (int64 ScriptNum-native) instead of uint128    | ~80b    | ~2380     |
| Cap M ≤ 2 in flex-transfer output reconstruction (PoC)       | ~210b   | ~2170     |
| Defer MPKH owner to separate variant (PKH-only v2 Normal)    | ~60b    | ~2110     |
| Covenant OP_CODESEPARATOR optimization                       | ~50b    | ~2060     |
| Share tail reconstruction subroutine via compile-time macros | ~50b    | ~2010     |
| **All 5 cuts combined**                                      | ~450b   | **~2010** |

Just barely hits PASS. Alternative: accept PIVOT verdict and revise G5 target to 2500b (still a 38% reduction vs v1's 4054b and 19% under DSTAS's 3050b per-UTXO — a significant win over both).

### 8.3 PASS-with-margin plan (≤ 2300b)

Simpler path: just two cuts instead of five.

- Cap M ≤ 2 in path 1: **~2250b**. Satisfies PASS-with-margin.
- OR drop MPKH owner + uint128→uint64: **−140b → ~2320b**. Just over; need one more small cut.

---

## 9. Open questions and spec amendments

**OPEN QUESTION #1 (§4.1, depth propagation):** `max_input_depth` pushed freely in unlocking rather than being bound to inputs via hash. Collective verification (each input checks `my_depth ≤ max_input_depth`) ensures pushed value ≥ actual max; over-reporting inflates output depth (benign — ages faster). Spec should ratify this as acceptable.

**OPEN QUESTION #2 (§4.2, issuer MPKH royalty owner):** royalty UTXO's owner field when issuer is MPKH: assume option (i) 20b PKH = `issuerPkh` with MPKH-spend requirement at next transfer. Zero bytes impact.

**OPEN QUESTION #3 (§4.3, Frozen body embedding without whitelist):** option (β) — embed 32b SHA256 of Frozen body as constant inside Normal. Adds 32b to path 3. Alternative: define Frozen minimally so it can be reconstructed (risk: Frozen body is ~600b per spec §11.1, can't inline). Committed to option (β). **SPEC AMENDMENT REQUEST #1:** §3 template catalog should state "each template's body hash is a deployment-time constant that other templates may embed for cross-template output verification."

**OPEN QUESTION #4 (§3.5, tail field cache layout):** §5.2 of spec lists tail at 111b "without redemptionPkh". §9.6 discussion considers adding redemptionPkh back (131b) then reverses the decision to "redeem collapsed into flex-transfer, no redemptionPkh, 111b". Simpler interpretation (this doc): **111b tail, no redemptionPkh, no path 5.** Flagged.

**OPEN QUESTION #5 (Contract amount at mint):** §9.9 notes Contract has an `amount` field and "how is this set at mint"? Out of scope for Normal template — answered in Contract template doc. Flagged for that follow-up.

**SPEC AMENDMENT REQUEST #1:** see OQ #3 above. Require each template body to expose a canonical 32b content hash usable as a constant in other templates' bodies, and a deployment manifest listing those hashes. This is a lighter-weight substitute for v1's WHITELIST block — same function (cross-template verification) at ~32b per cross-reference instead of 131b monolithic whitelist.

**SPEC AMENDMENT REQUEST #2:** pin `max_input_depth` push semantics in §9.2 (see OQ #1). Either (a) allow free push with collective upper-bound enforcement, or (b) require per-input-depth array + hash commitment. Recommend (a) with a "may inflate" note.

**SPEC AMENDMENT REQUEST #3 (G5 gate realism):** current G5 target ~2000b is achievable only with feature cuts (uint64 amount, cap M ≤ 2, no MPKH owner). If the feature set (uint128, M ≤ 4, MPKH owner + MPKH authorities) must all stay, G5 target should be revised to **~2500b** (PIVOT band per this doc). This is still a ~40% reduction vs v1 NormalBase and ~20% under DSTAS per-UTXO — both meaningful wins, just not under a hard 2000b cap.

---

## 10. Assumptions

1. uint128 amount encoded LE, converted to ScriptNum via `OP_BIN2NUM` (assumes values fit; for strict uint128 support script-side math would need chunked arithmetic — significant bloat. This doc assumes practical amounts ≤ int63 fit ScriptNum and documents this as an IMPLICIT simplification).
2. `max_input_depth` is freely pushed and collectively enforced (OQ #1).
3. Tail is 111b (no redemptionPkh); optionalData ≤ 4096b (inherited v1 limit).
4. Frozen body hash is embedded as a 32b constant (OQ #3 option β).
5. Path dispatcher is 4-way (paths 1-4); paths 5 and 6 do not exist in Normal.
6. Body marker encoded as `4c 02 01 ff 75` (5 bytes, same convention as v1 — SPEC AMENDMENT from v1 §5.3 carries forward).
7. Anti-dust: `amount ≥ 1` per token output; inlined (5-6b per check).
8. Owner MPKH is supported (flag bit 5) — if dropped, save ~60-75b.

---

## 11. Summary

- **Body estimate:** ~2461b
- **Gate verdict:** PIVOT (2300-2800b band); specifically low in the band, only 161b above PASS-with-margin.
- **Biggest wins vs v1:** removal of WHITELIST (−131b), of anchor/follower merge (−700b embedded in path consolidation), of redeem path (−540b), of shared hash-match helper (−282b).
- **Biggest v2-specific costs:** amount conservation with uint128 (+205b), MPKH owner (+75b), Frozen-body-hash embed (+32b), depth logic (+~30b total inline).
- **PASS path requires:** cap M ≤ 2 (−210b) and uint64 amount (−80b), or similar combined 450b of cuts.
- **Recommended outcome:** accept PIVOT verdict; propose G5 target revision to 2500b (SPEC AMENDMENT REQUEST #3). This holds all features intact. If strict 2000b cap is required, cap M ≤ 2 in PoC with forward path to M ≤ 4 in v2.1.
