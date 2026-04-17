# BNTP Anchor/Follower Merge Algorithm

**Status:** Phase 0 design artifact. Slice S3 of BNTP Phase 0 pseudo-ASM wave.

**Scope:** concrete position-determination algorithm for BNTP v1 Normal template merge-K path (K ∈ [2, 4]). Defines what anchor and follower scripts push and verify, and proves the algorithm resistant to reordering / spoofing / delegation-escape attacks.

**Relationship to spec:** refines `BNTP_SERIES_V1_SPEC.md` §9.3 by making the position-determination algorithm fully explicit, and raises `**SPEC AMENDMENT REQUEST:**` markers where the current sketch is ambiguous or unsafe as written.

**Out of scope:** full Normal template pseudo-ASM (S1 owns this), whitelist commitment proof (S2 owns this), token-field extraction opcode sequences inside the reconstructed prev tx (treated as black-box "same token" check here).

---

## 1. Problem statement

### 1.1 Setup

A merge-K transaction has the following input layout:

- `inputs[0..K-1]` — K Normal BNTP UTXOs of the same token. Each carries identical `seriesId`, `tokenId`, `redemptionPkh`, `issuerPkh`, `authorityFlags`, `freezeAuthHash`, `confiscAuthHash`, `optionalData`. Each uses the Normal template body (body_marker `0x01ff`).
- `inputs[K]` — P2PKH or P2MPKH funding input paying miner fees. Non-BNTP, no covenant.
- Outputs: 1..2 Normal outputs carrying conserved satoshis, plus optional null-data and P2PKH change.

K is constrained to `[2, 4]` per spec §4.2 rule 1.

### 1.2 Goal

Every BNTP script that runs (one per STAS input) must verify that the transaction is a valid merge. The anchor/follower pattern minimises work:

- Anchor (the script at input[0]) reconstructs the K-1 followers' prev txs, validates they are same-token Normal UTXOs, and performs the satoshi conservation check for the whole tx.
- Each follower (scripts at input[1..K-1]) reconstructs only input[0]'s prev tx, validates it is a same-token Normal UTXO, and delegates conservation to the anchor.

Total cost is `2(K-1)` reconstructions rather than the naive `K(K-1)`. This makes K=4 practical (6 reconstructions total, ~19 KB tx weight) rather than prohibitive (12 reconstructions).

### 1.3 Fundamental constraint

Bitcoin Script per-input isolation: each input's script sees only:

- Its own `scriptCode` (via OP_PUSH_TX covenant).
- A BIP143-style sighash preimage, including among other things `hashPrevouts` (a SHA256d over concat of all input outpoints, binding the entire input set in-order) and `outpoint` (this input's own outpoint).
- Whatever the unlocker pushes.

There is no native way for a script to ask "which input index am I?" — this must be derived from the preimage. Every reliance on unlocking-provided data must be anchored to a covenant-bound quantity (hashPrevouts or hashOutputs).

A naive design "unlocking says I'm anchor, trust it" is forgeable: any follower's owner can craft an unlocking that claims anchor status, bypassing the anchor path's heavier conservation checks and potentially forging satoshi imbalance.

### 1.4 Preimage fields used

From BSV BIP143 preimage (the OP_PUSH_TX result), these fields at known byte offsets are used:

| Field                  | Offset (bytes from start) | Size | Purpose                                           |
| ---------------------- | ------------------------- | ---- | ------------------------------------------------- |
| nVersion               | 0                         | 4    | —                                                 |
| hashPrevouts           | 4                         | 32   | anchor for input-list verification                |
| hashSequence           | 36                        | 32   | —                                                 |
| outpoint               | 68                        | 36   | this input's own outpoint (txid 32b + vout 4b LE) |
| scriptCode varint+data | 104                       | var  | —                                                 |
| value                  | …                         | 8    | this input's satoshi value                        |
| nSequence              | …                         | 4    | —                                                 |
| hashOutputs            | …                         | 32   | covenant binding on tx outputs                    |
| nLocktime              | …                         | 4    | —                                                 |
| sighashType            | …                         | 4    | must equal 0x41 (enforced elsewhere in body)      |

"Known offset" here means offsets fixed up to the point of `scriptCode` which carries a varint length prefix; scriptCode extraction is not needed for position determination, only for output reconstruction. `outpoint` at offset 68 is load-bearing for this algorithm.

---

## 2. Proposed algorithm

### 2.1 Unlocking script layout (shared scaffold)

Both anchor and follower unlockings push the following common block (in addition to path_id 2, preimage, sig, pubKey specified in spec §9.1):

```
all_outpoints        36 × K_STAS bytes, txid(32b BE as in outpoint) ‖ vout(4b LE) for each STAS input
funding_outpoint     36 bytes, the non-BNTP funding input's outpoint
```

Note that `all_outpoints` does NOT include the funding input; funding is pushed separately. See §5.3 for why BNTP inputs are required to be contiguous and positioned first.

The script verifies once (in shared dispatcher):

```
HASH256( all_outpoints ‖ funding_outpoint ) == preimage.hashPrevouts
```

Because `hashPrevouts = SHA256d(serialize(all_input_outpoints_in_order))`, this check binds `all_outpoints ‖ funding_outpoint` to the actual tx input list, in order. If attacker modifies any byte — reordering, swapping, inserting — the hash breaks and the script rejects.

### 2.2 Position determination

Each script then extracts its own outpoint from the preimage (36 bytes at offset 68) and scans `all_outpoints` for a match.

```
my_outpoint = preimage[68..104]                      // fixed offset
selfPosition = findFirstMatch(all_outpoints, my_outpoint, stride=36)
```

- If `selfPosition == 0` → anchor path.
- If `selfPosition ∈ [1, K_STAS - 1]` → follower path.
- If no match found → fail (this input's outpoint is not in the BNTP-contiguous block; see §5.3 on funding placement).

`K_STAS` is derived from `|all_outpoints| / 36`. Script enforces `K_STAS ∈ [2, 4]`.

**Safety claim:** `selfPosition` is not trusted from the unlocking — it is COMPUTED inside the script from two covenant-bound quantities (preimage.outpoint and hashPrevouts-bound all_outpoints). An attacker has no degree of freedom to lie about position.

### 2.3 Anchor responsibilities (selfPosition == 0)

Unlocking block (additional beyond §2.1 common):

```
for i in 1..K_STAS-1:
    follower_i_mergeVout          4b LE, vout index of the follower's input in its prev tx
    follower_i_prev_tx_pieces     N_i pieces split by this.counterpartyScript
    follower_i_piece_count        small int

followerCount                     explicit push, equals K_STAS - 1, range [1, 3]
```

Anchor script steps (pseudo):

```
1.  enforce sighashType == 0x41 (shared)
2.  covenant-verify all_outpoints:
        HASH256(all_outpoints ‖ funding_outpoint) == hashPrevouts
3.  compute K_STAS = |all_outpoints| / 36
    enforce K_STAS ∈ [2, 4]
4.  read followerCount from unlocking
    enforce followerCount == K_STAS - 1  (redundant cross-check)
5.  scan all_outpoints for my_outpoint → selfPosition
    enforce selfPosition == 0
6.  running_satoshis := this.inputValue   (from preimage.value field)
7.  for i in 1..K_STAS-1:
        reconstruct follower_i_prev_tx:
            splice(follower_i_prev_tx_pieces[0] ‖ this.counterpartyScript ‖ pieces[1] ‖ ... ‖ this.counterpartyScript ‖ pieces[N_i-1])
        compute recon_txid = HASH256(reconstructed)
        extract expected_txid = all_outpoints[i*36 .. i*36+32]
        enforce recon_txid == expected_txid
        parse reconstructed prev tx outputs at index follower_i_mergeVout
        extract (output_satoshis_i, output_script_i)
        enforce output_script_i is Normal template with body_marker 0x01ff
        enforce output_script_i tail fields (seriesId, tokenId, redemptionPkh, issuerPkh, authorityFlags, freezeAuth, confiscAuth, optionalData) == this.tail fields
        running_satoshis += output_satoshis_i
8.  reconstruct expected outputs (1..2 Normal output_tuples)
        for each output: enforce Normal body, same token, satoshis ≥ 1
        sum them → out_total
    reconstruct full hashOutputs candidate (Normal outputs ‖ optional null-data ‖ optional change)
    enforce HASH256(concatenated_outputs) == preimage.hashOutputs
9.  enforce running_satoshis == out_total + change_satoshis
    (i.e., token-leg satoshis conserved; change is funded by funding input, not from BNTP value)
10. owner-sig check:
        HASH160(anchor_pubKey) == owner_field_from_scriptCode
        CHECKSIGVERIFY(anchor_sig, preimage, anchor_pubKey)
```

Step 8 subsumes the spec §7 output verification (class detection, whitelist byte-match, body-hash ∈ whitelist). That logic is common and not detailed here; see S1 Normal-ASM doc.

Step 9 conservation: on the merge path, `Σ input_BNTP_satoshis == Σ output_BNTP_satoshis`. Change/null-data bytes are present in the hashOutputs reconstruction but are funded by the funding input's satoshi surplus, not by token-leg value.

### 2.4 Follower responsibilities (selfPosition ∈ [1, K_STAS-1])

Unlocking block (additional beyond §2.1 common):

```
anchor_mergeVout               4b LE, vout index of anchor's input in its prev tx
anchor_prev_tx_pieces          N_a pieces split by this.counterpartyScript
anchor_piece_count             small int
```

Follower script steps:

```
1.  enforce sighashType == 0x41
2.  covenant-verify all_outpoints:
        HASH256(all_outpoints ‖ funding_outpoint) == hashPrevouts
3.  compute K_STAS = |all_outpoints| / 36, enforce ∈ [2, 4]
4.  scan all_outpoints for my_outpoint → selfPosition
    enforce selfPosition ∈ [1, K_STAS - 1]
5.  reconstruct anchor_prev_tx:
        splice pieces with this.counterpartyScript separator
    compute recon_txid = HASH256(reconstructed)
    expected_txid = all_outpoints[0..32]
    enforce recon_txid == expected_txid
    parse anchor_prev_tx outputs at anchor_mergeVout
    extract (anchor_output_satoshis, anchor_output_script)
    enforce anchor_output_script is Normal, body_marker 0x01ff
    enforce anchor tail fields == this.tail fields   (same token)
6.  owner-sig check for THIS follower's owner:
        HASH160(follower_pubKey) == this.owner_field
        CHECKSIGVERIFY(follower_sig, preimage, follower_pubKey)
7.  NO conservation check. NO hashOutputs verification from this script.
    Anchor's script (which MUST be running in this same tx because
    input[0] was proved to be a Normal UTXO same token) will enforce it.
```

### 2.5 Why follower delegation is safe

The argument has two limbs:

1. **Anchor's script is guaranteed to run.** Follower's step 5 cryptographically proves that `all_outpoints[0]` points at an output whose locking script is a Normal template of the same token. That locking script IS the script Bitcoin executes for input[0]. Bitcoin's consensus rule requires every input's script to succeed for the tx to be valid. Therefore, anchor's script WILL run, and if it fails the whole tx fails (and follower's approval is inert).

2. **Anchor's script will enforce conservation.** Anchor's script branches on `selfPosition == 0`, which is forced true at input[0] because the preimage.outpoint field for input[0] literally equals `all_outpoints[0]` (hashPrevouts binding), so no other branch is reachable for input[0]. The anchor branch in §2.3 performs full conservation.

If step 1 were compromised (anchor script ≠ Normal), reconstruction hash mismatch or tail-field mismatch in follower step 5 would reject. If step 2 were compromised (anchor script's selfPosition computation could be fooled), §4 A2 and A6 analyses show it cannot.

---

## 3. Opcode sketches

These are structural sketches sufficient for an implementer to write the full ASM (S1's territory). Actual opcode counts and byte budgets are S1's responsibility.

### 3.1 `all_outpoints` verification (common dispatcher fragment)

Stack before: `[... all_outpoints funding_outpoint]` (unlocking pushes).

```
OP_DUP                         // duplicate funding_outpoint for later use
OP_TOALTSTACK                  // stash funding_outpoint
OP_OVER                        // bring all_outpoints back on top
OP_CAT                         // all_outpoints ‖ funding_outpoint  (note: CAT is enabled in BSV)
OP_HASH256                     // double-SHA256 = HASH256
<preimage-offset to hashPrevouts: 4, len 32>
<preimage from altstack or pick>
OP_SPLIT ... OP_EQUALVERIFY    // compare to preimage.hashPrevouts
OP_FROMALTSTACK                // restore funding_outpoint for later use
```

This commits the pushed outpoints list to the tx structure.

### 3.2 `selfPosition` detection

Stack has `all_outpoints` at some depth and preimage pickable.

```
// extract my_outpoint from preimage at offset 68, length 36
<preimage> <68> OP_SPLIT OP_DROP  // keep left half = first 68 bytes
... (reverse split to take bytes 68..104)
// my_outpoint on stack

// scan all_outpoints in 36b strides
OP_0                              // selfPosition accumulator
OP_0                              // cursor in all_outpoints
<loop unrolled up to K_STAS=4>:
    OP_DUP OP_TOALTSTACK           // save cursor
    // slice all_outpoints[cursor..cursor+36]
    ...
    OP_DUP my_outpoint OP_EQUAL    // byte-match
    OP_IF
        // store selfPosition, set found=1
        ...
    OP_ENDIF
```

Simpler variant (fixed K ≤ 4): read all four 36-byte slices into four positions, test equality against my_outpoint at each, produce four booleans, encode position as `0*b0 + 1*b1 + 2*b2 + 3*b3` with OP_ADD, verify exactly one matches with OP_ADD on booleans == 1.

Uniqueness invariant: outpoints in a tx are unique (Bitcoin consensus: no two inputs can spend same outpoint in same tx). So at most one match is possible; "exactly one match" is enforced.

### 3.3 Dispatch to anchor vs follower branch

```
// selfPosition on stack
OP_DUP
OP_0
OP_EQUAL
OP_IF
    // anchor branch
    ... (§3.4)
OP_ELSE
    OP_DUP OP_1 OP_3 OP_WITHIN OP_VERIFY   // selfPosition ∈ [1, 3]
    // follower branch
    ... (§3.5)
OP_ENDIF
```

### 3.4 Anchor loop (K_STAS - 1 reconstructions)

```
// read followerCount
<followerCount from unlocking>
OP_DUP OP_1 OP_3 OP_WITHIN OP_VERIFY    // range check

// loop unrolled for i in 1..followerCount
<pieces_1> <piece_count_1> <mergeVout_1>
    // reconstruct by interleaving pieces with this.counterpartyScript
    // counterparty_script already pulled from self locking (scriptCode minus owner/action_data prefix)
    OP_CAT ... OP_CAT
    OP_HASH256
    // compare to all_outpoints[1 * 36 .. 1 * 36 + 32]
    ... OP_EQUALVERIFY
    // parse output at mergeVout_1, extract (sats_1, script_1)
    ...
    // script_1 byte-match against locally-reconstructed Normal-template-of-same-token expected bytes
    ...
    // running_satoshis += sats_1
    OP_ADD
    // continue

// same structure for i=2, i=3 gated on followerCount
```

Normal template byte-match against expected: since the whole locking script is reproducible from (owner_i, OP_0 action_data, counterparty_script, tail) where counterparty_script and tail are THIS utxo's (same token), and owner_i is extracted from the reconstructed prev tx output — the anchor can deterministically compare the extracted bytes. Equality byte-by-byte implies Normal body, body_marker 0x01ff, correct whitelist, correct tail. This reuses the same verification shape as path 1 (§9.2) output reconstruction.

### 3.5 Follower single reconstruction

```
<anchor_pieces> <anchor_piece_count> <anchor_mergeVout>

// splice pieces with this.counterpartyScript
OP_CAT ... OP_CAT
OP_HASH256
// compare to all_outpoints[0..32]
<all_outpoints slice 0..32> OP_EQUALVERIFY
// parse output at anchor_mergeVout
...
// byte-match extracted output script against expected-Normal-same-token template
...
// done. No conservation.
```

---

## 4. Attack analysis

Each attack lists attacker capability, attack steps, and the concrete check that catches it.

### A1: Input reorder attack

**Attacker goal:** place a legitimate follower UTXO at input[0] so its script runs the follower branch while actually being at position 0 (or vice versa), hoping to escape the heavier anchor conservation check.

**Attacker controls:** input ordering in the constructed tx.

**Trace:**

- Attacker constructs tx with their controlled-owner BNTP UTXO at input[0], another BNTP UTXO at input[1].
- Attacker must push SOMETHING in `all_outpoints` of the input[0] unlocking.
- Case A: attacker pushes `all_outpoints` in the real tx order. Input[0] script computes `selfPosition = 0` (since preimage.outpoint equals `all_outpoints[0]`) → forced onto anchor path. There is no escape: the anchor path demands reconstruction of all followers and full conservation. No "reorder" gain.
- Case B: attacker pushes `all_outpoints` in a different order, placing the real anchor's outpoint at position 1 in the list and some other outpoint at position 0. Script step "covenant-verify" computes `HASH256(all_outpoints ‖ funding_outpoint)` and compares to preimage.hashPrevouts. Since the list order was changed, the hash mismatches → script rejects.

**Catch:** hashPrevouts is order-sensitive double-SHA256 of the entire outpoint sequence. Any reordering by the unlocker is detected by §2.1 step 2.

### A2: Anchor-spoofing attack via `all_outpoints`

**Attacker goal:** in a follower's unlocking, push a forged `all_outpoints` that places the attacker's own outpoint at position 0, making the script compute `selfPosition == 1` locally but route a benign-looking "anchor is honest" story.

**Attacker controls:** unlocking contents of any input they spend.

**Trace:**

- Attacker's follower input at actual position 2 is spent. Attacker pushes a forged `all_outpoints` where position 2 is still the attacker's outpoint, but positions 0 and 1 are fake outpoints of attacker's choosing.
- Script computes `HASH256(forged_all_outpoints ‖ funding_outpoint)` → this hash is forged by attacker's choice.
- Script compares to `preimage.hashPrevouts`. hashPrevouts is covenant-bound to the REAL tx input list, not to the unlocking. They will only match if the forged list equals the real list. Forged content → hash mismatch → reject.

**Catch:** preimage.hashPrevouts is inaccessible to attacker forgery. Any attempt to mutate `all_outpoints` for position-manipulation is caught by §2.1 step 2.

**Corollary:** even with full unlocking control, an attacker cannot lie about `selfPosition` because both sides of the position computation are derived from preimage (my_outpoint via offset 68, all_outpoints via hashPrevouts-bound check).

### A3: Follower-delegation escape

**Attacker goal:** construct a tx where followers' scripts all pass but no real anchor runs conservation. For example, make input[0] something other than a Normal UTXO whose script has no conservation logic.

**Attacker controls:** prev tx creation, input selection, unlocking contents.

**Trace — Sub-attack A3a (input[0] is P2PKH):**

- Attacker crafts a tx with a P2PKH UTXO at input[0] and Normal UTXOs at inputs[1..K-1].
- The P2PKH script at input[0] has NO covenant and runs independently — it doesn't know about merge semantics, doesn't enforce conservation.
- Each follower at position 1..K-1 attempts step §2.4.5: reconstruct the prev tx at `all_outpoints[0]`. Reconstruction splices with `this.counterpartyScript` (Normal template counterparty-script). For this to hash to `all_outpoints[0].txid`, the prev tx must contain Normal-template bytes. A genuine P2PKH prev tx (output at anchor_mergeVout is P2PKH) cannot contain the Normal counterparty-script, so either:
  - Reconstruction HASH256 mismatches → reject.
  - Reconstruction happens to hash match (astronomically unlikely SHA256 collision), but the extracted output script at anchor_mergeVout is not Normal → byte-match check against "expected Normal body" rejects.
- Follower rejects. Tx fails.

**Trace — Sub-attack A3b (input[0] is a different template — SwapReady, Frozen):**

- SwapReady/Frozen templates have different body markers (0x0fff, 0xfeff) and different PREFIX/SUFFIX bytes.
- Follower step reconstructs prev tx at input[0], extracts output at anchor_mergeVout, byte-compares to expected Normal template. SwapReady/Frozen bytes differ from Normal bytes (at minimum body_marker differs) → byte-match rejects.

**Trace — Sub-attack A3c (input[0] is a Normal-looking decoy that skips conservation):**

- Attacker mints their own protocol where input[0] mimics Normal bytes but skips conservation. This requires producing an output whose locking script matches Normal byte-for-byte but internally does nothing. That's contradictory: if the bytes match Normal, Bitcoin executes Normal's opcodes, which include conservation logic (step §2.3.9). Attacker cannot have "same bytes" and "different semantics".

**Catch:** the byte-match check in §2.4 step 5 forces input[0] to actually be a Normal UTXO. Bitcoin then forces that Normal UTXO's script to run, which is the anchor branch, which enforces conservation. No delegation escape.

### A4: Mixed-token merge

**Attacker goal:** merge inputs belonging to different tokens (e.g., input[0] = token A, input[1] = token B with different tokenId).

**Attacker controls:** input selection.

**Trace:**

- Input[0] is Normal token A. Its script runs anchor branch. In §2.3 step 7, anchor reconstructs follower_1's prev tx and extracts the output at follower_1_mergeVout. The extracted output's tail fields include tokenId. Anchor enforces `extracted.tokenId == this.tokenId` (token A). If follower_1 is token B, mismatch → reject.
- Symmetrically, input[1]'s script runs follower branch. It reconstructs input[0]'s prev tx and enforces `anchor.tail == this.tail`. Tail includes tokenId → mismatch → reject.

**Catch:** tail-field byte-match in §2.3.7 (anchor checks all followers) and §2.4.5 (each follower checks anchor).

**Subcase A4a — different seriesId but same tokenId:** tokenId derivation includes issuerPkh and genesisTxId. Two different series producing "same" tokenId would be an astronomic SHA256 collision. Even ignoring that, seriesId is part of the tail byte-match — different seriesId means different 32 bytes at tail offset 0 → reject.

### A5: K-lie attack

**Attacker goal:** anchor pushes `followerCount=3` but only 1 actual follower is in the tx. Or the reverse — real K=4 but anchor claims followerCount=1, skipping verification of 2 followers.

**Attacker controls:** anchor unlocking.

**Trace — Sub-attack A5a (over-claim):**

- Tx has K_STAS=2 (input[0] anchor, input[1] follower, input[2] funding). `|all_outpoints| = 2 × 36 = 72` bytes.
- Anchor pushes `followerCount=3`.
- Anchor script step 3 computes K_STAS = 72/36 = 2, so K_STAS-1 = 1. Step 4: `enforce followerCount == K_STAS - 1` → 3 != 1 → reject.

**Trace — Sub-attack A5b (under-claim):**

- Tx has K_STAS=4 (inputs[0..3] BNTP, input[4] funding). `|all_outpoints| = 144` bytes.
- Anchor pushes `followerCount=1`.
- Step 4: `followerCount == K_STAS - 1` → 1 != 3 → reject.

**Trace — Sub-attack A5c (anchor provides fake prev tx pieces):**

- Anchor claims followerCount matches K_STAS-1 correctly but provides fake prev tx pieces for follower_2.
- Step §2.3.7: reconstruct, compute `HASH256(reconstructed)`, compare to `all_outpoints[2*36..2*36+32]`. That txid is the REAL follower_2.prev_txid (bound by hashPrevouts). Fake pieces yield a different hash → reject.

**Catch:** redundant cross-check between `followerCount` push and `|all_outpoints|` derivation, plus per-follower HASH256 reconstruction binding.

### A6: Multiple anchors attack

**Attacker goal:** construct a tx where two BNTP UTXOs both try to be anchor, hoping only one conservation check runs and the other skips.

**Attacker controls:** input order.

**Trace:**

- Only one input can occupy position 0 in a Bitcoin tx (by definition). The other BNTP UTXOs are at positions 1..K_STAS-1.
- Input[0]'s script computes selfPosition = 0 → anchor branch. Its counterparty_script value is THIS utxo's counterparty script (token A, say).
- Input[1]'s script computes selfPosition = 1 → follower branch. Its counterparty_script is THIS utxo's — also token A, since §A4 constrains same-token.
- Both branches perform independent checks against the same hashPrevouts, producing consistent validation. No double-anchor possible.

**Catch:** positional identity — a Bitcoin tx has exactly one input[0]. Dispatcher in §3.3 routes exactly one script down the anchor branch.

### A7: Funding-at-position-0 attack

**Attacker goal:** put the funding P2PKH at input[0] and BNTP UTXOs at positions 1..K, hoping no script runs the anchor branch.

**Attacker controls:** input order, unlocking contents.

**Trace:**

- Funding P2PKH at input[0] has NO covenant; its script is just the P2PKH standard script — runs, signs, passes. It does NOT run anchor logic because it's not BNTP.
- BNTP UTXOs at inputs[1..K]. Each computes `selfPosition ∈ [1..K]` (the funding P2PKH's outpoint is at position 0 in hashPrevouts, but P2PKH-outpoint ≠ any BNTP-outpoint).
- Follower scripts attempt §2.4 step 5: reconstruct prev tx at `all_outpoints[0]` → that's the P2PKH's prev tx. Reconstruction splices pieces with Normal counterparty_script. Only hashes to the real txid if the real prev tx contains Normal counterparty_script in its bytes — P2PKH doesn't → reject.
- Even if HASH256 somehow matched, the output at anchor_mergeVout in a P2PKH-funding prev tx would be P2PKH bytes, not Normal → byte-match rejects.

**Refinement via spec amendment:** actually, the unlocking layout in §2.1 requires `all_outpoints` (36 × K_STAS) and `funding_outpoint` (36b) pushed separately. The BNTP scripts compute `HASH256(all_outpoints ‖ funding_outpoint) == hashPrevouts`. For this to match, `funding_outpoint` must be at position K_STAS in the real input list. If attacker places funding at position 0, the real hashPrevouts = HASH256(funding_outpoint ‖ bntp_outpoints), but the script computes HASH256(bntp_outpoints ‖ funding_outpoint) — different concatenation order → hash mismatch → reject.

**Catch:** the layout of `all_outpoints ‖ funding_outpoint` in the hash preimage bakes in the rule "BNTP inputs contiguous starting at 0, funding last". See §5.3.

**SPEC AMENDMENT REQUEST:** add to §9.3 an explicit rule: "Merge-K tx input layout: inputs[0..K-1] are BNTP Normal UTXOs (K ∈ [2, 4]), input[K] is funding. No other input layouts are valid; scripts enforce via `HASH256(all_outpoints ‖ funding_outpoint) == hashPrevouts`."

---

## 5. Edge cases

### 5.1 K=2 minimum

- 1 anchor + 1 follower + 1 funding. `|all_outpoints| = 72b`, `followerCount = 1`.
- Anchor does 1 reconstruction (for follower_1). Follower does 1 reconstruction (for anchor).
- Total reconstructions = 2. Matches DSTAS 2-merge parity.
- No algorithmic corner cases; loop unrolls with only i=1.

### 5.2 K=4 maximum

- 1 anchor + 3 followers + 1 funding. `|all_outpoints| = 144b`, `followerCount = 3`.
- Anchor does 3 reconstructions. Each follower does 1. Total reconstructions = 6.
- Size estimate anchor unlocking (per spec §12.3): ~380 + 3 × 2500b = ~7880b. Within BSV per-tx limits.
- Stack depth during anchor's loop: each iteration requires holding pieces, counterpartyScript, tail-expected bytes, running_satoshis. Stack can be managed via altstack for running_satoshis between iterations. No exhaustion risk at K=4.

### 5.3 Funding input position

Spec §9.3 says funding is "usually" at index K. The proposed algorithm makes this MANDATORY by baking `all_outpoints ‖ funding_outpoint` concat order into the hashPrevouts verification.

If a wallet builder places funding at index 2 (between BNTP inputs), the hashPrevouts will interleave the funding outpoint among BNTP outpoints, and no `all_outpoints ‖ funding_outpoint` concatenation of 36-byte entries will reproduce that hash (because the funding 36b would be in a different slot).

**SPEC AMENDMENT REQUEST:** add to `BNTP_SERIES_V1_SPEC.md` §9.3 explicit invariant:

> **Input layout invariant:** merge-K transactions MUST place all K BNTP Normal inputs contiguously at positions 0..K-1, followed by exactly one funding (P2PKH or P2MPKH) input at position K. Additional non-BNTP inputs are not permitted. The merge scripts enforce this via the hashPrevouts verification `HASH256(all_outpoints ‖ funding_outpoint) == preimage.hashPrevouts` where `all_outpoints` is the K×36-byte concat of BNTP outpoints and `funding_outpoint` is the 36-byte funding outpoint.

This amendment also resolves A7.

### 5.4 Cross-series inputs

Tail byte-match (§2.3.7 anchor, §2.4.5 follower) compares `seriesId` bytes. Different series = different 32-byte seriesId at tail offset 0 → reject. Caught.

### 5.5 K=0, K=1 handling

- K=0 is not a valid merge (no BNTP inputs). No BNTP script runs, no anchor/follower logic applies. Not a case for this algorithm.
- K=1 is transfer/split (path 1), not merge. Spec §4.2 rule 1 locks merge to K ∈ [2, 4]. followerCount range is [1, 3], disallowing K=1 (which would need followerCount=0).
- Enforcement: anchor's step 4 `followerCount ∈ [1, 3]` rejects followerCount=0.

---

## 6. Complexity & size impact

### 6.1 Per-path work

| Aspect                     | Anchor                | Follower   |
| -------------------------- | --------------------- | ---------- |
| Prev tx reconstructions    | K - 1                 | 1          |
| Token-consistency checks   | K - 1 (each follower) | 1 (anchor) |
| HashOutputs covenant check | Yes                   | No         |
| Satoshi conservation       | Yes                   | No         |
| Owner sig check            | Yes (self)            | Yes (self) |

Total reconstructions across all BNTP scripts: `(K-1) + (K-1) = 2(K-1)`.

### 6.2 Unlocking size estimates

Let `P ≈ 2500b` be a typical prev-tx size with single STAS output (similar to DSTAS prod).

| Item                         | Anchor            | Follower         |
| ---------------------------- | ----------------- | ---------------- |
| preimage                     | ~220b             | ~220b            |
| sig + pubkey + path_id       | ~75b              | ~75b             |
| all_outpoints (K×36b)        | K×36              | K×36             |
| funding_outpoint (36b)       | 36                | 36               |
| followerCount / selfPosition | 1-2b              | 1-2b             |
| prev tx pieces (K-1 or 1 tx) | (K-1)×P           | P                |
| output_tuples (1..2 outs)    | ~60-120b          | 0                |
| Base overhead                | ~230b             | ~230b            |
| **Estimate K=2**             | ~330 + P ≈ 2830b  | ~330 + P ≈ 2830b |
| **Estimate K=4**             | ~380 + 3P ≈ 7880b | ~380 + P ≈ 2880b |

Anchor at K=4: ~8 KB. Full merge-4 tx (anchor + 3 followers + funding + outputs): ~8 + 3×2.9 + ~1 ≈ 18-19 KB. Within BSV per-tx limits (1 GB per tx; 100 MB block).

### 6.3 Opcode budget implications

Anchor body contains:

- 1 dispatcher (§3.3)
- 1 loop unrolled to 3 iterations (each ~50-80 opcodes for reconstruction + compare + tail-check + satoshi accumulate)
- 1 shared output verification (§7)
- 1 conservation check

Estimate: anchor branch opcodes ~400. Follower branch opcodes ~150. Both share ~100 opcodes (dispatcher, position detection, sig check). Total Normal-merge-path opcodes ~650 out of S1's ~2000b Normal body budget. Matches spec §12.1.

---

## 7. Assumptions & open questions

### Assumptions

1. **OP_PUSH_TX preimage structure is accessible.** True for BSV with standard BIP143-like serialization. `hashPrevouts` at offset 4 (32b), `outpoint` at offset 68 (36b). These offsets are fixed; no variable-length fields precede them.
2. **`this.counterpartyScript` is reconstructible from the running scriptCode.** The script can extract its own locking script via OP_PUSH_TX (scriptCode field), then strip owner+action_data prefix to obtain counterparty_script. Since merge-K constrains all BNTP inputs to be same token (§A4), the counterparty_script is byte-identical for all followers' prev outputs, making prev tx reconstruction possible (splice by counterparty_script boundary works for every follower).
3. **Normal template has only one action_data encoding (OP_0, 1 byte).** Splitting `scriptCode` at `owner.length + 1 + OP_2DROP` reliably yields counterparty_script. No ambiguity.
4. **SHA256 collision resistance.** Prev tx reconstruction hash match is only achievable if pieces + counterparty_script concat equals the real prev tx bytes. Collisions are cryptographically negligible.
5. **All tail fields are byte-identical across same-token UTXOs.** Spec §7.3 invariant: same-token means tail[0..145+optData] matches byte-for-byte. Enforced on every token-leg transition, so inductively every live Normal UTXO of a token has the same tail bytes.

### Open questions

**OPEN QUESTION:** preimage `scriptCode` extraction for counterparty_script derivation — is there a more efficient way than re-parsing the scriptCode varint each invocation? S1 pseudo-ASM should surface the exact opcode count. For this document, treated as black-box.

**OPEN QUESTION:** whether the explicit `followerCount` push is strictly necessary given `|all_outpoints|` already encodes K_STAS. Arguments for keeping: redundancy catches malformed unlockings early. Arguments for dropping: −1b, one fewer push to verify. Recommendation: keep for defense-in-depth at negligible cost.

**OPEN QUESTION:** should follower validate that input[K] (funding) is actually a P2PKH/P2MPKH input, not another BNTP-variant? Currently the algorithm doesn't verify funding's scriptPubKey shape. If attacker replaces funding with another BNTP input (making a 5-input mix), what happens? The funding_outpoint push is just 36b with no script-shape check. The hashPrevouts check passes as long as the concat order is right. But a second BNTP input at position K would have its own script run — if same-token Normal, it would try to be a "follower at position K=4" which is out of range (K_STAS from length would be 5, followerCount pushed by anchor = 3, mismatch → reject). So A7 via BNTP-at-funding-position is caught by the K_STAS range check.

### Spec amendment requests collected

1. **SPEC AMENDMENT REQUEST (§5.3 / A7):** Add to spec §9.3 explicit invariant on input layout (BNTP contiguous at 0..K-1, funding at K). See §5.3 for full proposed wording.
2. **SPEC AMENDMENT REQUEST (§2.1):** Update §9.3 anchor and follower unlocking catalog to push `all_outpoints` (K × 36b) and `funding_outpoint` (36b) as SEPARATE pushes rather than a single concatenated list. Current spec §9.3 says "all_input_outpoints 36b×K" ambiguously — clarify that this is the BNTP subset and funding is a separate push, and the hash check is over the concatenation in that order.
3. **SPEC AMENDMENT REQUEST (§2.3 / A5):** Require anchor to cross-check `followerCount == (|all_outpoints| / 36) - 1`. Currently spec §9.3 only says `followerCount ∈ [1, 3]`. Redundant check at ~5 opcodes is cheap insurance.
4. **SPEC AMENDMENT REQUEST (preimage offsets):** Document in `BNTP_INVARIANTS.md` (future) the exact preimage byte offsets the merge algorithm depends on (outpoint at 68, hashPrevouts at 4). Lock these to BSV BIP143 layout in conformance matrix.

---

## Gate verdict

**PASS**

Rationale:

1. The algorithm provides concrete opcode-level structure for both anchor and follower paths with two covenant-bound checks (hashPrevouts over `all_outpoints ‖ funding_outpoint`, and my_outpoint from preimage offset 68) that together force `selfPosition` to be computed from quantities the attacker cannot forge.
2. All 7 attack scenarios (A1–A7) trace to an explicit rejection point in the algorithm. A1/A2 are caught by the hashPrevouts binding; A3 by byte-match-to-Normal-template; A4 by tail byte-match; A5 by redundant `followerCount == K_STAS - 1` and per-follower HASH256; A6 by positional uniqueness (Bitcoin-level); A7 by concat-order in the hashPrevouts check plus a spec amendment requiring input layout.
3. All 5 edge cases (K=2, K=4, funding position, cross-series, K=0/K=1) addressed with either natural algorithm coverage or explicit rejection.
4. Follower-delegation safety is argued via a two-limb proof (§2.5) grounded in Bitcoin's per-input script execution rule — no trust leak.
5. 4 `**SPEC AMENDMENT REQUEST:**` markers raised. None are blockers for the algorithm itself — they clarify/tighten the spec so the algorithm is enforceable as written. They are all minor (layout invariant, unlocking field separation, redundant cross-check, preimage offset documentation).

No attack succeeds, no external trust required beyond Bitcoin consensus + SHA256 collision resistance. Algorithm proceeds to S1 pseudo-ASM with the 4 amendment requests to be resolved during spec lock.
