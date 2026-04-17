# BNTP — BSV Native Tokenization Protocol, Series v1 Spec

**Status:** Draft / architectural. Not yet implemented. Supersedes DSTAS 1.0.4 as a fresh protocol (no migration bridge).

**Document scope:** state machine, template catalog, locking script layout, tail/whitelist commitment scheme, spend paths, unlocking script formats, merge (K ∈ [2, 4]) mechanics, swap mechanics. Concrete pseudo-ASM per template is delivered in per-template addenda (out of scope for this doc).

**Architecture:** Option A — 4 deployable templates (`NormalBase`, `NormalSwapOnRamp`, `Frozen`, `SwapReady`) + `Contract`. Locked in after Phase 0 PIVOT + alternatives research. See `BNTP_CRITICAL_REVIEW.md` §8 Revision history for decision log.

**Related documents:**

- `BNTP_CRITICAL_REVIEW.md` — living design review (risks, open gaps, gates)
- `BNTP_VS_DSTAS_COMPARISON.md` — scenario/size comparison
- `BNTP_ALTERNATIVES_EVALUATION.md` / `BNTP_ALTERNATIVES_RECOMMENDATION.md` — Option A justification
- `BNTP_TEMPLATE_NORMAL_ASM.md` — Phase 0 exploratory pseudo-ASM of all-paths Normal (~4640b, led to Option A pivot)
- `BNTP_WHITELIST_COMMITMENT_PROOF.md` — commitment soundness argument
- `BNTP_ANCHOR_FOLLOWER_ALGORITHM.md` — merge-K position-determination algorithm
- `BNTP_TEMPLATE_NORMALBASE_ASM.md` — NormalBase pseudo-ASM (Phase 0.1 deliverable, target ≤ 3000b)
- `BNTP_TEMPLATE_NORMAL_SWAP_ONRAMP_ASM.md` — NormalSwapOnRamp pseudo-ASM (Phase 0.2, pending)
- `BNTP_TEMPLATE_FROZEN.md` — Frozen pseudo-ASM (to be written)
- `BNTP_TEMPLATE_SWAPREADY.md` — SwapReady pseudo-ASM (to be written)
- `BNTP_TEMPLATE_CONTRACT.md` — Contract pseudo-ASM (to be written)
- `BNTP_INVARIANTS.md` — transaction-level flow invariants (to be written; replaces `DSTAS_SCRIPT_INVARIANTS.md`)
- `BNTP_CONFORMANCE_MATRIX.md` — conformance vectors (to be written)

---

## 1. Design goals

1. **Replace the monolithic DSTAS template** with a small family of specialized templates, one per UTXO state.
2. **Close the state space** — any valid BNTP UTXO can only be spent to produce outputs whose locking scripts are one of the series' 4 known templates (or P2PKH for redeem/change).
3. **No recursive action_data** — action_data is either `OP_0` (Normal/Frozen discriminator) or a single swap descriptor (SwapReady), never a chain.
4. **Reduce per-UTXO bytes** for the common case (NormalBase) by ~20% vs DSTAS 1.0.4.
5. **Support wider merge** (up to 4-input) via NormalBase template supporting variable K ∈ [2, 4].
6. **Explicit `seriesId`** as a cryptographic commitment to the whitelist of allowed templates.
7. **Uniform tail layout** across all templates of a series, so output verification can use a single extraction path.
8. **DEX-compatibility** via issuer attestation gate: prepare-swap path lives in dedicated `NormalSwapOnRamp` template and requires issuer signature (via null-data output + SIGHASH_ALL covenant — see §9.4), enabling off-chain back-to-genesis validation with royalty-based business model.
9. **Path isolation via template split** — prepare-swap is the highest-complexity path and is moved out of NormalBase to keep NormalBase body within budget. NormalSwapOnRamp is entered ONLY from NormalBase via prepare-swap-transition path.

### Non-goals (v1)

- Full back-to-genesis verification. BNTP v1 closes the forward state space but does not prove provenance on-chain. Off-chain verification via indexers remains required for trustless provenance.
- Any DSTAS interop, migration, or bridging. DSTAS 1.0.4 is a research artifact in this repository — it does not ship to production and no BNTP path references DSTAS state. Both protocols live in strict SDK isolation (separate folders, separate subpath exports, no shared builders). Shared primitives are limited to `/bsv` (curve math, hashing, buffer utils, identity-field, script reader).

---

## 2. Glossary

| Term                   | Meaning                                                                                                                                                                                                                    |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Series**             | A closed family of 4 templates sharing one `seriesId`. Deployed together.                                                                                                                                                  |
| **Template**           | A parameterized locking script with constant body and variable fields (owner, action_data, tail).                                                                                                                          |
| **State**              | The template a UTXO is in: NormalBase, NormalSwapOnRamp, Frozen, SwapReady.                                                                                                                                                |
| **seriesId**           | 32-byte commitment to the whitelist of body hashes: `SHA256(h_NB ‖ h_NSO ‖ h_F ‖ h_SR)`.                                                                                                                                   |
| **tokenId**            | 32-byte unique identifier for a single token issuance within a series: `SHA256(genesisTxId ‖ contractVout ‖ issuerPkh)`.                                                                                                   |
| **Whitelist block**    | 128-byte sequence `h_NB ‖ h_NSO ‖ h_F ‖ h_SR` embedded as constants in every template body, at a fixed offset from body start (immediately after PREFIX).                                                                  |
| **Body**               | Opcode sequence between `OP_2DROP` and `OP_RETURN`, split into PREFIX ‖ WHITELIST ‖ SUFFIX.                                                                                                                                |
| **h_X**                | `SHA256(PREFIX_X ‖ SUFFIX_X)` — shape hash of template X. The WHITELIST bytes are NOT part of the hash input (self-reference avoidance — see `BNTP_WHITELIST_COMMITMENT_PROOF.md` §2-3).                                   |
| **Tail**               | Fixed-layout 145-byte field block after `OP_RETURN`: seriesId, tokenId, redemptionPkh, issuerPkh, authority block, optionalData.                                                                                           |
| **Anchor / Follower**  | In merge-K (K ∈ [2, 4], NormalBase only), input[0] is anchor (reconstructs all other STAS inputs); inputs[1..K-1] are followers (reconstruct only anchor). See `BNTP_ANCHOR_FOLLOWER_ALGORITHM.md` for detailed algorithm. |
| **Issuer attestation** | Null-data output at known index in the prepare-swap tx carrying `(tokenId ‖ thisOutpoint ‖ timestamp ‖ issuerPubkey)`, bound by issuer's SIGHASH_ALL signature over the tx preimage. Off-chain B2G gate. See §9.4.         |
| **NormalBase**         | Normal-variant template holding paths 1 (transfer/split), 2 (merge-K), 4 (freeze), 5 (confiscate), 6 (redeem), and 7 (prepare-swap-transition → NormalSwapOnRamp). Target body ≤ 3000b.                                    |
| **NormalSwapOnRamp**   | Dedicated template for path 3 (owner-initiated swap preparation with issuer attestation). Entered via NormalBase path 7. Target body ≤ 1500b.                                                                              |

---

## 3. Template catalog

Series v1 contains **4 deployable templates** plus one issuance-time template (`Contract`).

| #   | Template           | action_data                         | Role                                                                                            | Can be spent to                             | Est. body size  |
| --- | ------------------ | ----------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------- | --------------- |
| 0   | `Contract`         | none                                | pre-issuance satoshi reserve                                                                    | NormalBase outputs (issue)                  | ~600b           |
| 1   | `NormalBase`       | `OP_0`                              | spendable token; paths: transfer/split/merge-K/freeze/confiscate/redeem/prepare-swap-transition | NormalBase, NormalSwapOnRamp, Frozen, P2PKH | ~3000b (target) |
| 2   | `NormalSwapOnRamp` | `OP_0`                              | owner-initiated swap preparation with issuer attestation                                        | SwapReady (1 path only)                     | ~1500b (target) |
| 3   | `Frozen`           | `OP_2`                              | frozen token, only authority can move                                                           | NormalBase                                  | ~700b           |
| 4   | `SwapReady`        | swap-descriptor (62b, single-level) | token marked for swap                                                                           | NormalBase, SwapReady (remainder)           | ~1400b          |

**Whitelist** contains templates 1–4 (not Contract). Contract is reachable only once (from funding P2PKH) and is not a valid target from any series template. `h_Contract` is NOT part of the whitelist hash.

### 3.1 Why Contract is outside the whitelist

Contract is spent exactly once, in the issue transaction. Its outputs are NormalBase only. Having `h_Contract` in the whitelist would allow arbitrary templates to output Contract-like UTXOs, which is not desirable. Instead, Contract's spend path verifies the ISSUANCE invariants directly, and its outputs must be in whitelist of templates 1–4 (it embeds the same whitelist block).

### 3.2 Why NormalBase + NormalSwapOnRamp split (Option A pivot)

Earlier draft proposed a single `Normal` template holding all 6 spend paths. Phase 0 pseudo-ASM (`BNTP_TEMPLATE_NORMAL_ASM.md`) showed this body estimate at ~4640b (nearly 2× the 2400b target), with optimized floor ~3600b — still over budget.

The path 3 (prepare-swap with issuer attestation) alone contributed ~695b. Moving it to a dedicated `NormalSwapOnRamp` template:

- Removes ~650-700b from NormalBase → target ~3000b achievable
- Keeps `NormalSwapOnRamp` focused on a single path → audit-isolation bonus
- Cost: +1 template in whitelist (128b vs 96b) → +32b per UTXO
- Size savings vs DSTAS: NormalBase ~3000b UTXO ≈ −28% (still meaningful)

Option A was confirmed via alternatives research (see `BNTP_ALTERNATIVES_RECOMMENDATION.md` §4) as the only feasible design in the trade-off space under current BSV opcodes. Full Phase 0.1 verdict in `BNTP_CRITICAL_REVIEW.md` §8.

### 3.3 Why single-variant Normal (no N-2/N-4/N-8 sub-split)

Earlier draft proposed three Normal variants (Normal-2, Normal-4, Normal-8) with different merge ceilings. This was dropped in favor of a single NormalBase template supporting variable K ∈ [2, 4] for the following reasons:

- Real production usage (per user feedback on DSTAS prod) concentrates around merge-4. Wider (N-8) and narrower (N-2) would be rarely exercised.
- N-8 feasibility was speculative (7 reconstructions per anchor script might exceed BSV opcode/stack limits).
- Variant lock-in (merge requires matching variants) would require wallet-level bundling workarounds → added complexity for marginal benefit.
- Whitelist benefits from fewer templates → smaller WHITELIST block.
- Audit surface reduced ~40%.
- Future extension (add Normal-2 or Normal-8) is possible in BNTP v1.x as additions to whitelist if prod usage warrants.

---

## 4. State machine

### 4.1 Transitions (input state × spend path → output states)

```
Contract
  └─(issue,                 issuer sig)──► NormalBase × N        [Σsats_out == contract.sats]

NormalBase
  ├─(transfer,              owner sig)──► NormalBase × 1
  ├─(split,                 owner sig)──► NormalBase × 2..4     [Σ == input]
  ├─(merge-K,               owner sig)──► NormalBase × 1..2     [K ∈ [2, 4] STAS inputs]
  ├─(prepare-swap-transit.  owner sig)──► NormalSwapOnRamp × 1  [value preserved; owner preserved]
  ├─(freeze,                freezeAuth)─► Frozen × 1
  ├─(confiscate,            confiscAuth)► NormalBase × 1        [new owner]
  └─(redeem,                issuer sig)─► P2PKH + optional NormalBase × 0..3

NormalSwapOnRamp
  ├─(complete-swap-prep,    owner sig + issuer attestation)─► SwapReady × 1
  └─(abort-swap-prep,       owner sig)──► NormalBase × 1        [owner backs out, no royalty]

Frozen
  ├─(unfreeze,              freezeAuth)─► NormalBase × 1
  └─(confiscate,            confiscAuth)► NormalBase × 1        [new owner]

SwapReady
  ├─(cancel,                owner sig)──► NormalBase × 1
  └─(swap-exec,             two owner sigs)─► NormalBase × 2 +  [the principals]
                                               SwapReady × 0..2 [remainders keep swap descriptor]
```

### 4.2 Key transition rules

1. **Merge-K (K ∈ [2, 4])** is only supported on `NormalBase`. `followerCount` pushed explicitly in anchor's unlocking (range 1..3). All K STAS inputs MUST be `NormalBase` (same template, same seriesId, same tokenId).
2. **Prepare-swap is TWO-STEP in Option A.** `NormalBase` does NOT directly produce `SwapReady`. Instead:
   - Step A (on NormalBase): owner-sig-only `prepare-swap-transition` produces a `NormalSwapOnRamp` output. Value and owner preserved. No issuer sig, no royalty required here — purely owner-initiated state move.
   - Step B (on NormalSwapOnRamp): owner-sig + **issuer attestation** (null-data output, see §9.4) + royalty output produces the final `SwapReady` output.
   - Rationale: keeps NormalBase body small. Issuer attestation complexity is contained entirely in NormalSwapOnRamp.
   - Abort path: owner can spend `NormalSwapOnRamp` back to `NormalBase` without issuer involvement if they change their mind before Step B.
3. **Swap-exec is cross-token.** The two SwapReady inputs may belong to different tokens (different `tokenId`) but MUST belong to the same series (same `seriesId`).
4. **OptionalData continuity.** Any spend of a token-bearing UTXO must preserve `optionalData` byte-exact in its token-leg output(s). Remainder SwapReady outputs inherit from their source leg. Confiscation outputs retain source `optionalData`. Swap-exec principals inherit `optionalData` from the OPPOSITE leg (since principal receives the other token).
5. **Redemption PKH** is preserved across all token-leg transitions (identical in all outputs of a token).
6. **Frozen output cannot originate from SwapReady, NormalSwapOnRamp, or Contract.** Frozen state is only reachable from NormalBase via freeze path.
7. **Satoshi conservation** on all owner-sig paths and on merge. Confiscation preserves satoshis. Redeem can burn (P2PKH + optional remainders) but sum(redeem_P2PKH + remainder_NormalBase) == input.
8. **NormalSwapOnRamp is ephemeral.** Not intended as a long-lived state. It exists only between Step A and Step B of prepare-swap, typically in the same mempool window. UTXOs sitting long-term in NormalSwapOnRamp state are treated as "pending, possibly stuck" by indexers.

---

## 5. Locking script layout

All series templates share this structure:

```
[Owner field]                 variable, 20b PKH or MPKH preimage
[Action data]                 variable, state-specific (see §5.2)
OP_2DROP                      drop the two variable pushes
[PREFIX]                      constant per template, spend-path dispatcher
[WHITELIST]                   constant per series, 160b = 5 × 32b
[SUFFIX]                      constant per template, output verification
OP_RETURN
[Tail]                        fixed layout, 125b + optionalData
```

### 5.1 Variable prefix fields (before OP_2DROP)

| Field      | Size                               | Content                                                  |
| ---------- | ---------------------------------- | -------------------------------------------------------- |
| Owner      | 20b PKH, or 36..171b MPKH preimage | Spender identity (for owner-sig paths in all templates)  |
| ActionData | variable (see 5.2)                 | State-category discriminator (combined with body marker) |

### 5.2 ActionData per template

| Template         | action_data bytes                                                                                                    | Notes                          |
| ---------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| Contract         | `OP_0` (1 byte, `0x00`)                                                                                              | No state                       |
| NormalBase       | `OP_0`                                                                                                               | Normal category                |
| NormalSwapOnRamp | `OP_0`                                                                                                               | Normal category (ephemeral)    |
| Frozen           | `OP_2` (1 byte, `0x52`)                                                                                              | Frozen discriminator           |
| SwapReady        | 62-byte pushdata: `0x01 ‖ requestedScriptHash(32) ‖ requestedPkh(20) ‖ rateNum(4) ‖ rateDenom(4) ‖ reserved(1b = 0)` | Single-level, no `.next` chain |

**Note:** NormalBase and NormalSwapOnRamp share the same action_data (`OP_0`). They are distinguished by body marker (§7.4), not by action_data. Action_data is a category discriminator; body marker is the precise template identifier.

Action_data category → state mapping:

- `0x00` (OP_0, empty push) → Normal category → resolved to NormalBase or NormalSwapOnRamp via body marker
- `0x52` (OP_2 opcode pushed as-is, or byte `0x52`) → Frozen
- `0x01` prefix → SwapReady

Any other prefix is invalid.

### 5.3 Whitelist block

**128-byte** constant block embedded in all 4 series templates **at a fixed offset immediately after PREFIX** (normative rule — see §5.3.1):

```
WHITELIST = h_NormalBase ‖ h_NormalSwapOnRamp ‖ h_Frozen ‖ h_SwapReady
            (32 bytes × 4 = 128 bytes)
```

Each `h_X = SHA256(PREFIX_X ‖ SUFFIX_X)` — the body shape of template X, **excluding** the whitelist block itself. This breaks the self-reference problem: whitelist bytes are not part of their own hash. See `BNTP_WHITELIST_COMMITMENT_PROOF.md` for full soundness argument.

All 4 templates in a series share the identical WHITELIST block (byte-for-byte). This enables a simple byte-match check during output verification (§7.2 step 5). Contract embeds the same whitelist block for issue-path output validation, though its own `h_Contract` is NOT part of the whitelist.

**Clarification (S2 AMR #1):** the 96-byte-zero-placeholder used in pseudo-ASM references is never itself a hash input. h_X is computed with PREFIX_X and SUFFIX_X only; WHITELIST bytes (whether zero during template design or real hashes at deployment) are skipped.

**Clarification (S2 AMR #2):** `h_candidate = SHA256(PREFIX_candidate ‖ SUFFIX_candidate)` hashes **raw byte slices** from the output's locking script — not canonicalised opcode representations. This makes pushdata-malleability (e.g., OP_PUSHDATA1 vs OP_PUSHDATA2 for same data) a rejection condition, not a collision risk. Bytes-as-literal is the contract.

### 5.3.1 Normative WHITELIST offset rule (S1 AMR #3)

For output verification to be sound without ambiguity, the WHITELIST block MUST be at a **deterministic byte offset** from the body start. The rule:

```
body_offset(WHITELIST_start) = sizeof(body_marker) + sizeof(PREFIX) - sizeof(body_marker)
                             = sizeof(PREFIX_body) [where PREFIX includes the body marker]
body_offset(WHITELIST_end)   = body_offset(WHITELIST_start) + 128
```

In practice: PREFIX starts with the 2-byte body marker (§7.4). WHITELIST follows immediately after PREFIX. SUFFIX follows immediately after WHITELIST. This layout MUST hold for all 4 templates in the series; output verification assumes it.

### 5.4 Tail layout (after `OP_RETURN`)

Fixed, 145 bytes + optionalData:

```
seriesId            32 bytes    SHA256(WHITELIST)
tokenId             32 bytes    SHA256(genesisTxId ‖ contractVout ‖ issuerPkh)
redemptionPkh       20 bytes    P2PKH target for redeem
issuerPkh           20 bytes    hash160 of issuer (single-sig) OR hash160 of issuer MPKH preimage (if flags bit 4 set)
authorityFlags       1 byte     (see §5.5)
freezeAuthHash      20 bytes    hash160 of freeze authority (all-zero if !freezable)
confiscAuthHash     20 bytes    hash160 of confisc authority (all-zero if !confiscatable)
optionalData        variable    byte-exact preserved across transitions; empty allowed
```

Push-data prefix for each tail field is INCLUDED in the tail (standard Bitcoin pushdata). OptionalData can be zero, one, or multiple pushdata chunks (the same as DSTAS 1.0.4).

### 5.5 Authority flags byte

```
bit 0 (0x01): freezable enabled
bit 1 (0x02): confiscatable enabled
bit 2 (0x04): freezeAuth is MPKH (hash of canonical MPKH preimage)
bit 3 (0x08): confiscAuth is MPKH
bit 4 (0x10): issuerPkh is MPKH (hash of canonical MPKH preimage)
bits 5-7: reserved, MUST be 0
```

Semantics:

- If `freezable` disabled, `freezeAuthHash` MUST be 20 zero bytes; `Frozen` state is unreachable from this token.
- If `confiscatable` disabled, `confiscAuthHash` MUST be 20 zero bytes.
- If `freezeAuth is MPKH`, unlocking script provides the MPKH preimage (canonical m-of-n, see `DSTAS_SDK_SPEC.md` §identity-field) + m signatures. Script hashes preimage, compares to `freezeAuthHash`.
- Same for `confiscAuth`.

---

## 6. seriesId & tokenId derivation

### 6.1 seriesId

```
seriesId = SHA256(WHITELIST)
         = SHA256(h_NormalBase ‖ h_NormalSwapOnRamp ‖ h_Frozen ‖ h_SwapReady)
```

**Invariant:** seriesId uniquely identifies a deployment of BNTP v1 templates. Two tokens with identical seriesId belong to the same closed family — they could (in principle) be swapped across tokens without template mismatch (but `tokenId` prevents cross-token misuse in regular spends).

### 6.2 tokenId

```
tokenId = SHA256(genesisTxId(32b, big-endian) ‖ contractVout(4b LE) ‖ issuerPkh(20b))
```

Where:

- `genesisTxId` = txid of the Mint transaction producing the Contract output
- `contractVout` = output index of the Contract in the genesis tx
- `issuerPkh` = the P2PKH/MPKH hash that can sign the Contract's issue path

**Invariant:** every token-leg output in every spend tx MUST carry the same `tokenId` in its tail. This blocks accidental mixing of tokens and serves as the off-chain "what is this token" identifier.

### 6.3 Contract identity

Contract has its own layout: no tokenId in tail initially. The `issue` transaction creates the tokenId from Contract's genesisTxId and issuerPkh. All issued Normal outputs embed this fresh tokenId. Contract's PREFIX/SUFFIX enforces the computation.

---

## 7. Output verification protocol

Every series template's SUFFIX performs this check for every non-change output in the current transaction.

### 7.1 Output classes

| Class                           | Detection                                      | Action                                                  |
| ------------------------------- | ---------------------------------------------- | ------------------------------------------------------- |
| null-data                       | `OP_FALSE OP_RETURN` at script start           | Skip (allowed payload)                                  |
| P2PKH/P2MPKH change             | owner sig and script type matches standard     | Exclude from token conservation; must be last output(s) |
| P2PKH redeem (redeem path only) | output 0 is P2PKH with hash == `redemptionPkh` | Validate vs redeem flow (`§9.6`)                        |
| Series template                 | hash check passes (§7.2)                       | Must match token/series invariants (§7.3)               |
| Anything else                   | none of above                                  | **REJECT**                                              |

### 7.2 Series-membership hash check

For each candidate series output:

1. Extract output locking script.
2. Split the script at known offsets:
   - owner push (variable width)
   - action_data push (variable width, per §5.2)
   - **OP_2DROP** marker (1 byte)
   - body starts here
3. From body, read fixed-length PREFIX (length known per template). Body marker byte at start of PREFIX (§7.4) disambiguates which of 4 templates this is, so PREFIX length is known post-dispatch.
4. Extract WHITELIST block (128 bytes at fixed offset from body start — normative rule §5.3.1 — immediately after PREFIX).
5. **Byte-match** `output.WHITELIST == this.WHITELIST` (128 bytes compared via `OP_EQUALVERIFY` after concat). This anchors the output to this series.
6. Compute `h_candidate = SHA256(PREFIX_extracted ‖ SUFFIX_extracted)` (omit WHITELIST).
7. Verify `h_candidate ∈ {h_NormalBase, h_NormalSwapOnRamp, h_Frozen, h_SwapReady}` by comparing against the 4 hashes in the embedded WHITELIST.

This combination (steps 5 + 7) guarantees:

- The output belongs to this specific series (whitelist bytes identical)
- The output uses one of the 4 known template bodies (hash in the embedded list)
- No self-reference loop (hash doesn't include whitelist bytes)

**Per-path output-template restrictions (S2 AMR #3):** each spend path MAY restrict which subset of the 4 whitelist hashes are acceptable for its outputs. For example:

- NormalBase path 1 (transfer/split) accepts only `h_NormalBase` for token-leg outputs
- NormalBase path 7 (prepare-swap-transition) accepts only `h_NormalSwapOnRamp` for the single token-leg output
- NormalBase path 4 (freeze) accepts only `h_Frozen`
- NormalSwapOnRamp path (complete-swap-prep) accepts only `h_SwapReady`

The whitelist provides the **superset** of series-valid templates; each path narrows it further. Contract's issue path accepts only `h_NormalBase` (step 7 check collapses to single hash).

### 7.3 Tail consistency check

After class-specific checks, for every series output:

1. Tail `seriesId` == this UTXO's `seriesId` — always required.
2. Tail `tokenId` == this UTXO's `tokenId` — required for same-token paths (transfer, split, merge, freeze, unfreeze, confiscate, redeem). For swap-exec, cross-token is allowed (§10).
3. Tail `redemptionPkh` == this UTXO's `redemptionPkh` — always for same-token paths.
4. Tail authority block (flags + 2 hashes) == this UTXO's authority block — always for same-token paths. Authority cannot change mid-chain.
5. Tail `optionalData` byte-exact match against this UTXO's `optionalData` — for token-leg continuity (same token, same "leg" of split/merge/swap remainder).

### 7.4 Avoiding ambiguous variant detection

Because Normal-2/4/8 have different PREFIX lengths (logic size differs), the splitting in §7.2 step 3 is ambiguous without a hint. Two resolutions:

**Option A (data marker per template):** each template body starts with a unique 2-byte prefix:

| Template         | Body marker | Purpose                                                |
| ---------------- | ----------- | ------------------------------------------------------ |
| NormalBase       | `0x01 0xff` | Normal spendable template (all paths except prep-swap) |
| NormalSwapOnRamp | `0x02 0xff` | Swap-preparation transition template                   |
| Frozen           | `0xfe 0xff` | Frozen template                                        |
| SwapReady        | `0x0f 0xff` | SwapReady template                                     |
| Contract         | `0xc0 0xff` | Contract (not in whitelist, but uses same dispatch)    |

Script reads 2 bytes, branches on value to known PREFIX length.

**Option B (length prefix as pushed data):** reserve one push-data chunk at the very start of body that encodes the PREFIX length. This adds parsing overhead.

**Recommendation:** Option A (fixed 2-byte tag). Adds 2 bytes per template, known offsets for all templates. This is the **body marker** (analogous to DSTAS 1.0.4's `0x540b` marker, but carrying semantics).

**Constraint:** body marker values are frozen at v1 spec lock. Any future template addition (v1.x) MUST pick a value not colliding with {0x01ff, 0x02ff, 0xfeff, 0x0fff, 0xc0ff} and update the whitelist accordingly.

**Output-body-marker gating per path (S2 AMR #3 refinement):** each spend path validates not only that output's `h_candidate` is in the whitelist, but also that the output's body marker matches the specific expected template for this spend path's target. This prevents marker-confusion attacks where attacker crafts an output with marker of template A but WHITELIST/SUFFIX of template B.

### 7.5 Output ordering rule

To simplify SUFFIX logic, impose canonical output ordering:

```
Output 0..K-1     : token-leg outputs (series templates)    — K ≥ 1 unless redeem
Output K          : null-data (OP_RETURN message), optional
Output K+1        : P2PKH/P2MPKH change, optional (at most 1)
Output K+2        : P2PKH royalty to issuerPkh, REQUIRED on prepare-swap path only (§9.4)
```

Exception: redeem transactions place the P2PKH redeem output at index 0, followed by optional Normal remainders (up to 3), then null-data, then change.

---

## 8. Authority verification

### 8.1 Single-sig authority (flags bit 2/3 = 0)

`freezeAuthHash` is `hash160(compressed_pubkey)`. Unlocking provides pubkey + signature. Script verifies `HASH160(pubkey) == freezeAuthHash` and runs `OP_CHECKSIGVERIFY`.

### 8.2 MPKH authority (flags bit 2/3 = 1)

`freezeAuthHash` is `HASH160(mpkh_preimage)` where `mpkh_preimage` is the canonical m-of-n MPKH byte string (per DSTAS 1.0.4 identity-field spec):

```
mpkh_preimage = [m] ‖ [push33 ‖ pubKey_i]_{i=1..n} ‖ [n]
```

Unlocking provides:

```
[OP_0]                  (dummy for CHECKMULTISIG)
[sig_1, ..., sig_m]     (m DER-encoded signatures)
[mpkh_preimage]         (variable bytes, 36..171b)
```

Script performs:

1. `HASH160(mpkh_preimage) == freezeAuthHash` → OP_EQUALVERIFY
2. Parse m and n from preimage
3. `OP_CHECKMULTISIGVERIFY` against preimage-derived pubkey set

### 8.3 Authority cannot change

A token's authority block (41 bytes: flags + freeze + confisc hashes) plus issuerPkh (20 bytes) is fixed at issuance and MUST be preserved in every token-leg output for that token. Authority and issuer rotation are not supported in v1. Token issuer who wants rotatable authority/issuer uses MPKH with BIP32/threshold-signature off-chain rotation.

### 8.4 Issuer verification (used on prepare-swap and redeem paths)

`issuerPkh` is `hash160(compressed_pubkey)` for single-sig issuer, or `HASH160(mpkh_preimage)` for MPKH issuer (authority flags bit 4 set).

For single-sig issuer, unlocking provides pubkey + signature. Script verifies `HASH160(pubkey) == issuerPkh` and runs `OP_CHECKSIGVERIFY` against the relevant message (preimage for redeem, attestation-message for prepare-swap per §9.4).

For MPKH issuer, unlocking provides MPKH preimage + m signatures, identical to §8.2 mechanics but against `issuerPkh`.

---

## 9. Spend paths — detailed

This section defines WHICH unlocking push sequence triggers each path and what the script verifies.

### 9.1 Common stack layout

Unlocking script always ends with:

```
... [preimage] [spend_path_id: 1..9] [sig] [pubKey]
```

`spend_path_id` is an explicit small integer that disambiguates WHICH path within a template is being used. Values are template-scoped (not global):

| path_id | NormalBase              | NormalSwapOnRamp   | Frozen     | SwapReady | Contract |
| ------- | ----------------------- | ------------------ | ---------- | --------- | -------- |
| 1       | transfer/split          | abort-swap-prep    | —          | cancel    | —        |
| 2       | merge-K (K ∈ [2, 4])    | —                  | —          | —         | —        |
| 3       | prepare-swap-transition | complete-swap-prep | —          | —         | —        |
| 4       | freeze                  | —                  | unfreeze   | —         | —        |
| 5       | confiscate              | —                  | confiscate | —         | —        |
| 6       | redeem                  | —                  | —          | —         | —        |
| 7       | —                       | —                  | —          | swap-exec | —        |
| 8       | —                       | —                  | —          | —         | issue    |

Path_id is pushed as OP_1..OP_8. Each template script validates `path_id ∈ WHERE dispatching` via `OP_DUP OP_1 OP_8 OP_WITHIN OP_VERIFY` then branches.

**Note on path 3 semantics:** in NormalBase, path 3 is `prepare-swap-transition` (owner only, no attestation, no royalty, produces NormalSwapOnRamp). In NormalSwapOnRamp, path 3 is `complete-swap-prep` (owner + issuer attestation + royalty, produces SwapReady). Same path_id, different semantics per template — consistent with two-step flow (§4.2 rule 2).

**Note on path 1 semantics:** in NormalBase, path 1 is transfer/split (produces 1..4 NormalBase). In NormalSwapOnRamp, path 1 is `abort-swap-prep` (produces 1 NormalBase, no royalty, owner backs out). In SwapReady, path 1 is `cancel` (produces 1 NormalBase, owner aborts the swap offering).

### 9.2 NormalBase, path 1 (transfer/split)

**Unlocking:**

```
[output_tuples...]           reverse-order pushes, see below
[null-data payload?]         if present
[funding_txid 32b LE]
[funding_vout]
[preimage]
[OP_1]                       path_id = 1
[sig]
[pubKey]
```

Output tuple format (per token-leg output, pushed from last output back to first):

```
[satoshis ≥ 1]
[owner_field]                20b or MPKH preimage
[new_action_data]            per target template (OP_0 for Normal, OP_2 for Frozen, 62b descriptor for SwapReady)
[body_marker]                2b (§7.4): 0x01ff for Normal, 0xfeff for Frozen, 0x0fff for SwapReady
```

Note: transfer/split path only produces Normal outputs (to produce Frozen/SwapReady, use path 3 prepare-swap or path 4 freeze respectively). The output tuple format is unified across paths for SDK convenience; the script rejects non-Normal body_marker on path 1.

The script reconstructs expected output locking script:

```
output_script = owner_push ‖ action_data_push ‖ OP_2DROP
              ‖ body_marker ‖ PREFIX_expected
              ‖ WHITELIST (from this UTXO)
              ‖ SUFFIX_expected
              ‖ OP_RETURN
              ‖ tail_from_this_UTXO (seriesId, tokenId, redemptionPkh, issuerPkh, authority, optionalData)
```

Script verifies:

1. `HASH256(reconstructed_outputs ‖ change ‖ null-data) == hashOutputs(from preimage)` — covenant
2. `Σ satoshis_out == satoshis_in` (transfer/split is 1→N)
3. Each output satoshis ≥ 1
4. Owner sig valid for preimage
5. `HASH160(pubKey) == owner_field_from_scriptCode`
6. Target is Normal (body_marker = 0x01ff)
7. Target tail matches (§7.3)

**Output count:** 1..4 (split up to 4 legs per single input).

**Null-data output:** 1 optional, bytes pushed in unlocking.

**Change output:** 1 optional P2PKH/P2MPKH, last output. IS covered by hashOutputs (SIGHASH_ALL). Unlocking provides change satoshis + change scriptPubKey; script includes it in output reconstruction.

**Funding input:** detected by SDK at signing time (non-BNTP input in tx). Must be exactly one non-STAS input, else script fails (structural constraint; see `BNTP_INVARIANTS.md`).

### 9.3 NormalBase, path 2 (merge-K, K ∈ [2, 4])

A single Normal template supports merging 2, 3, or 4 inputs. `followerCount = K - 1` is pushed explicitly in anchor unlocking and verified `∈ [1, 3]`.

**Input positions:**

- inputs[0] = anchor (this script runs as anchor when its input position is 0)
- inputs[1..K-1] = followers
- inputs[K] (usually) = funding P2PKH

**Detection:** the script checks `inputPosition == 0` via the outpoint in preimage compared to hashPrevouts position. If 0 → anchor path. Else → follower path.

**Anchor unlocking (input[0]):**

```
[output_tuples...]                max 2 outputs (1..2 Normal)
[null-data?]
[funding_txid] [funding_vout]
[follower_1_mergeVout]
[follower_1_prev_tx_pieces...]   split by this UTXO's counterpartyScript
[follower_1_piece_count]
[follower_2_mergeVout]            (if K ≥ 3)
[follower_2_prev_tx_pieces...]
[follower_2_piece_count]
[follower_3_mergeVout]            (if K == 4)
[follower_3_prev_tx_pieces...]
[follower_3_piece_count]
[followerCount K-1]               explicit push, range 1..3
[all_input_outpoints 36b×K]       for inputPosition verification
[preimage]
[OP_2]                            path_id = 2
[sig]
[pubKey]
```

Anchor script verifies:

1. `followerCount ∈ [1, 3]`
2. `HASH256(all_input_outpoints ‖ funding_outpoint) == hashPrevouts` (from preimage)
3. Self-outpoint is at index 0 in the provided list → confirms anchor position
4. For each i in 1..followerCount:
   - Reconstruct `follower_i_prev_tx` from pieces ‖ this.counterpartyScript
   - `HASH256(reconstructed) == hashPrevouts.txid[i]` (from the provided outpoint list)
   - Extract output at `follower_i_mergeVout` → locking script + satoshis
   - Verify locking script is `Normal` with same seriesId, tokenId, redemptionPkh, issuerPkh, authority, optionalData (same token)
   - Accumulate `satoshis_follower_i`
5. `Σ (this.satoshis + satoshis_follower_1 + ... + satoshis_follower_{K-1}) == Σ satoshis_out`
6. Each output is Normal (body_marker = 0x01ff)
7. Standard owner-sig checks

**Follower unlocking (inputs[1..K-1]):**

```
[anchor_mergeVout]
[anchor_prev_tx_pieces...]
[anchor_piece_count]
[all_input_outpoints 36b×K]       for inputPosition verification
[selfPosition]                     push 1..3
[preimage]
[OP_2]                            path_id = 2
[sig]
[pubKey]
```

Follower script verifies:

1. `selfPosition ∈ [1, 3]`
2. `HASH256(all_input_outpoints ‖ funding_outpoint) == hashPrevouts`
3. Self-outpoint is at index `selfPosition` in list → confirms follower position
4. Reconstruct `anchor_prev_tx` from pieces ‖ this.counterpartyScript
5. `HASH256(reconstructed) == hashPrevouts.txid[0]`
6. Extract output at `anchor_mergeVout` from anchor_prev_tx → verify it's `Normal` with same token (same seriesId/tokenId/etc.)
7. Owner sig valid (follower's own owner)
8. Follower DELEGATES conservation to anchor. Safe because:
   - Anchor's script WILL run and WILL verify full conservation
   - If anchor's script fails, whole tx fails
   - Follower's reconstruction proves anchor is a legitimate `Normal` same-token UTXO

**Inputposition determination (both paths):** both anchor and follower require the full list of input outpoints provided in unlocking, hashed and verified against `hashPrevouts`. This ensures no ambiguity about which input is which. **The provided outpoints list is trusted only because its hash matches the covenant-verified `hashPrevouts`.**

**Merge-K cost breakdown:**

- Anchor: K-1 reconstructions, K-1 token-consistency checks, full output verification
- Follower: 1 reconstruction, 1 token-consistency check, delegate conservation
- Total script work: anchor does O(K), each follower does O(1) → total reconstructions: `2(K-1)`
- Unlocking size anchor: ~230 + (K-1)×2500b prev tx pieces
- Unlocking size follower: ~230 + 2500b (anchor's prev tx)

### 9.4 Prepare-swap is a TWO-STEP flow (Option A)

To keep `NormalBase` body within budget, entering `SwapReady` state requires **two transactions**, governed by two different templates:

- **Step A: NormalBase path 3 (prepare-swap-transition)** — owner-sig only, no issuer involvement. Transitions NormalBase → NormalSwapOnRamp. Cheap, owner can abort any time via path 1 (abort-swap-prep).
- **Step B: NormalSwapOnRamp path 3 (complete-swap-prep)** — owner-sig + issuer attestation (null-data output) + royalty output. Transitions NormalSwapOnRamp → SwapReady.

**Rationale for two-step:** issuer attestation logic (null-data parsing, hash binding, CHECKSIG against arbitrary data) is expensive in pseudo-ASM. Moving it out of `NormalBase` into dedicated `NormalSwapOnRamp` keeps NormalBase body within ≤3000b. NormalSwapOnRamp is a small dedicated template (~1500b) focused only on the swap-prep completion.

**AMR #1 redesign:** The issuer attestation mechanism uses **null-data output covered by SIGHASH_ALL**, not a second generator-point CHECKSIG-over-hash pattern. See §9.4.2 below.

#### 9.4.1 NormalBase path 3 — prepare-swap-transition

Owner-initiated state move from `NormalBase` to `NormalSwapOnRamp`. No issuer, no royalty. Just a state rename with preserved value + owner + token fields.

**Unlocking:**

```
[nso_output_satoshis]              must == this.satoshis
[nso_output_owner]                 must == this.owner
[NormalSwapOnRamp body_marker 0x02ff]
[null-data?]
[funding_txid] [funding_vout]
[preimage]
[OP_3]                            path_id = 3
[owner_sig]
[owner_pubkey]
```

Script verifies:

1. Owner sig valid against preimage, `HASH160(owner_pubkey) == owner_field_from_scriptCode`
2. Exactly 1 token-leg output at index 0, body_marker = 0x02ff (NormalSwapOnRamp)
3. Satoshis preserved: `nso_output_satoshis == this.satoshis`
4. Owner preserved: `nso_output_owner == this.owner`
5. Tail fields match (same token, same series)
6. HashOutputs covenant matches

Output-body-marker restriction: only `h_NormalSwapOnRamp` is acceptable as target for this path (§7.2 gating).

#### 9.4.2 NormalSwapOnRamp path 3 — complete-swap-prep (with issuer attestation)

This is where the DEX back-to-genesis gate is enforced on-chain. Owner has already transitioned to `NormalSwapOnRamp`; now, with issuer's approval, they complete the move to `SwapReady`.

**Output layout:**

```
Output 0: SwapReady (token-leg, with swap descriptor)
Output 1: null-data — issuer attestation (REQUIRED at this fixed index)
Output 2: P2PKH royalty to issuerPkh (REQUIRED)
Output 3: null-data (optional message)
Output 4: P2PKH change (optional)
```

**Null-data attestation format (at output index 1):**

```
scriptPubKey = OP_FALSE OP_RETURN
               <tokenId 32b>           attestation field #1
               <thisOutpoint 36b>      attestation field #2 (current UTXO's outpoint)
               <timestamp 8b LE>       attestation field #3 (issuer-chosen, unix seconds)
               <issuerPubkey 33b>      attestation field #4 (issuer's compressed pubkey, or MPKH preimage)
satoshis = 0
```

**Issuer attestation mechanism (AMR #1 redesign — null-data + SIGHASH_ALL):**

Instead of asking the script to CHECKSIG over `HASH256(tokenId ‖ outpoint ‖ timestamp)` — which BSV Script cannot natively do — we exploit the fact that `hashOutputs` in the preimage (under SIGHASH_ALL) commits to ALL outputs, including the null-data attestation.

Therefore:

1. User constructs the full tx (including null-data attestation output).
2. User asks issuer to sign the **transaction preimage** (SIGHASH_ALL | SIGHASH_FORKID = 0x41).
3. Issuer verifies: tokenId belongs to them, chain is OK off-chain (back-to-genesis check), attestation fields in the null-data output match expectations, royalty output is present.
4. If all checks pass, issuer returns signature.
5. User inserts signature into unlocking, broadcasts.

Script verifies at spend time:

1. Owner sig valid against preimage
2. Exactly 1 token-leg output at index 0, body_marker = 0x0fff (SwapReady)
3. Its swap_descriptor well-formed: first byte `0x01`, requestedScriptHash 32b, requestedPkh 20b, rateNum 4b, rateDenom 4b, reserved 1b = 0x00
4. Satoshis preserved: `swap_output_satoshis == this.satoshis`
5. Owner in SwapReady output == this.owner
6. Tail fields match (same token, same series)
7. **Null-data attestation output** at index 1:
   - scriptPubKey starts with `0x00 0x6a` (OP_FALSE OP_RETURN)
   - Contains pushed fields at expected byte offsets
   - `attestation_tokenId == this.tokenId`
   - `attestation_outpoint == thisOutpoint` (from preimage)
   - `attestation_pubkey HASH160 == this.issuerPkh` (for single-sig issuer) OR `attestation_pubkey HASH160 == this.issuerPkh` (for MPKH, where `attestation_pubkey` field carries MPKH preimage)
   - `attestation_satoshis == 0` (null-data convention)
8. **Royalty output** at index 2:
   - scriptPubKey = P2PKH(issuerPkh)
   - satoshis ≥ royaltyMin (embedded template constant)
9. **Issuer signature valid against the tx preimage** via standard CHECKSIGVERIFY — this is the normal covenant mechanism. Because SIGHASH_ALL binds the null-data content, a valid issuer signature implies the null-data attestation bytes are issuer-approved.
10. HashOutputs covenant matches reconstruction

**Unlocking:**

```
[swap_output_satoshis]
[swap_output_owner]
[swap_descriptor 62b]
[SwapReady body_marker 0x0fff]
[null-data-attestation bytes]        full null-data scriptPubKey (for reconstruction)
[royalty_satoshis]
[null-data-msg?]                      optional output 3 null-data
[change_satoshis] [change_script?]    optional output 4 P2PKH change
[funding_txid] [funding_vout]
[issuer_sig]                          DER-encoded; covers preimage via SIGHASH_ALL
[issuer_pubkey]                       or absent for MPKH (preimage carried in null-data)
[preimage]
[OP_3]                                path_id = 3
[owner_sig]
[owner_pubkey]
```

**Security model notes:**

- Issuer signature covers the entire tx via `hashOutputs`. Therefore, an issuer sig implies approval of ALL tx fields including null-data attestation content. This is stronger than signing just `HASH256(tokenId ‖ outpoint ‖ timestamp)` because issuer also implicitly approves royalty amount, change output, etc.
- Issuer can refuse to sign if the tx is malicious (unreasonable royalty, wrong owner, etc.).
- Timestamp is advisory; on-chain script does NOT verify freshness. SDK/indexer uses timestamp to reject stale SwapReady during discovery.
- Issuer compromise → all future attestations trustless (equivalent severity to DSTAS confisc auth compromise). Mitigate via MPKH issuer (authorityFlags bit 4).
- Replay protection: `thisOutpoint` in attestation binds to a specific UTXO; issuer's signature over preimage binds to the specific spend tx. Issuer cannot be tricked into signing the same attestation for a different UTXO.

**Size implication:**

- Attestation verification in NormalSwapOnRamp: ~100-130b (parsing null-data fields, byte comparisons, standard CHECKSIG) vs ~200b for the original CHECKSIG-over-hash alternative.
- Extra output in tx: ~50-70b null-data bytes.
- Net win: template body saves ~70-100b; tx grows ~50-70b. Worth the trade.

#### 9.4.3 NormalSwapOnRamp path 1 — abort-swap-prep

Owner backs out of swap preparation before issuer completes attestation. Produces NormalBase, restoring the original state.

**Unlocking:**

```
[nb_output_satoshis]               must == this.satoshis
[nb_output_owner]                  must == this.owner
[NormalBase body_marker 0x01ff]
[null-data?]
[funding_txid] [funding_vout]
[preimage]
[OP_1]                            path_id = 1
[owner_sig]
[owner_pubkey]
```

Script verifies:

1. Owner sig valid
2. Exactly 1 token-leg output at index 0, body_marker = 0x01ff (NormalBase)
3. Satoshis preserved
4. Owner preserved
5. Tail fields match
6. HashOutputs covenant matches

No issuer, no royalty — this is a pure ownership-controlled reversal.

### 9.5 NormalBase, paths 4 & 5 (freeze, confiscate)

**Freeze (path 4):**

Unlocking provides authority sig (single-sig or MPKH). Output: 1 Frozen UTXO (same owner, same value, same token).

```
[frozen_output_satoshis]          must == this.satoshis
[frozen_output_owner]             must == this.owner
[Frozen body_marker 0xfeff]
[null-data?]
[funding_txid] [funding_vout]
[preimage]
[OP_4]                            path_id = 4
[auth_sig]                        or [OP_0, sig_1..sig_m, mpkh_preimage] for MPKH
[auth_pubkey]                     absent for MPKH
```

Script verifies:

1. Flags bit 0 set (freezable)
2. Authority signature valid against `freezeAuthHash`
3. Exactly 1 Frozen output (body_marker 0xfeff), same owner, same satoshis, same token
4. Owner field is UNCHANGED (authority doesn't move ownership on freeze)

**Confiscate (path 5):**

Similar, but uses confiscation authority and ALLOWS owner change:

```
[normal_output_satoshis]          must == this.satoshis
[new_owner_field]                 authority's choice
[Normal body_marker 0x01ff]
[null-data?]
[funding_txid] [funding_vout]
[preimage]
[OP_5]                            path_id = 5
[auth_sig] [auth_pubkey]          or MPKH form
```

Script verifies:

1. Flags bit 1 set (confiscatable)
2. Authority signature valid against `confiscAuthHash`
3. Exactly 1 Normal output (body_marker 0x01ff), satoshis preserved, same token, new owner free

### 9.6 NormalBase, path 6 (redeem, issuer only)

Issuer burns all or part of a token leg by producing a P2PKH output to `redemptionPkh` plus optional NormalBase remainders.

**Unlocking:**

```
[P2PKH_output_satoshis]
[NormalBase_remainder_tuples ...] 0..3 remainders
[null-data?]
[funding_txid] [funding_vout]
[preimage]
[OP_6]                            path_id = 6
[issuer_sig]                      or [OP_0, sig_1..sig_m, mpkh_preimage] for MPKH issuer
[issuer_pubkey]                   absent for MPKH issuer
```

Script verifies:

1. Output 0 is P2PKH with hash == `redemptionPkh`
2. Outputs 1..R are NormalBase (body_marker 0x01ff), same token (R ∈ 0..3)
3. `Σ (P2PKH.satoshis + Σ NormalBase.satoshis) == this.satoshis`
4. Issuer identity verified per §8.4: single-sig (`HASH160(issuer_pubkey) == issuerPkh` + `CHECKSIG` against preimage), or MPKH (hash preimage, CHECKMULTISIG)

### 9.7 Frozen, paths 4 & 5 (unfreeze, confiscate)

**Unfreeze (path 4):**

Unlocking provides freeze authority sig. Output: 1 NormalBase UTXO, same token, same owner, same value.

```
[nb_output_satoshis]              == this.satoshis
[nb_output_owner]                 == this.owner
[NormalBase body_marker 0x01ff]
[null-data?]
[funding_txid] [funding_vout]
[preimage]
[OP_4]                            path_id = 4 in Frozen context
[auth_sig] [auth_pubkey]          or MPKH form
```

Verification parallels freeze but reverses the state (Frozen → NormalBase).

**Confiscate from Frozen (path 5):** same as NormalBase confiscate but source is Frozen. New owner free; output is NormalBase.

### 9.8 SwapReady, path 1 (cancel)

Owner cancels their swap and returns to NormalBase. Note: path_id for SwapReady cancel is **1**, not 3 (per updated dispatch table §9.1).

```
[nb_output_satoshis]              == this.satoshis
[nb_output_owner]                 == this.owner
[NormalBase body_marker 0x01ff]
[null-data?]
[funding_txid] [funding_vout]
[preimage]
[OP_1]                            path_id = 1 in SwapReady context
[sig]
[pubKey]
```

Script verifies:

1. Owner sig valid
2. Exactly 1 NormalBase output, same owner, same satoshis, same token (tokenId, redemptionPkh, issuerPkh, authority, optionalData preserved)

### 9.9 SwapReady, path 7 (swap-exec — cross-token)

The complex one. Two SwapReady inputs, each with their own swap descriptor. Cross-token.

**Input layout:**

- inputs[0] = leg A (this.tokenId_A)
- inputs[1] = leg B (this.tokenId_B)
- inputs[2] = funding P2PKH (optional)

Both legs MUST have matching `requestedScriptHash` pointing at each other's counterparty script hash, and matching rates (or complementary rates).

**Matching conditions:**

- `leg_A.swap.requestedScriptHash == SHA256(extractCounterpartyScript(leg_B.locking_script))`
- `leg_B.swap.requestedScriptHash == SHA256(extractCounterpartyScript(leg_A.locking_script))`
- `leg_A.swap.requestedPkh == pkh` receiving leg A's output (typically leg_B's owner)
- `leg_B.swap.requestedPkh == pkh` receiving leg B's output (typically leg_A's owner)
- rates consistency: `leg_A.swap.rateNum × leg_B.swap.rateDenom == leg_A.swap.rateDenom × leg_B.swap.rateNum` (cross-multiplied to avoid division)

**Output layout:**

```
Output 0: NormalBase, owner = leg_A.swap.requestedPkh, satoshis = X_A        [principal A]
Output 1: NormalBase, owner = leg_B.swap.requestedPkh, satoshis = X_B        [principal B]
Output 2: SwapReady remainder for leg A     (if leg A had leftover)           [optional]
Output 3: SwapReady remainder for leg B     (if leg B had leftover)           [optional]
Output K: null-data                                                           [optional]
Output K+1: P2PKH change                                                      [optional]
```

Each leg's script verifies:

1. This UTXO's swap_descriptor is parsed; requestedScriptHash is known
2. The OTHER leg's locking script is reconstructed via counterparty-script-splitting (as in merge). Its tail is extracted and verified against this leg's `requestedScriptHash`: `SHA256(other_leg.counterpartyScript) == this.swap.requestedScriptHash`
3. Principal output for this leg (index 0 if this is leg A, index 1 if leg B): owner == `this.swap.requestedPkh`, tokenId from other leg (cross-token), satoshis per rate
4. Remainder output (if present): SwapReady with same descriptor, owner preserved, satoshis == (this.satoshis - X_this_leg), same tokenId (leg's own)
5. Rate check (integer form): `X_this_leg × swap.rateDenom ≤ this.satoshis × swap.rateNum` (principal receives up to proportional amount)
6. Owner sig valid

**Remainder semantics:** after partial swap, remainder keeps swap-ready state with unchanged descriptor, so further partial swaps can continue. Owner can cancel remainder via path 3 to recover Normal.

**Cross-token seriesId:** both legs must have identical `seriesId` (same BNTP deployment), but `tokenId` differs. Principal output for leg A uses leg B's tokenId (user receives leg B's token).

### 9.10 Contract, path 8 (issue)

Issuer spends the Contract UTXO to produce N initial Normal outputs.

**Unlocking:**

```
[output_tuples...]                N outputs, all Normal
[null-data?]
[funding_txid] [funding_vout]
[genesisTxId 32b BE]              Contract's own txid, provided by issuer
[preimage]
[OP_8]                            path_id = 8
[issuer_sig]                      or MPKH form
[issuer_pubkey]                   absent for MPKH
```

Contract script verifies:

1. Issuer identity per §8.4
2. All N outputs are Normal (body_marker 0x01ff)
3. All N outputs share the same seriesId (Contract's), same tokenId (computed from provided `genesisTxId ‖ contractVout ‖ issuerPkh`), same redemptionPkh (Contract's), same issuerPkh, same authority (Contract's), same optionalData
4. `Σ Normal.satoshis == Contract.satoshis`

**Contract genesisTxId:** the Contract's own txid is not available in its own preimage (the preimage covers the tx that SPENDS the Contract, not the tx that created it). Issuer provides `genesisTxId` in unlocking; script verifies `tokenId` in outputs matches `SHA256(provided_genesisTxId ‖ contractVout ‖ issuerPkh)`. The Contract doesn't cryptographically verify this txid. If issuer lies about genesisTxId, the resulting tokens will have a wrong tokenId and off-chain validators reject them. **Known limitation, same as DSTAS 1.0.4** — see `BNTP_CRITICAL_REVIEW.md` §2.

**Alternative considered:** tokenId = `SHA256(issuer_sig || issuerPkh)`. Issuer's sig covers preimage including Contract outpoint. More rug-resistant but tied to signature non-malleability. **Deferred to v2.**

---

## 10. Swap mechanics — clarifications

### 10.1 Single-level only

`action_data` in SwapReady contains exactly ONE swap descriptor (62b). No `.next` chain. This simplifies parsing and removes a class of DSTAS 1.0.4 complexity.

Owner wanting multi-leg swap must chain them explicitly: each swap-exec produces a new Normal, which owner can re-prepare into a new SwapReady for the next leg (requires fresh issuer attestation each time, by design — off-chain B2G gate re-entered per swap). Multi-hop swaps are off-chain orchestration, not on-chain.

### 10.2 Cancel = no-op state transition

SwapReady-cancel produces Normal with IDENTICAL owner, satoshis, tokenId, redemption, issuer, authority, optionalData. Only action_data changes (swap descriptor → OP_0) and body_marker changes (0x0fff → 0x01ff).

### 10.3 Requested script hash commitment

In leg A's swap descriptor, `requestedScriptHash = SHA256(B_counterpartyScript)` where B_counterpartyScript is everything after leg B's owner+action_data push (same extraction as DSTAS 1.0.4). This commits A's participation to receiving a specific template+tail (which fixes tokenId, authority, etc.) without fixing B's owner.

B's owner is fluid because swap can partially execute over many txs (remainder preserved).

### 10.4 Rate validation

Integer-only:

```
X_leg × rateDenom ≤ input_leg.satoshis × rateNum
```

With rate_num = 0 AND rate_denom = 0 → swap-cancel-only mode (no actual execution possible; only cancel). This matches DSTAS 1.0.4 sentinel.

Floor-rounding loss is capped at `rateDenom - 1` satoshis per execution. SDK should warn if rateDenom > 2³² / 2.

### 10.5 No cross-series swap

`leg_A.seriesId == leg_B.seriesId` required. Different BNTP deployments cannot interoperate via in-script swap. Cross-series exchanges must use custodial/federated bridges or future protocol versions.

---

## 11. Unlocking script catalog (summary)

For quick reference, unlocking push sequence per template × path:

| Template         | Path                    | Path_id | Key pushes (from top of stack down, reversed for order into stack)                                                                                                          |
| ---------------- | ----------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NormalBase       | transfer/split          | 1       | pubKey, sig, OP_1, preimage, funding_outpoint, null-data?, output_tuples (NormalBase)…                                                                                      |
| NormalBase       | merge-K (anchor)        | 2       | pubKey, sig, OP_2, preimage, all_input_outpoints, followerCount, follower-data × (K-1), funding_outpoint, null-data?, output_tuples                                         |
| NormalBase       | merge-K (follower)      | 2       | pubKey, sig, OP_2, preimage, selfPosition, all_input_outpoints, anchor-data                                                                                                 |
| NormalBase       | prepare-swap-transition | 3       | owner_pubkey, owner_sig, OP_3, preimage, funding_outpoint, null-data?, nso_output_tuple (NormalSwapOnRamp target)                                                           |
| NormalBase       | freeze                  | 4       | auth_pubkey, auth_sig, OP_4, preimage, funding_outpoint, null-data?, frozen_output_tuple                                                                                    |
| NormalBase       | confiscate              | 5       | auth_pubkey, auth_sig, OP_5, preimage, funding_outpoint, null-data?, nb_output_tuple                                                                                        |
| NormalBase       | redeem                  | 6       | issuer_pubkey, issuer_sig, OP_6, preimage, funding_outpoint, null-data?, remainders (NormalBase)…, p2pkh_sats                                                               |
| NormalSwapOnRamp | abort-swap-prep         | 1       | owner_pubkey, owner_sig, OP_1, preimage, funding_outpoint, null-data?, nb_output_tuple (NormalBase target)                                                                  |
| NormalSwapOnRamp | complete-swap-prep      | 3       | owner_pubkey, owner_sig, OP_3, preimage, issuer_pubkey, issuer_sig, funding_outpoint, change?, null-data?, royalty_satoshis, attestation_null_data_bytes, swap_output_tuple |
| Frozen           | unfreeze                | 4       | auth_pubkey, auth_sig, OP_4, preimage, funding_outpoint, null-data?, nb_output_tuple                                                                                        |
| Frozen           | confiscate              | 5       | auth_pubkey, auth_sig, OP_5, preimage, funding_outpoint, null-data?, nb_output_tuple                                                                                        |
| SwapReady        | cancel                  | 1       | pubKey, sig, OP_1, preimage, funding_outpoint, null-data?, nb_output_tuple                                                                                                  |
| SwapReady        | swap-exec               | 7       | pubKey, sig, OP_7, preimage, funding_outpoint, null-data?, output_tuples, other_leg_pieces, other_leg_counterparty_script                                                   |
| Contract         | issue                   | 8       | issuer_pubkey, issuer_sig, OP_8, preimage, genesisTxId, funding_outpoint, null-data?, output_tuples (NormalBase)                                                            |

All output_tuples are pushed in reverse order (last output first, so they pop in forward order during script reconstruction).

---

## 12. Size estimates

### 12.1 Template body (PREFIX + WHITELIST + SUFFIX)

| Template         | PREFIX | WHITELIST | SUFFIX | Body marker | **Body total**      | Notes                                                |
| ---------------- | ------ | --------- | ------ | ----------- | ------------------- | ---------------------------------------------------- |
| NormalBase       | ~1100b | 128b      | ~1770b | 2b          | **~3000b (target)** | 6 paths; largest template; merge-K dominates         |
| NormalSwapOnRamp | ~900b  | 128b      | ~470b  | 2b          | **~1500b (target)** | 2 paths (abort, complete-swap-prep with attestation) |
| Frozen           | ~400b  | 128b      | ~230b  | 2b          | **~760b**           | 2 paths (unfreeze, confiscate)                       |
| SwapReady        | ~800b  | 128b      | ~570b  | 2b          | **~1500b**          | 2 paths (cancel, swap-exec)                          |
| Contract         | ~350b  | 128b      | ~220b  | 2b          | **~700b**           | 1 path (issue)                                       |

**Budget gates (per `BNTP_CRITICAL_REVIEW.md` §5.1):**

- NormalBase ≤ 3000b: G4 PASS → proceed to Phase 1
- 3000 < NormalBase ≤ 3200b: G4 PASS-with-margin; proceed cautiously
- 3200 < NormalBase ≤ 3400b: G4 PIVOT; drop or defer a feature (e.g., K=4 merge → K=2 only)
- NormalBase > 3400b: G4 ABORT; revisit Option B (drop prepare-swap from protocol)

### 12.2 Per-UTXO on-chain size (owner 20b PKH, no optionalData)

```
UTXO_size = 1 (OP_PUSH20) + 20 (owner) + 1..2 (action_data push)
          + 1 (OP_2DROP)
          + body
          + 1 (OP_RETURN)
          + 1 (OP_PUSH32) + 32 (seriesId)
          + 1 + 32 (tokenId)
          + 1 + 20 (redemptionPkh)
          + 1 + 20 (issuerPkh)
          + 1 + 1 (authFlags)
          + 1 + 20 (freezeAuth)
          + 1 + 20 (confiscAuth)
          + optionalData (0 here)
```

Fixed tail overhead = ~175b. WHITELIST is now 128b (+32b vs earlier 96b estimate).

| State            | Body | Tail | Action data | **Per-UTXO total** | vs DSTAS 1.0.4 (~3050b) |
| ---------------- | ---- | ---- | ----------- | ------------------ | ----------------------- |
| NormalBase       | 3000 | 175  | 1           | **~3200b**         | **−5%** (modest)        |
| NormalSwapOnRamp | 1500 | 175  | 1           | **~1700b**         | **−44%** (ephemeral)    |
| Frozen           | 760  | 175  | 1           | **~960b**          | **−68%**                |
| SwapReady        | 1500 | 175  | 63          | **~1760b**         | **−42%**                |
| Contract         | 700  | 175  | 1           | **~900b**          | new                     |

**Honest update:** NormalBase's per-UTXO footprint at ~3200b gives only ~5% savings vs DSTAS 1.0.4's ~3050b — **much smaller than previously advertised**. The big wins remain on Frozen (−68%) and SwapReady (−42%). See `BNTP_ALTERNATIVES_RECOMMENDATION.md` §4 for why this trade-off is still net positive.

### 12.3 Unlocking script size (examples, no MPKH)

| Path                                   | Approx. size                                           |
| -------------------------------------- | ------------------------------------------------------ |
| NormalBase transfer (1 output, change) | ~230b                                                  |
| NormalBase split (4 outputs, change)   | ~380b                                                  |
| NormalBase merge-2 (anchor)            | ~340 + 1 × 2500b = ~2840b                              |
| NormalBase merge-4 (anchor)            | ~380 + 3 × 2500b = ~7880b                              |
| NormalBase merge-K (follower)          | ~270 + 2500b = ~2770b                                  |
| NormalBase prepare-swap-transition     | ~250b                                                  |
| NormalSwapOnRamp complete-swap-prep    | ~400b (includes issuer sig + null-data reconstruction) |
| NormalSwapOnRamp abort-swap-prep       | ~230b                                                  |
| NormalBase freeze/confiscate           | ~260b                                                  |
| NormalBase redeem                      | ~250b                                                  |
| Frozen unfreeze/confiscate             | ~260b                                                  |
| SwapReady cancel                       | ~260b                                                  |
| SwapReady swap-exec                    | ~230 + other_leg_prev_tx (~2500b) = ~2730b             |
| Contract issue (N=4 NormalBase outs)   | ~450b                                                  |

**Merge-4 anchor unlocking ~8 KB.** Within BSV per-tx size limits; feasibility для pseudo-ASM ok. Followers ~2.8 KB each. Total merge-4 tx ~19 KB (see `BNTP_VS_DSTAS_COMPARISON.md` §2.5).

---

## 13. Security considerations carried forward

Reference: `DSTAS_LOCKING_SCRIPT_AUDIT.md` и `BNTP_CRITICAL_REVIEW.md`. Ключевые положения:

- **Back-to-genesis (still unresolved for non-DEX flows):** BNTP v1 closes the forward state space (outputs must be in series), but does not prove provenance for transfer/merge/freeze paths. For swap participation, **issuer attestation gate (§9.4) provides off-chain B2G validation** before entering SwapReady state. Off-chain `verifyTokenChain` still required for non-swap acceptance (receiving a payment token into wallet).
- **Sighash type enforcement:** BNTP v1 templates MUST include explicit check `sighashType == 0x41` (SIGHASH_ALL | SIGHASH_FORKID) to avoid relying on implicit hashOutputs non-zero test. +5 bytes per template.
- **Merge reconstruction:** cryptographically sound (hash256 collision resistance).
- **Rate rounding:** known floor-truncation leak; SDK must warn on extreme denominators.
- **Frozen protection matrix:** Frozen UTXO cannot be spent on owner-sig paths. Verified by template separation (Frozen has no owner-sig paths).
- **Issuer compromise risk:** compromised `issuerPkh` allows forging attestations (permitting arbitrary SwapReady creation) and signing fake redeems. Same severity as DSTAS confiscation authority compromise. Mitigation: issuer SHOULD use MPKH (authorityFlags bit 4) with threshold-signature hardware setup.

### 13.1 Attack surface: whitelist spoofing

An attacker tries to produce an output that satisfies `output.WHITELIST == this.WHITELIST` but has a mutated PREFIX/SUFFIX. Fails because:

- Step 7.2.6 computes `h_candidate` over PREFIX/SUFFIX (not whitelist).
- `h_candidate` must match one of the 4 hashes in the embedded whitelist.
- Body mutation changes `h_candidate` → hash mismatch → reject.

### 13.2 Attack surface: body marker spoofing

Attacker tries to craft an output with wrong body_marker to bypass template identification. Dispatch logic explicitly checks marker ∈ {0x01ff, 0x02ff, 0xfeff, 0x0fff, 0xc0ff} and rejects otherwise. Per-path output-marker restrictions (§7.2, §7.4) further narrow acceptable markers for each path's target.

### 13.3 New attack surface: SwapReady descriptor forgery

SwapReady's swap descriptor is owner-set. An attacker-owner could craft a descriptor with `requestedScriptHash = SHA256(legitimate_cp_script)` but `requestedPkh = attacker_pkh`. This makes a "free money" swap offer — the attacker proposes swap of X for Y=attacker's pkh. Any honest counterparty who naively executes this sends their token to the attacker for nothing.

**Mitigation (SDK-level):** SwapReady UTXOs must be advertised via a trusted channel (relay, orderbook) that displays the full descriptor. Counterparty validates descriptor makes economic sense before executing. This is off-chain protocol, not script responsibility.

---

## 14. Implementation phases

### Phase 0 — Pre-impl gates (COMPLETED 2026-04-17)

- [x] Pseudo-ASM all-paths Normal — ~4640b, exceeds 2400b budget → PIVOT
- [x] Formal whitelist commitment write-up — PASS
- [x] Anchor/follower position-check algorithm — PASS

**Outcome:** PIVOT to Option A (split Normal → NormalBase + NormalSwapOnRamp). See `BNTP_CRITICAL_REVIEW.md` §8 for Phase 0 outcome and `BNTP_ALTERNATIVES_RECOMMENDATION.md` for pivot justification.

### Phase 0.1 — Option A adoption (IN PROGRESS 2026-04-18)

- [x] Design AMR #1 issuer attestation redesign (null-data + SIGHASH_ALL)
- [x] Spec pivot to 4-template Option A architecture
- [x] Merge 11 Phase 0 SPEC AMENDMENT REQUESTs into spec
- [ ] NormalBase pseudo-ASM to opcode depth (gate G4 ≤ 3000b target)
- [ ] Gate G4 verdict

**Go/no-go:** proceed to Phase 1 if NormalBase ≤ 3200b. If 3200-3400b → minor scope reduction. If > 3400b → ABORT Option A, revisit Option B.

### Phase 1 — PoC skeleton (mint + transfer + redeem)

- `Contract` template, issue path only
- `NormalBase` template, paths: transfer/split (path 1), merge-K (path 2), redeem (path 6)
- Whitelist populated with `h_NormalBase` + 3 zero-slots (placeholders for NormalSwapOnRamp, Frozen, SwapReady)
- `seriesId` = SHA256 of this partial whitelist (PoC-only value, not production)
- Tail layout finalized (145b + optionalData)
- SDK builders for 5 tx types: mint-contract, issue, transfer, split, merge-K, redeem
- Conformance vectors for all

**Deliverable:** PoC token can be minted, transferred, split, merged (K ∈ [2, 4]), redeemed. No freeze, no swap. Demonstrates series commitment and closed forward state.

### Phase 2 — Freeze + Confiscation

- Add `Frozen` template
- Extend `NormalBase` with paths 4 (freeze), 5 (confiscate)
- Add paths 4, 5 in `Frozen`
- Update whitelist: `h_NormalBase`, `h_Frozen`, 2 zero-slots
- Update seriesId
- SDK builders for freeze, unfreeze, confiscate

**Note:** Phase 1 tokens are NOT forward-compatible with Phase 2 whitelist (seriesId changes). Phase 1 is for skeleton validation only.

### Phase 3 — SwapReady + Swap (with NormalSwapOnRamp two-step flow)

- Add `NormalSwapOnRamp` template (paths: abort, complete-swap-prep with issuer attestation)
- Add `SwapReady` template (paths: cancel, swap-exec)
- Extend `NormalBase` with path 3 (prepare-swap-transition → NormalSwapOnRamp)
- Update all templates' WHITELIST to final 4 hashes (128b block)
- **Final seriesId lock-in** at end of Phase 3
- SDK builders for prepare-swap-transition, complete-swap-prep, abort-swap-prep, swap-exec, cancel
- Issuer attestation service reference implementation (null-data output generator + preimage signer)

**Tokens minted in Phase 3 onwards are production BNTP v1.**

### Phase 4 — Audit, optimize, ship

- Full security audit of 3 deployed templates (+ Contract)
- External review of whitelist commitment scheme
- Optimize for size: remove redundant endian flips, simplify varint paths (lessons from `DSTAS_LOCKING_SCRIPT_AUDIT.md` §5)
- Conformance matrix completion
- Docs: `BNTP_INVARIANTS.md`, per-template pseudo-ASM docs
- Issuer service reference implementation
- Wallet SDK integration helpers (bundle merge before transfer, variant-free UX)

**Note:** No Phase 5. Single-variant design removed Normal-4/Normal-8 rollout. If future demand warrants, v1.x can add Normal-2 or Normal-8 as whitelist extensions in a new seriesId.

---

## 15. Resolved questions (Phase 0 + Phase 0.1)

1. ✅ **Body marker encoding (§7.4):** 2-byte tag — 0x01ff NormalBase, 0x02ff NormalSwapOnRamp, 0xfeff Frozen, 0x0fff SwapReady, 0xc0ff Contract.
2. ✅ **issuerPkh derivation for tokenId:** explicit genesisTxId provided in issue unlocking (§9.10). Revisit in v2.
3. ✅ **Sighash type explicit check:** `sighashType == 0x41 OP_EQUALVERIFY` in every template (+5b).
4. ✅ **Anti-dust rule:** enforce `satoshis ≥ 1` on every token output (+4 opcodes per output).
5. ✅ **OptionalData size limit:** SDK caps at 4096 bytes; on-chain script does not enforce (size-independent).
6. ✅ **Cross-token swap optionalData semantics:** principal inherits opposite leg's optionalData; remainder keeps own.
7. ✅ **Issuer MPKH support:** `isIssuerMpkh` flag bit 4 in authorityFlags (§5.5, §8.4).
8. ✅ **Attestation TTL semantics:** timestamp advisory on-chain; SDK/indexer enforces freshness.
9. ✅ **Issuer attestation mechanism (AMR #1):** null-data output at output index 1, covered by issuer's SIGHASH_ALL preimage signature. No CHECKSIG-over-arbitrary-hash required. See §9.4.2.
10. ✅ **Unlocking pushes full candidate scripts (S1 AMR #2):** not tuple components. SDK builder derives script bytes from (owner, action_data, body, tail).
11. ✅ **WHITELIST normative offset (S1 AMR #3):** immediately after PREFIX. See §5.3.1.
12. ✅ **WHITELIST zero-placeholder never in hash (S2 AMR #1):** explicit in §5.3.
13. ✅ **Raw-byte slices for h_candidate (S2 AMR #2):** explicit in §5.3.
14. ✅ **Body marker set per-path (S2 AMR #3):** per-path output-marker restrictions in §7.2, §7.4.
15. ✅ **Optional Contract seriesId sanity check (S2 AMR #4):** add ~40b check to Contract issue path. Accepted as optional hardening.
16. ✅ **BNTP input contiguity invariant (S3 AMR #1):** normative in §9.3 — BNTP inputs at positions [0..K-1], funding at K.
17. ✅ **all_outpoints / funding_outpoint separation (S3 AMR #2):** separate pushes in unlocking, hash over concatenation in order.
18. ✅ **followerCount cross-check (S3 AMR #3):** anchor verifies `followerCount == (|all_outpoints|/36) - 1`.
19. ✅ **BIP143 preimage offsets (S3 AMR #4):** TODO in `BNTP_INVARIANTS.md` when written.

## 15a. Remaining open questions (Phase 0.2+)

1. **Royalty minimum satoshis encoding:** 1000 sats default; finalize byte-encoding during NormalSwapOnRamp pseudo-ASM.
2. **Rate floor for SwapReady:** SDK-level rejection of `rateDenom > input_satoshis` to prevent unexecutable-partial traps. Not on-chain.
3. **OP_CODESEPARATOR optional optimization:** formal trace of interaction with OP_PUSH_TX scriptCode hashing. If safe, can share PREFIX code across templates (see alternatives evaluation candidate E).
4. **Deferred to BNTP v2:** signature-anchored tokenId derivation (more rug-resistant than explicit genesisTxId).

---

## 16. Terminology index

- **Anchor:** input[0] in merge-K (NormalBase path 2), performs full conservation check for all K STAS inputs.
- **Body:** opcode bytes between OP_2DROP and OP_RETURN.
- **Body marker:** first 2 bytes of body, identifies template (0x01ff NormalBase, 0x02ff NormalSwapOnRamp, 0xfeff Frozen, 0x0fff SwapReady, 0xc0ff Contract).
- **Counterparty script:** bytes after owner+action_data push, common to all UTXOs of same token+state.
- **Follower:** input[1..K-1] in merge-K (NormalBase path 2), performs lightweight check delegating to anchor.
- **h_X:** SHA256 shape hash of template X (excludes whitelist block).
- **Issuer attestation:** mandatory null-data output at output index 1 in complete-swap-prep tx, covered by issuer's SIGHASH_ALL signature over preimage. Carries (tokenId, outpoint, timestamp, issuerPubkey). See §9.4.2.
- **MPKH:** Multi-Pubkey Key Hash, canonical m-of-n preimage.
- **NormalBase:** principal Normal-category template. Paths 1, 2, 4, 5, 6 and prepare-swap-transition (path 3).
- **NormalSwapOnRamp:** ephemeral Normal-category template entered via NormalBase path 3. Holds complete-swap-prep (path 3, with issuer attestation) and abort-swap-prep (path 1).
- **Path_id:** small integer (1..8) in unlocking selecting the spend path within a template.
- **Preimage:** sighash preimage per BIP143/BSV covenant, accessed via OP_PUSH_TX.
- **requestedScriptHash:** in swap descriptor, SHA256 of counterparty's counterparty-script tail.
- **seriesId:** SHA256(WHITELIST), commits to the 4 body hashes in the series.
- **Tail:** fixed-layout 145-byte fields after OP_RETURN.
- **tokenId:** per-issuance unique identifier, SHA256(genesisTxId ‖ contractVout ‖ issuerPkh).
- **WHITELIST:** 128-byte constant block embedded in every template body at fixed offset after PREFIX; contains 4 body hashes (`h_NormalBase ‖ h_NormalSwapOnRamp ‖ h_Frozen ‖ h_SwapReady`).

---

## 17. Change log

- **2026-04-17** — initial draft, Series v1 with 5 templates (Normal-2/4/8, Frozen, SwapReady).
- **2026-04-17** — updated: single-variant Normal (dropped Normal-2 and Normal-8), whitelist 96b (3 hashes), DSTAS isolation rules. Decision rationale in §3.2. Audit time revised −40%.
- **2026-04-17** — updated: added issuer attestation (Способ C) on prepare-swap path (§9.4). Added `isIssuerMpkh` authority flag (§5.5). Added royalty output requirement. Simplified Phase 4 into audit/ship phase (merged with former Phase 5). Moved Phase 0 gates to explicit pre-impl checks.
- **2026-04-18** — **Phase 0.1 structural pivot to Option A.** Split `Normal` template into `NormalBase` (paths 1, 2, 4, 5, 6) + `NormalSwapOnRamp` (path 3 only). Whitelist expanded from 3 to 4 templates (128b block). Issuer attestation mechanism redesigned per AMR #1: null-data output covered by SIGHASH_ALL preimage, replacing CHECKSIG-over-arbitrary-hash pattern (~100b savings). Prepare-swap is now a two-step flow: (a) NormalBase path 3 (prepare-swap-transition, owner-only, produces NormalSwapOnRamp), (b) NormalSwapOnRamp path 3 (complete-swap-prep, owner + issuer attestation + royalty, produces SwapReady). Added NormalSwapOnRamp abort path (path 1). All 11 Phase 0 SPEC AMENDMENT REQUESTs applied. NormalBase body target revised to ≤ 3000b (G4 gate). See `BNTP_CRITICAL_REVIEW.md` §8 for outcome history.
