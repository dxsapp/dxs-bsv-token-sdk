# BNTP v2 — BSV Native Tokenization Protocol, v2 Spec

**Status:** Draft / architectural. Not yet implemented.

**Relationship to v1:** BNTP v1 (`BNTP_SERIES_V1_SPEC.md`) is a preceding research artifact. v1 optimized for locking-script body size and treated swaps as on-chain flows. Full-tx comparison (`BNTP_FULL_TX_FOOTPRINT_COMPARISON.md`) showed v1 did not strictly dominate DSTAS. v2 pivots goals: **solve STAS adoption pains (merges, B2G), not minimize footprint**. Swaps become external protocol (BNTP v2 does not know about swaps). See `BNTP_CRITICAL_REVIEW.md` §8 for outcome log.

**Scope:** state machine, template catalog, tail layout, spend paths, unlocking formats, issuer attestation mechanism, depth-based rolling freshness.

**Architecture:** 3 deployable templates (`Normal`, `Frozen`) + `Contract`. Amount stored in tail (uint128), not satoshis. Issuer attestation via null-data + SIGHASH_ALL (carried forward from v1 Способ C design, simplified). Swaps handled by external protocol layer using BNTP UTXOs as primitives.

---

## 1. Design goals

1. **Solve STAS merge pain.** Token amount lives in a tail field, not in satoshis. Unified `flex-transfer` path accepts N inputs → M outputs with on-script conservation. "Pay X from UTXO of value Y" requires one tx regardless of Y vs X relationship.
2. **Solve STAS back-to-genesis pain for swap/DEX use cases.** Issuer attestation mechanism gives wallets O(1) verification of UTXO legitimacy when attestation is fresh. Depth counter tracks freshness; rolling refresh is the recovery path.
3. **Trust-flexible.** Issuer can be PKH single-sig or MPKH threshold-sig. Owner, freeze authority, confiscation authority all independently configurable as PKH or MPKH.
4. **Compliance-capable.** Freeze and confiscation remain first-class authority paths. Redeem is not a dedicated path — it is a flex-transfer to issuer-owned address; issuer handles off-chain redemption. ETH-decimal compatibility via uint128 amount field (storage format; script arithmetic capped at ScriptNum int63 per §9.11).
5. **Simple state space.** Two spendable templates (Normal, Frozen), no swap-specific templates, no whitelist commitment scheme.

### Non-goals (v2)

- **Smaller footprint than DSTAS** — v1 chased this goal and failed to strictly dominate. v2 accepts per-UTXO parity-ish size; the win is in pain resolution, not bytes.
- **On-chain swap primitives.** Swaps are an external concern built on top of BNTP UTXOs. Cross-token atomic swap is a separate protocol layer.
- **Closed forward state via whitelist commitment.** Not needed — attestation + tokenId matching cover the same function.
- **Back-to-genesis proof in pure trustless form.** Requires ZK which is infeasible on current BSV Script; deferred indefinitely. Attestation is the pragmatic B2G solver.

---

## 2. Glossary

| Term                   | Meaning                                                                                                                                                                             |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Normal**             | Spendable token UTXO. Holds token amount, owner, tokenId, issuer reference, authority fields, attestation depth.                                                                    |
| **Frozen**             | Frozen token UTXO. Only authority can move (unfreeze or confiscate). No owner path.                                                                                                 |
| **Contract**           | Pre-issuance reserve UTXO. Spent once to issue N Normal outputs.                                                                                                                    |
| **tokenId**            | 32-byte unique identifier for a token issuance: `SHA256(genesisTxId ‖ contractVout ‖ issuerPkh)`. Identity invariant across all UTXOs of the same token.                            |
| **amount**             | uint128 (16 bytes) token quantity. Sum of amounts conserved across spend inputs and outputs of the same token.                                                                      |
| **attestation_depth**  | uint16 (2 bytes) counter. Increments by 1 on each flex-transfer. Resets to 0 on refresh. Freshness indicator for wallets.                                                           |
| **Issuer attestation** | Issuer's sig (SIGHASH_ALL) on a tx containing a well-formed null-data output with `(tokenId ‖ thisOutpoint ‖ issuerPubkey)`. Only required on refresh path (not regular transfers). |
| **Refresh**            | Explicit tx path that resets `attestation_depth` to 0 with issuer's attestation. Issuer charges royalty paid in the token itself.                                                   |
| **Flex-transfer**      | Unified N→M spend path. Conservation enforced via shared `amounts_in_array` pushed in unlocking and bound to `hashPrevouts`.                                                        |
| **MPKH**               | Multi-Pubkey Key Hash. Canonical m-of-n preimage hashed via HASH160. Spending requires preimage push + m signatures.                                                                |

---

## 3. Template catalog

Series v2 contains **2 deployable token templates** + 1 issuance template:

| #   | Template   | action_data | Role                                                  | Spent to              | Est. body                                                                      |
| --- | ---------- | ----------- | ----------------------------------------------------- | --------------------- | ------------------------------------------------------------------------------ |
| 0   | `Contract` | `OP_0`      | Pre-issuance reserve                                  | Normal × N (issue)    | ~500b                                                                          |
| 1   | `Normal`   | `OP_0`      | Spendable token, all owner + authority + issuer paths | Normal, Frozen, P2PKH | ~2500b (target, revised from initial ~2000b per Phase 0 pseudo-ASM validation) |
| 2   | `Frozen`   | `OP_2`      | Frozen token                                          | Normal                | ~600b                                                                          |

No whitelist commitment. No seriesId. No SwapReady. No NormalSwapOnRamp. No anchor/follower pattern.

### 3.1 Why 2 templates not 4

v1 had 4 templates (NormalBase, NormalSwapOnRamp, Frozen, SwapReady) to split complexity and stay under body budget. v2 goals don't include footprint minimization, and swaps are external. This lets us collapse back to a simpler topology.

Frozen remains separate because:

- Body is much smaller (~600b vs ~2000b) — per-UTXO savings for frozen state
- Spending semantics are distinct (authority-only, no owner path) — cleaner audit if separate
- Frozen UTXOs can be long-lived (compliance holds) — storage savings matter

---

## 4. State machine

### 4.1 Transitions

```
Contract
  └─(issue, issuer sig + attestation)──► Normal × N      [attestation_depth = 0 on all outputs]

Normal
  ├─(flex-transfer, owner sig)─────► Normal × M          [N→M, amounts conserved, depth +=1]
  ├─(refresh, owner sig + issuer attestation)─► Normal × 2  [user's refreshed + issuer royalty; both depth = 0]
  ├─(freeze, freezeAuth sig)────────► Frozen × 1         [depth carried forward]
  └─(confiscate, confiscAuth sig)───► Normal × 1         [new owner, depth reset to 0]

  (no dedicated redeem path; redeem is owner-initiated flex-transfer
   to issuer-owned address; issuer handles off-chain redemption)

Frozen
  ├─(unfreeze, freezeAuth sig)──────► Normal × 1         [same depth]
  └─(confiscate, confiscAuth sig)───► Normal × 1         [new owner, depth reset to 0]
```

### 4.2 Transition rules

1. **Flex-transfer is the universal owner path.** N inputs → M outputs where N ≥ 1, M ∈ [1, 4]. All inputs must share `tokenId`. Amounts conserved: `Σ input_amounts == Σ output_amounts`. Each output's `attestation_depth = max_input_depth + 1` where `max_input_depth` is a freely-pushed value collectively enforced by all input scripts (see §9.2.1).
2. **Depth propagation:** on merge-like flex-transfer (multiple inputs), the output's depth = max(input depths) + 1. This is conservative — the token's "freshness" is as old as the oldest constituent. Over-reporting `max_input_depth` results in unnecessarily-stale output UTXO (self-harm for the spender); under-reporting fails some input's script and rejects the tx.
3. **Refresh resets depth to 0.** Requires issuer attestation. Exactly 1 input → exactly 2 outputs (user's refreshed UTXO + issuer's royalty UTXO). Royalty amount is flexible (≥ 1); issuer rejects via off-chain policy if too small.
4. **Confiscation resets depth to 0.** Rationale: confiscation implies authority has vetted the new owner; fresh attestation semantically holds.
5. **Freeze preserves depth.** Frozen UTXO's depth equals the spent UTXO's depth.
6. **Unfreeze preserves depth.** Symmetric.
7. **TokenId preserved across all transitions.** Confiscation does not change tokenId.
8. **Authority block (flags + freezeAuthHash + confiscAuthHash) preserved across all transitions.**
9. **issuerPkh preserved across all transitions.**
10. **OptionalData byte-exact preserved across all token-leg outputs.**
11. **Amount sum conservation enforced on flex-transfer and refresh.** Redeem allows burn (P2PKH amount does not need to match input; remaining goes to Normal remainders with conservation: `input_amount == sum(remainder_amounts)`; P2PKH represents out-of-protocol satoshi redemption tied to token being burned).
12. **Swaps are not a protocol primitive.** External protocol may spend BNTP UTXOs, but BNTP script treats any such tx as flex-transfer (for owner-sig paths). Swap atomicity/correctness is outside BNTP scope.

---

## 5. Locking script layout

All Normal UTXOs follow this shape:

```
[Owner field]              20b PKH or MPKH preimage (35..171b)
[Action data]              OP_0 (Normal), OP_2 (Frozen)
OP_2DROP                   drop variable prefix
[Body marker]              2 bytes: 0x01 0xff (Normal), 0xfe 0xff (Frozen), 0xc0 0xff (Contract)
[PREFIX]                   template-specific opcodes (common + path-specific)
[SUFFIX]                   template-specific opcodes (output verification, tail matching)
OP_RETURN
[Tail]                     111b fixed + optionalData
```

Body = marker + PREFIX + SUFFIX. No WHITELIST block (removed from v2).

### 5.1 Variable prefix

| Field      | Size                                                     | Content             |
| ---------- | -------------------------------------------------------- | ------------------- |
| Owner      | 20b (PKH) or 35..171b (MPKH preimage — canonical m-of-n) | Spender identity    |
| ActionData | 1b (OP_0 or OP_2)                                        | State discriminator |

Owner is either plain 20b PKH or canonical MPKH preimage (per §8).

### 5.2 Tail (111 bytes fixed + optionalData)

```
tokenId           32 bytes  SHA256(genesisTxId ‖ contractVout ‖ issuerPkh)
issuerPkh         20 bytes  HASH160(issuer_pubkey) or HASH160(issuer_MPKH_preimage)
amount            16 bytes  uint128 little-endian
authorityFlags     1 byte   see §5.3
freezeAuthHash    20 bytes  HASH160(freeze authority) — 20 zero bytes if disabled
confiscAuthHash   20 bytes  HASH160(confisc authority) — 20 zero bytes if disabled
attestation_depth  2 bytes  uint16 little-endian
optionalData    variable    byte-exact preserved across all transitions
```

Total fixed: **111 bytes** (down from v1's 145b because no seriesId and no whitelist hashes).

### 5.3 Authority flags byte

```
bit 0 (0x01): freezable enabled
bit 1 (0x02): confiscatable enabled
bit 2 (0x04): freezeAuth is MPKH (hash of canonical MPKH preimage)
bit 3 (0x08): confiscAuth is MPKH
bit 4 (0x10): issuerPkh is MPKH
bit 5 (0x20): owner is MPKH
bits 6-7: reserved, MUST be 0
```

Semantics as in v1 §5.5, extended with bit 5 (owner MPKH) for compliance use cases (2-of-3 multisig wallets, N-of-M treasury, etc.).

### 5.4 Why no whitelist/seriesId

v1 used whitelist commitment to enforce "closed forward state" — outputs must be in known template set. v2 drops this because:

1. **B2G is now solved by attestation**, not by closed-state commitment. Wallet verifies via issuer sig, not via chain walk. Whitelist added cost without solving the actual problem.
2. **Swaps are external**. v1's whitelist was partly motivated by swap needing to verify counterparty's template shape. Since swaps are now outside BNTP, whitelist is unnecessary for protocol integrity.
3. **tokenId + issuerPkh are sufficient identity anchors.** Same tokenId + same issuerPkh = same token. Malicious template with different issuerPkh doesn't pass attestation check.
4. **Smaller UTXOs, simpler audit.** Removing 128-byte whitelist block + ~230 bytes of verification logic = significant simplification.

Trade-off: BNTP v2 relies entirely on off-chain verification (trusted issuer PKH registry) for "is this token legitimate". Same trust model as DSTAS+attestation, but cheaper to verify on receipt.

### 5.5 Body hash manifest (replaces whitelist commitment)

When a template needs to verify that an output is of a specific other template (e.g., Normal's freeze path produces a Frozen output, must verify the output body shape), v1's approach was to embed a 128-byte WHITELIST block listing all template body hashes. v2 takes a lighter approach.

Each template body has a canonical deployment-time hash: `h_X = SHA256(body_X)`. Other templates that need cross-template verification embed **only the specific 32-byte hash they reference**, not a full whitelist.

For v2 spec, the cross-template references are:

- `Normal` embeds `h_Frozen` (32b) — used on path 3 freeze to verify Frozen output shape
- `Contract` embeds `h_Normal` (32b) — used on path 6 issue to verify all N outputs are Normal
- `Frozen` embeds `h_Normal` (32b) — used on path 3 unfreeze to verify Normal output shape

**Total cross-reference cost:** 32b × 3 references = 96b across the 3 templates (vs v1's 128b × 4 templates = 512b total).

**Deployment manifest (not on-chain):** a separate document or repository file that lists all template hashes and their deployment addresses. Used by SDK/indexer to assemble the constants during template compilation. Off-chain artifact.

**Security:** same as v1 whitelist. Hash preimage resistance on SHA-256 prevents forgery; byte-exact embedded hash prevents substitution.

---

## 6. tokenId derivation

Same as v1:

```
tokenId = SHA256(genesisTxId(32b BE) ‖ contractVout(4b LE) ‖ issuerPkh(20b))
```

Where:

- `genesisTxId` = txid of the Mint transaction producing Contract output
- `contractVout` = output index of Contract in mint tx
- `issuerPkh` = PKH (single-sig) or HASH160(MPKH preimage)

Contract's own txid is not available in its preimage (self-reference limit). Issuer provides `genesisTxId` in issue unlocking; script verifies `tokenId == SHA256(provided_genesisTxId ‖ contractVout ‖ issuerPkh)` for each issued Normal output.

Same known limitation as v1: issuer can lie about `genesisTxId` at issue time, producing tokens with wrong tokenId that off-chain validators reject. Not a consensus-level rug; requires off-chain B2G as backstop.

---

## 7. Issuer attestation mechanism

### 7.1 When attestation is required

- ✅ `refresh` path (Normal path 2)
- ✅ `issue` path (Contract path 6)
- ❌ `flex-transfer` path (Normal path 1) — no issuer involvement
- ❌ `freeze` / `unfreeze` / `confiscate` paths — authority sig suffices (no issuer attestation)
- ℹ️ `redeem` is not a dedicated path — owner does a flex-transfer to issuer-owned address; no issuer attestation at that moment (issuer handles off-chain payout afterwards)

### 7.2 Attestation format

Mandatory null-data output at known index in the attesting tx:

```
scriptPubKey = OP_FALSE OP_RETURN
               <tokenId 32b>         this token's ID
               <thisOutpoint 36b>    UTXO being refreshed (or first-issued outpoint at issue)
               <issuerPubkey 33b>    issuer's compressed pubkey or MPKH preimage
satoshis = 0
```

Total null-data content: **~101 bytes** (33+2 opcodes + 101 bytes data + push prefixes ≈ 110 bytes on-chain).

### 7.3 Verification mechanism (unchanged from v1 Способ C)

On refresh/issue tx:

1. User constructs full tx with placeholder issuer sig slot
2. User asks issuer to sign tx preimage (SIGHASH_ALL | SIGHASH_FORKID = 0x41)
3. Issuer verifies off-chain:
   - tokenId belongs to them
   - Off-chain chain walk from last attested point (or from genesis for issue) is valid
   - Null-data output fields match expected
   - Royalty output amount is acceptable (business policy)
4. If satisfied, issuer signs preimage, returns sig
5. User inserts sig into unlocking, broadcasts

At spend time, BNTP template verifies:

1. Null-data output at expected index matches expected format
2. Null-data `tokenId` == this.tokenId (from tail)
3. Null-data `thisOutpoint` == spending input's outpoint (from preimage)
4. `HASH160(null-data issuerPubkey)` == this.issuerPkh (from tail)
5. Standard `CHECKSIGVERIFY(issuer_sig, issuer_pubkey, preimage)` — this is the normal covenant mechanism, no CHECKSIG-over-arbitrary-hash

### 7.4 Royalty mechanics

Refresh path produces exactly 2 BNTP Normal outputs:

- Output 0: user's refreshed UTXO (owner = original owner, amount = `input_amount − royalty`, depth = 0)
- Output 1: issuer's royalty UTXO (owner = issuerPkh, amount = `royalty`, depth = 0)

Protocol-level floor: `royalty ≥ 1` (anti-dust). Protocol-level ceiling: none.

Actual royalty amount = **off-chain issuer policy**. Issuer rejects signing if:

- Royalty below their cost model
- Refreshing-user's UTXO depth very high (longer off-chain chain to verify → higher charge)

Depth-scaled royalty implements "комиссия нарастает" semantics naturally.

### 7.5 Depth reset semantics

On refresh:

- User's output: `depth = 0`
- Issuer's royalty output: `depth = 0` (issuer's UTXO is itself attestation-fresh since just minted)

Issuer can freely spend royalty UTXO without needing another refresh (it's depth=0 from creation).

---

## 8. Authority / owner / issuer verification

### 8.1 Single-sig (PKH)

`freezeAuthHash` / `confiscAuthHash` / `issuerPkh` / `owner_field` = `HASH160(compressed_pubkey)`. Unlocking provides pubkey + signature. Script verifies `HASH160(pubkey) == expected_hash` and runs `OP_CHECKSIGVERIFY`.

### 8.2 MPKH (multisig via flags)

If flag bit set, hash = `HASH160(canonical_MPKH_preimage)` where:

```
mpkh_preimage = [m byte] ‖ [push33 byte ‖ pubKey_i]_{i=1..n} ‖ [n byte]
```

Supports m-of-n multisig, 1 ≤ m ≤ n ≤ 5 (per v1 identity-field spec).

Unlocking:

```
[OP_0]                    (dummy for CHECKMULTISIG)
[sig_1, ..., sig_m]       (m DER-encoded signatures)
[mpkh_preimage]           (variable bytes, 36..171b)
```

Script:

1. `HASH160(mpkh_preimage) == expected_hash` → EQUALVERIFY
2. Parse m and n from preimage
3. `OP_CHECKMULTISIGVERIFY` against preimage-derived pubkey set

### 8.3 Authority/issuer/owner cannot rotate

Fields fixed at issuance. No rotation mechanism in v2 core. Rotation = off-chain (issuer publishes new issuerPkh under same public identity; users migrate by flex-transferring old tokens to issuer-redemption-address under old pkh, then receiving fresh tokens from new issuance under new pkh).

---

## 9. Spend paths — detailed

### 9.1 Common stack layout

Unlocking always ends with:

```
... [preimage] [path_id: 1..6] [sig] [pubKey]
```

Path_id values are template-scoped (not global). Normal uses 1..4, Frozen uses 3..4, Contract uses 6. Value 5 is reserved (formerly redeem in early drafts; collapsed into flex-transfer per spec decision).

| path_id | Normal        | Frozen     | Contract |
| ------- | ------------- | ---------- | -------- |
| 1       | flex-transfer | —          | —        |
| 2       | refresh       | —          | —        |
| 3       | freeze        | unfreeze   | —        |
| 4       | confiscate    | confiscate | —        |
| 5       | reserved      | —          | —        |
| 6       | —             | —          | issue    |

### 9.2 Normal path 1 — flex-transfer

**Unlocking:**

```
[output_tuples... (M × [amount 16b, owner 20b or MPKH preimage, new_depth 2b, body_marker 2b])]
[amounts_in_array (N × 16b)]
[all_input_outpoints (N × 36b)]
[selfPosition (1b, 0..N-1)]
[max_input_depth (2b, uint16)]
[null-data payload?]
[funding_outpoint]
[preimage]
[OP_1]                         path_id = 1
[owner_sig] [owner_pubkey]     or [OP_0, sig_1..sig_m, mpkh_preimage] for MPKH owner
```

**Script verifies:**

1. Owner sig valid (standard or MPKH per flag bit 5)
2. `HASH256(all_input_outpoints ‖ funding_outpoint) == hashPrevouts` (binds shared state)
3. `all_input_outpoints[selfPosition] == my_outpoint` (from preimage)
4. `amounts_in_array[selfPosition] == my_amount` (from scriptCode tail)
5. `N ≥ 1`, `M ∈ [1, 4]`
6. `my_depth ≤ max_input_depth` (each input verifies this slice of max — collective upper-bound enforcement; see §9.2.1)
7. Each output[i] for i ∈ [0, M-1]:
   - Is a Normal UTXO (body_marker = 0x01ff)
   - Has same tokenId as this UTXO
   - Has same issuerPkh, authorityFlags, freezeAuthHash, confiscAuthHash, optionalData (byte-exact)
   - `new_depth == max_input_depth + 1` (enforced per output)
   - `new_depth ≤ 65535` (uint16 bound check, prevents overflow)
   - `amount ≥ 1` (anti-dust)
8. `Σ amounts_in_array == Σ output_amounts` (conservation)
9. `hashOutputs` in preimage matches reconstructed outputs

#### 9.2.1 `max_input_depth` collective enforcement mechanism

`max_input_depth` is pushed freely in unlocking (not hash-committed). Each input's script verifies `my_depth ≤ max_input_depth`. Since **every** input's script runs independently and enforces this check, the pushed value is guaranteed to be ≥ actual max of all input depths.

**Attacker analysis:**

- Over-reporting (push `max_input_depth` > actual max): output's `new_depth` becomes inflated. UTXO "ages faster" and sooner requires refresh. **This is self-harm for the spender** — no attack vector against others or against the protocol's integrity.
- Under-reporting (push `max_input_depth` < actual max of some input): that input's script check `my_depth ≤ max_input_depth` fails → entire tx rejected.

Over-reporting as self-harm is deemed acceptable. No separate per-input-depth hash commitment is needed, saving ~40-80b of unlocking script and ~20b of template body. See `BNTP_V2_TEMPLATE_NORMAL_ASM.md` §9 AMR #2 for original rationale.

### 9.3 Normal path 2 — refresh (with issuer attestation)

**Unlocking:**

```
[refreshed_output_tuple (amount A-royalty, owner unchanged, new_depth=0, body_marker=0x01ff)]
[royalty_output_tuple (amount royalty, owner=issuerPkh or MPKH, new_depth=0, body_marker=0x01ff)]
[null-data attestation bytes]
[change_satoshis? change_script?]
[funding_outpoint]
[preimage]
[OP_2]                         path_id = 2
[issuer_sig] [issuer_pubkey]   or MPKH form
[owner_sig] [owner_pubkey]     or MPKH form
```

**Script verifies:**

1. Owner sig valid (owner consents to pay royalty)
2. Exactly 2 BNTP outputs at indices 0, 1
3. Output 0: `amount = my_amount − royalty`, `owner = my_owner`, `new_depth = 0`, tail fields match
4. Output 1: `amount = royalty`, `owner = issuerPkh` (from my tail), `new_depth = 0`, tail fields match
5. Conservation: `my_amount == (output_0.amount) + (output_1.amount)`, both positive
6. Null-data output at index 2:
   - Format: `OP_FALSE OP_RETURN <tokenId 32b> <thisOutpoint 36b> <issuerPubkey 33b>`
   - `tokenId` == my.tokenId
   - `thisOutpoint` == my_outpoint (from preimage)
   - `HASH160(issuer_pubkey)` == my.issuerPkh (for PKH issuer) OR `HASH160(issuer_pubkey_as_MPKH_preimage)` == my.issuerPkh (if flag bit 4)
7. Issuer `CHECKSIGVERIFY` against preimage — standard covenant sig. This binds all outputs (including null-data) to issuer's approval via SIGHASH_ALL.
8. hashOutputs matches reconstruction

**Royalty UTXO owner semantics:**

- For PKH issuer (flag bit 4 = 0): royalty UTXO `owner = issuerPkh` (20b PKH). Issuer spends via standard single-sig path with owner flag bit 5 = 0.
- For MPKH issuer (flag bit 4 = 1): royalty UTXO `owner = issuerPkh` (same 20b hash; hash of canonical MPKH preimage). Issuer spends via owner-MPKH path (owner flag bit 5 = 1 on royalty UTXO). Issuer must provide MPKH preimage + m signatures when spending. This means the royalty UTXO carries owner-MPKH semantics; no separate "issuer-spend PKH" is needed.

In both cases, royalty UTXO inherits all other tail fields from the source UTXO (tokenId, issuerPkh, authority block, authorityFlags). `attestation_depth` is 0 (freshly attested at refresh time).

### 9.4 Normal path 3 — freeze

**Unlocking:**

```
[frozen_output_tuple (amount=my_amount, owner=my_owner, new_depth=my_depth, body_marker=0xfeff)]
[null-data?]
[funding_outpoint]
[preimage]
[OP_3]                         path_id = 3
[freezeAuth_sig] [freezeAuth_pubkey]  or MPKH form
```

**Script verifies:**

1. `authorityFlags bit 0` set (freezable)
2. Freeze authority sig valid (PKH or MPKH per flag bit 2)
3. Output body shape matches Frozen template: `SHA256(output.body) == h_Frozen` where `h_Frozen` is embedded as a 32-byte constant in the Normal template body (see §5.5 Body hash manifest)
4. Exactly 1 Frozen output (body_marker = 0xfeff), with:
   - amount = my_amount
   - owner = my_owner (owner unchanged)
   - new_depth = my_depth (depth preserved)
   - All other tail fields preserved
5. hashOutputs match

### 9.5 Normal path 4 — confiscate

**Unlocking:**

```
[normal_output_tuple (amount=my_amount, owner=new_owner, new_depth=0, body_marker=0x01ff)]
[null-data?]
[funding_outpoint]
[preimage]
[OP_4]                         path_id = 4
[confiscAuth_sig] [confiscAuth_pubkey]  or MPKH form
```

**Script verifies:**

1. `authorityFlags bit 1` set (confiscatable)
2. Confiscation authority sig valid (PKH or MPKH per flag bit 3)
3. Exactly 1 Normal output with:
   - amount = my_amount (preserved)
   - owner = new_owner (authority chooses)
   - new_depth = 0 (reset — confiscation implies authority vetted new owner)
   - All other tail fields preserved
4. hashOutputs match

### 9.6 Redeem — no dedicated path

Redeem is **not** a dedicated spend path in BNTP v2. Owner who wants to redeem their token uses `flex-transfer` (§9.2) with the destination owner set to an issuer-controlled address. The issuer then handles off-chain redemption (fiat payout, asset unlock, etc.) via their custody procedures.

**Rationale:**

- DSTAS-style redeem (P2PKH output matching `redemptionPkh`) required satoshi=amount equivalence. BNTP v2's amount-in-tail decouples satoshis from token amount, making P2PKH-as-redemption-target semantically awkward (different currencies).
- Multiple candidate mechanisms (amount-to-sat conversion rate, dedicated redemption address, issuer-verified destination) each added complexity and/or a new tail field, without providing capabilities beyond "flex-transfer + off-chain settlement".
- Collapsing redeem into flex-transfer keeps the protocol surface smaller and the tail at 111 bytes (no `redemptionPkh`).

**User workflow:**

1. User initiates `flex-transfer` with: inputs = own Normal UTXO(s), output[0].owner = issuer-redemption-address (issuer publishes this address off-chain).
2. Issuer sees on-chain transfer (via indexer or direct submission), verifies amount and tokenId.
3. Issuer triggers off-chain payout (bank wire, stablecoin bridge, asset release, etc.).

**Trust model:** identical to DSTAS redeem — user trusts issuer to honor redemption. No on-chain enforcement of redemption execution; that is inherent to any asset-backed token.

Path_id 5 is **reserved** (not used) so that future versions can re-add a dedicated redeem semantic without a path-id migration.

### 9.7 Frozen path 3 — unfreeze

Symmetric to freeze but Frozen → Normal.

### 9.8 Frozen path 4 — confiscate

Confiscation from Frozen. Same as Normal confiscate but source is Frozen.

### 9.9 Contract path 6 — issue

**Unlocking:**

```
[output_tuples... (N × Normal tuples with amount / owner / new_depth=0 / body_marker=0x01ff)]
[null-data attestation bytes]
[change_satoshis? change_script?]
[funding_outpoint]
[genesisTxId 32b]              Contract's own txid (issuer-provided)
[preimage]
[OP_6]                         path_id = 6
[issuer_sig] [issuer_pubkey]   or MPKH form
```

**Script verifies:**

1. Issuer sig valid (PKH or MPKH per flag bit 4)
2. All N outputs are Normal: `SHA256(output[i].body) == h_Normal` where `h_Normal` is embedded as a 32-byte constant in Contract body (body hash manifest per §5.5)
3. All N outputs have `body_marker = 0x01ff`
4. All N outputs share `tokenId = SHA256(genesisTxId ‖ contractVout ‖ issuerPkh)` where `issuerPkh` is from Contract's tail
5. Tail fields (issuerPkh, authorityFlags, freezeAuthHash, confiscAuthHash, optionalData) match Contract's tail on every output
6. All N outputs have `new_depth = 0` (fresh)
7. `Σ output_amounts == Contract.reserve_amount` (amount conservation — Contract's `amount` tail field set at mint time, enforces total supply)
8. Null-data attestation at index N (after all output_tuples) — same format as refresh attestation (§7.2).

#### 9.9.1 Contract tail layout

Contract tail mirrors Normal's tail layout (111b fixed + optionalData), with one semantic difference: Contract's `amount` field is the **total reserve / max supply** for the token at issue time, not an individual holding. At issue, this total is distributed across N Normal outputs; Contract is consumed (single-spend UTXO, exists only between mint and issue).

```
tokenId           32 bytes   ← set at mint via SHA256(genesisTxId ‖ contractVout ‖ issuerPkh)
issuerPkh         20 bytes   ← set by issuer at mint
amount            16 bytes   ← total reserve / max supply (uint128, same ScriptNum cap §9.11)
authorityFlags     1 byte    ← same structure as Normal
freezeAuthHash    20 bytes
confiscAuthHash   20 bytes
attestation_depth  2 bytes   ← unused in Contract (always 0); kept for layout uniformity with Normal
optionalData    variable
```

**Mint tx** (one-shot, creates Contract from funding): issuer publishes a tx with output[0] = Contract locking script with fully-populated tail including desired `amount`. No special on-chain validation at mint (it's just a P2-something → Contract output creation). The `amount` is issuer's declaration of supply.

**Issue tx** (spends Contract, produces N Normal UTXOs): §9.9 path above. Script enforces distribution sums to `Contract.amount`. Once Contract is spent, no more tokens of this tokenId can be issued — fixed supply is structurally enforced.

#### 9.9.2 Variable vs fixed supply

v2 Contract supports fixed supply only (single-spend Contract consumed at first issue). Re-mintable supply would require a different template (e.g., ContractMintable that permits partial issue with leftover tracked in Contract UTXO's own amount field). Deferred to v2.1 if needed.

### 9.10 Why no anchor/follower

v1 had anchor/follower pattern for merge-K because each input needed to reconstruct other inputs' prev txs to verify same-token invariant. In v2, conservation is verified via `amounts_in_array` pushed directly in unlocking and bound via `hashPrevouts`. Each input just checks its own slice of this array. No prev-tx reconstruction needed.

Saving: ~500-1000b removed from merge logic vs v1's anchor/follower.

### 9.11 Amount precision — uint128 storage, ScriptNum runtime cap

The tail's `amount` field is **stored as uint128 (16 bytes, little-endian)** for ETH-decimal compatibility (e.g., tokens bridged from 18-decimal ETH representations need to round-trip through BNTP UTXOs).

However, BSV Script's `OP_BIN2NUM` converts bytes to Script's internal `ScriptNum` type, which is a **signed integer up to ~int63** (9,223,372,036,854,775,807 ≈ 9.2 × 10¹⁸). Script-side arithmetic (amount conservation, anti-dust, sum/diff) operates on ScriptNum values.

**Practical cap:** amount values in BNTP v2 MUST fit within int63 at the moment of any arithmetic operation. The uint128 storage format allows representing values up to 2¹²⁸ − 1, but v2 does not support chunked big-integer arithmetic in script (doing so would add ~200-400b to the template body for no meaningful production use case).

**In practical terms:**

- ≤ 9.2 × 10¹⁸ token units — fully supported ✅
- > 9.2 × 10¹⁸ units — rejected at tx validation (script's BIN2NUM or arithmetic overflow)

For context, 9.2 × 10¹⁸ ≈ 9.2 quintillion. For typical token use cases:

- Stablecoin at 6 decimals: 9.2 trillion USD-equivalent — far beyond any realistic market cap
- ETH at 18 decimals: 9.2 tokens — **may be too small** for mint supplies of high-volume tokens
- Commodity at 8 decimals: 92 billion units — ample

If a token issuance legitimately exceeds the int63 cap (e.g., bridging in all of ETH's 120M × 10¹⁸ wei supply), use a **smaller decimal base** in BNTP representation (e.g., 12 decimals instead of 18) and perform final-decimal normalization off-chain at bridging boundaries.

SDK should validate issuance and transfer amounts against this cap and reject early (before constructing a tx that would fail validation). Spec ratifies the cap explicitly to avoid surprise rejections.

---

## 10. Unlocking script catalog

| Template | Path          | Path_id | Key pushes                                                                                                                             |
| -------- | ------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Normal   | flex-transfer | 1       | pubkey, sig, OP_1, preimage, funding_outpoint, null-data?, selfPosition, all_outpoints, amounts_array, output_tuples…                  |
| Normal   | refresh       | 2       | issuer-pk, issuer-sig, owner-pk, owner-sig, OP_2, preimage, funding_outpoint, change?, null-data_bytes, royalty_tuple, refreshed_tuple |
| Normal   | freeze        | 3       | auth-pk, auth-sig, OP_3, preimage, funding_outpoint, null-data?, frozen_tuple                                                          |
| Normal   | confiscate    | 4       | auth-pk, auth-sig, OP_4, preimage, funding_outpoint, null-data?, normal_tuple                                                          |
| Frozen   | unfreeze      | 3       | auth-pk, auth-sig, OP_3, preimage, funding_outpoint, null-data?, normal_tuple                                                          |
| Frozen   | confiscate    | 4       | auth-pk, auth-sig, OP_4, preimage, funding_outpoint, null-data?, normal_tuple                                                          |
| Contract | issue         | 6       | issuer-pk, issuer-sig, OP_6, preimage, genesisTxId, funding_outpoint, change?, null-data, output_tuples…                               |

MPKH variants: issuer/owner/auth MPKH adds `OP_0 + m sigs + MPKH preimage` instead of single-sig.

---

## 11. Size estimates

### 11.1 Template body budget (revised per Phase 0 pseudo-ASM validation)

G5 gate targets (revised from initial ~2000b draft):

- **PASS:** body ≤ 2500b
- **PASS-with-margin:** 2500-2700b (minor optimization opportunities remaining)
- **PIVOT:** 2700-3000b (feature cuts needed)
- **ABORT:** > 3000b (design reconsideration)

| Template | PREFIX (common) | SUFFIX (path-specific) | Body marker | **Body total (target)** | Pseudo-ASM (measured) |
| -------- | --------------- | ---------------------- | ----------- | ----------------------- | --------------------- |
| Contract | ~350b           | ~250b                  | 2b          | **~600b**               | TBD Phase 1           |
| Normal   | ~830b           | ~1630b                 | 2b          | **~2500b**              | **2461b (PASS)**      |
| Frozen   | ~350b           | ~350b                  | 2b          | **~700b**               | TBD Phase 1           |

Normal measured at 2461b per `BNTP_V2_TEMPLATE_NORMAL_ASM.md`. PASS under revised gate.

### 11.2 Per-UTXO (owner 20b PKH, empty optionalData)

Fixed tail: 111b. Variable prefix: ~22b (owner push + action_data + OP_2DROP). Body per above.

| State    | Body | Tail | Variable prefix | **Per-UTXO** | vs DSTAS (~3050b) |
| -------- | ---- | ---- | --------------- | ------------ | ----------------- |
| Normal   | 2461 | 111  | 22              | **~2594b**   | **−15%**          |
| Frozen   | 700  | 111  | 22              | **~833b**    | **−73%**          |
| Contract | 600  | 111  | 22              | **~733b**    | —                 |

**Normal ~15% smaller per-UTXO than DSTAS.** Primary wins remain on Frozen (−73%) and merge operations (see §11.4). Smaller-Normal is a secondary benefit, not the goal.

### 11.3 Unlocking sizes (examples, no MPKH)

| Path                                               | Approx size                                                             |
| -------------------------------------------------- | ----------------------------------------------------------------------- |
| Normal flex-transfer (1 in, 1 out + change)        | ~260b                                                                   |
| Normal flex-transfer (4 in, 1 out) — consolidation | ~460b (amounts_array 64b + outpoints 144b + tuples 1×~40b + base ~210b) |
| Normal flex-transfer (1 in, 4 out) — split         | ~410b                                                                   |
| Normal refresh                                     | ~420b (includes null-data attestation + issuer sig)                     |
| Normal freeze/confiscate                           | ~260b                                                                   |
| Frozen unfreeze/confiscate                         | ~260b                                                                   |
| Contract issue (N=4)                               | ~470b                                                                   |

**Note on merge:** unlike v1/DSTAS where merge unlocking carried prev-tx reconstruction (~2500b per input), v2 flex-transfer unlocking scales linearly with N (input count) via pushed arrays. 4-input consolidation unlocking ~460b vs DSTAS merge-2 ~3230b. **Huge reduction.**

### 11.4 Per-tx estimates for key scenarios

| Scenario                                  | DSTAS                    | BNTP v2                   | Δ        |
| ----------------------------------------- | ------------------------ | ------------------------- | -------- |
| Transfer 1→2 (pay + change)               | ~3471b                   | ~2350b                    | **−32%** |
| Merge 4→1 (consolidation)                 | ~29400b (3 chained tx)   | **~2850b (1 tx)**         | **−90%** |
| Merge 2→1                                 | ~9800b                   | ~2550b                    | **−74%** |
| Split 1→4                                 | ~12800b                  | ~8800b                    | **−31%** |
| Refresh                                   | N/A                      | ~2900b                    | new      |
| Freeze                                    | ~3570b                   | ~1150b                    | **−68%** |
| Confiscate                                | ~3570b                   | ~2350b                    | **−34%** |
| External swap (2 BNTP UTXOs, cross-token) | ~19100b (via DSTAS swap) | ~4800b (2 flex-transfers) | **−75%** |

**The win is merge.** Because amount-in-tail removes prev-tx reconstruction, N→M operations scale linearly with push data (cheap) not with reconstructed prev-tx bytes (expensive).

---

## 12. Pain resolution — target outcomes

### 12.1 Pain: merge-then-transfer pattern

**Before (DSTAS):** to pay 100 from UTXOs of 150 and 80: merge (150+80=230) → split (100 payment + 130 change). 2-3 txs, ~13 KB total.

**After (BNTP v2):** 1 flex-transfer with 2 inputs → 2 outputs. 1 tx, ~2.6 KB.

**Result:** ~80% reduction + UX simplification (no "prepare then pay" pattern).

### 12.2 Pain: back-to-genesis verification

**Before:** wallet walks chain from received UTXO to genesis — can be thousands of tx deep, expensive.

**After:** wallet checks `issuerPkh` against trusted registry (O(1)). For fresh UTXOs (depth=0), trust established. For older UTXOs (depth > N), wallet policy decides (warn user / request refresh / reject).

**Result:** O(1) verification for fresh UTXOs; bounded walk (depth) for stale.

### 12.3 Secondary wins

- **Frozen UTXO size** -76% vs DSTAS — important for compliance-heavy tokens
- **External swap tx** -75% — due to simpler per-leg conservation vs DSTAS swap reconstruction
- **uint128 amount** — ETH-decimal compat for bridging use cases
- **MPKH owner** — compliance-ready 2-of-3 multisig wallets

---

## 13. Security considerations

### 13.1 Issuer compromise

Issuer key compromise allows:

- Forging attestations on bad UTXOs (wallets accept invalid tokens)
- Signing fake issue txs (minting bogus tokens)

Mitigation:

- Use MPKH issuer (flag bit 4) with N-of-M signing hardware
- Off-chain monitoring for unauthorized issuer activity
- Confiscation as recovery mechanism (if confiscatable + authority also MPKH)

Same severity as DSTAS confisc authority compromise.

### 13.2 Amount-in-tail attack surfaces

Attacker attempts to:

- Forge UTXO with arbitrary amount in tail — blocked by conservation check (inputs sum must equal outputs sum, enforced in script)
- Replay attestation for different amount — blocked because null-data commits to `thisOutpoint`, not amount; amount is covered by SIGHASH_ALL → issuer's sig binds to specific amount in output

### 13.3 Depth counter attacks

Attacker attempts to:

- Set output depth to 0 without issuer attestation — blocked by script logic (path 1 requires `new_depth ≥ max(input_depth) + 1`; depth=0 only on refresh/confiscate paths)
- Overflow uint16 depth — blocked by bounds check `new_depth ≤ 65535`
- Backdate depth (set lower than inputs') — blocked by `new_depth ≥ max + 1`

### 13.4 Flex-transfer cross-input attacks

Attacker attempts to:

- Push wrong amounts_in_array — each input's script checks `amounts[selfPos] == my_amount`; all inputs must sign consistent data for tx to succeed
- Mix tokens (different tokenIds in same tx) — each input's script checks all outputs share its tokenId
- Forge `all_outpoints` — bound via hashPrevouts (`HASH256(all_outpoints) == hashPrevouts`)

### 13.5 What's still unsolved

- **Back-to-genesis in pure trustless form** — requires ZK which is infeasible on BSV Script today. v2 accepts issuer-trust-based B2G as pragmatic solution.
- **Issuer liveness dependency** — refresh requires issuer online. Mitigation: MPKH federation, pre-paid subscription batches, long depth windows.
- **Cross-series swap atomicity** — since swaps are external, atomicity is guaranteed by swap protocol (e.g., atomic multi-input tx signed by both parties), not BNTP.

---

## 14. Implementation phases

### Phase 1 — PoC (mint + transfer + refresh)

- Contract template, issue path
- Normal template paths: flex-transfer (1), refresh (2)
- Issuer service stub (off-chain signer)
- SDK builders for: mint-contract, issue, transfer, refresh
- Conformance vectors for all

Deliverable: functional mint + pay + refresh. No freeze, no confiscate.

### Phase 2 — Authority paths

- Add Frozen template
- Extend Normal with paths 3 (freeze), 4 (confiscate)
- Frozen paths 3, 4
- SDK builders for freeze, unfreeze, confiscate

### Phase 3 — Compliance extensions

- MPKH owner support (flag bit 5)
- MPKH issuer support (flag bit 4) — enabling federated issuer
- Conformance vectors for MPKH cases

### Phase 4 — Audit, optimize, ship

- Full security audit
- Optimize body sizes where possible (remove redundancies per v1 audit findings)
- Issuer service reference implementation (subscription, batch signing, depth-scaled pricing)
- Wallet integration helpers
- Migration notes (if applicable)

---

## 15. Resolved decisions (from user consultation)

| #   | Decision                                | Outcome                                                                                             |
| --- | --------------------------------------- | --------------------------------------------------------------------------------------------------- |
| 1   | Swap architecture                       | External protocol layer, not in BNTP core                                                           |
| 2   | Issuer liveness model                   | Rolling attestation (D+B combo) via depth counter; subscription business model                      |
| 3   | Owner PKH/MPKH                          | Both supported (flag bit 5)                                                                         |
| 4   | Amount precision                        | uint128 (ETH-compat)                                                                                |
| 5   | Attestation economics                   | Flat royalty paid in token amount (not satoshis), out of UTXO's own value                           |
| 6   | Attestation content                     | Minimal: tokenId + thisOutpoint + issuerPubkey (option A)                                           |
| 7   | On-chain freshness enforcement          | Off-chain advisory only (option A), no CLTV                                                         |
| 8   | Authority paths vs attestation          | Authority sig sufficient, no attestation required on freeze/confiscate (option B)                   |
| 9   | Issue attestation                       | Required (option B) — for uniformity                                                                |
| 10  | OptionalData continuity                 | Preserved byte-exact (option A)                                                                     |
| 11  | Attestation revocation                  | No separate mechanism; use confiscation if issuer mis-attested                                      |
| 12  | Naming                                  | BNTP (continuation of v1 research, not new protocol)                                                |
| 13  | `max_input_depth` sync on merge         | Free push + collective upper-bound enforcement. Over-reporting = self-harm, acceptable. See §9.2.1. |
| 14  | Issuer MPKH royalty owner               | royalty UTXO `owner = issuerPkh` with owner-MPKH flag bit 5 set for MPKH-gated spend. §9.3.         |
| 15  | Frozen body cross-template verification | Option β: embed 32b SHA256(Frozen_body) as constant in Normal. §5.5 body hash manifest.             |
| 16  | Tail layout                             | **111b** fixed, no `redemptionPkh`. Redeem collapsed into flex-transfer. §5.2, §9.6.                |
| 17  | Contract amount location                | In Contract tail as uint128 (mirrors Normal tail layout). §9.9.1.                                   |
| 18  | uint128 vs ScriptNum arithmetic         | Storage format uint128; runtime cap ~int63 (9.2 × 10¹⁸). SDK validates. §9.11.                      |
| 19  | Body hash manifest pattern              | Accepted as WHITELIST replacement. 32b per cross-reference, not 128b block. §5.5.                   |
| 20  | G5 gate target                          | Revised from ~2000b to ~2500b per Phase 0 pseudo-ASM validation. §11.1.                             |

---

## 16. Open questions (Phase 1+)

1. **Royalty minimum** — protocol enforces `≥ 1`, actual minimum is issuer policy. Should SDK have default guidance for depth-scaled pricing?
2. **Null-data at issue (path 6)** — position of attestation null-data output when there are N token outputs. Simplest: always at index N. But varies with tx structure. Lock normative in Phase 1 Contract pseudo-ASM.
3. **OptionalData size limit** — reuse v1 limit (4096 bytes)? Decision for Phase 1.
4. **Deployment manifest format** — body hash manifest (§5.5) is off-chain artifact; file format / publication channel TBD for operational spec.
5. **Issuer service reference implementation** — REST API for attestation, subscription batch signing, depth-scaled pricing. Phase 3-4 deliverable.

---

## 17. Terminology index

- **amount**: uint128 token quantity, in tail.
- **attestation_depth**: uint16 counter, increments on flex-transfer, resets on refresh/confiscate.
- **flex-transfer**: unified N→M owner spend path with on-script conservation.
- **refresh**: issuer-attested tx that resets depth to 0 and takes royalty.
- **issuerPkh**: 20b hash identifying issuer (PKH or MPKH).
- **tokenId**: 32b unique token identifier.
- **MPKH**: canonical m-of-n multi-pubkey preimage for multisig identity.

---

## 18. Change log

- **2026-04-18** — Initial draft of BNTP v2. Pivot from v1 after full-tx footprint analysis showed v1 did not strictly dominate DSTAS. v2 redefines success as "solve STAS pains" not "smaller footprint". Swaps external, amount-in-tail, issuer attestation via depth-based rolling model. 12 design questions resolved with user input (see §15).
- **2026-04-18** — Pseudo-ASM validation (opus) measured Normal body at **2461b** — low in PIVOT band vs initial ≤2000b target. Pain-resolution analysis (sonnet) scored BNTP v2 at 61/105 vs DSTAS 26.5/105 weighted (merge + B2G dominate, adoption friction -1). User ratified 8 additional design decisions + 3 SPEC AMENDMENT REQUESTs resolving pseudo-ASM OPEN QUESTIONs. Spec updated: §5.5 body hash manifest (replaces whitelist commitment), §9.2.1 max_input_depth collective enforcement, §9.3 MPKH issuer royalty owner, §9.6 redeem as flex-transfer (no dedicated path), §9.9.1 Contract tail with amount field, §9.11 uint128-vs-ScriptNum runtime cap, §11.1 G5 gate revised to ≤2500b. Verdict: **PASS under revised gate**. Proceed to Phase 1 planning.
