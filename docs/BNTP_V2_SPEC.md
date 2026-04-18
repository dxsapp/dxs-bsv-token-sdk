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

| #   | Template   | action_data | Role                                                  | Spent to              | Est. body                                                                                                   |
| --- | ---------- | ----------- | ----------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------- |
| 0   | `Contract` | `OP_0`      | Pre-issuance reserve                                  | Normal × N (issue)    | **~3100b** (inlines Normal body, one-shot mint — see §5.5)                                                  |
| 1   | `Normal`   | `OP_0`      | Spendable token, all owner + authority + issuer paths | Normal, Frozen, P2PKH | ~2500b (target, revised from initial ~2000b per Phase 0 pseudo-ASM validation; post-audit est. ~2500-2600b) |
| 2   | `Frozen`   | `OP_2`      | Frozen token                                          | Normal                | ~700b                                                                                                       |

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

**Normative: body_before_tail walk direction (Gap 4.2 closure).** When the locking script needs to isolate `body_before_tail` (= `[Body marker] ‖ [PREFIX] ‖ [SUFFIX]`, used in output reconstruction) from its own `scriptCode` (= `[Variable prefix] ‖ [body_before_tail] ‖ [OP_RETURN] ‖ [Tail]`), it MUST use **forward walk** from the start of scriptCode:

1. Parse and strip `[Variable prefix]` (owner push + action_data + OP_2DROP) using length-prefix reads on the owner push, followed by the 1-byte action_data and 1-byte OP_2DROP opcode.
2. The remainder is `[body_before_tail] ‖ [OP_RETURN] ‖ [Tail]`.
3. Locate OP_RETURN (byte `0x6a`) at a deployment-time-known fixed offset: `|body_before_tail| = |PREFIX| + |SUFFIX| + 2` (the `+2` is the body marker). This offset is a constant resolved by the SDK at template compile time and patched into the locking script.
4. Split at the OP_RETURN offset: left part = `body_before_tail`, right part starts with OP_RETURN followed by Tail.

Backward walk (scanning for OP_RETURN from end) is rejected: optionalData may legitimately contain `0x6a` bytes, making back-scan ambiguous. Forward walk with deployment-time-known offset is unambiguous.

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

### 5.5 Cross-template output verification (hybrid approach)

When a template needs to produce an output of a **different** template (e.g., Normal's freeze path produces a Frozen output, Contract's issue path produces Normal outputs), the script must reconstruct that output's full serialized bytes to satisfy the covenant's `hashOutputs` commitment. v2 uses two complementary mechanisms depending on the spend frequency of the path.

#### 5.5.1 Hash-commit + unlocking body push (for rare cross-template paths)

For paths that produce a different template **rarely** (authority-gated or one-shot), the source template embeds only a 32-byte hash `h_X = SHA256(body_X)`; the unlocking must push `body_X` bytes at spend time. The locking script verifies `SHA256(pushed_body) == h_X`, then uses `pushed_body` to reconstruct the expected output.

Applied to:

| Source → Target     | Path            | Embedded constant             | Unlocking push             | Unlocking cost       |
| ------------------- | --------------- | ----------------------------- | -------------------------- | -------------------- |
| `Normal` → `Frozen` | path 3 freeze   | 32b `h_Frozen` in Normal body | Frozen body bytes (~700b)  | +~700b per freeze    |
| `Frozen` → `Normal` | path 3 unfreeze | 32b `h_Normal` in Frozen body | Normal body bytes (~2500b) | +~2500b per unfreeze |

**Rationale for rare paths:** freeze and unfreeze are authority operations, executed infrequently compared to user transfers. Per-operation unlocking overhead of 0.7–2.5 KB is acceptable. Source template body stays at estimated size (32b constant add only).

**Security:** SHA-256 preimage resistance ensures unlocking cannot push an alternative body that hashes to the same `h_X`. Byte-exact hash embed prevents substitution at deployment time.

#### 5.5.2 Inline body constant (for one-shot high-frequency cross-template paths)

For paths that produce a different template **often within a single tx** (the issue path emits N Normal outputs per Contract spend), the source template **inlines the target template's body bytes as a constant** at deployment time. No unlocking push needed; reconstruction pulls the inlined constant into candidate-output assembly via OP_CAT chains.

Applied to:

| Source → Target       | Path         | Embedded constant                       | Unlocking cost |
| --------------------- | ------------ | --------------------------------------- | -------------- |
| `Contract` → `Normal` | path 6 issue | Full Normal body bytes (~2500b) inlined | 0 bytes        |

**Trade-off analysis:**

- **Hash + unlocking-push (option A):** Contract body stays ~500b; issue unlocking grows `N × ~2500b` (N = number of Normal outputs produced). For N=4, issue unlocking +10 KB.
- **Inline (option B, chosen):** Contract body grows ~500b → **~3100b**; issue unlocking adds 0b. Full mint+issue lifecycle byte total ~7 KB smaller than option A for N=4.

**Rationale for Contract inline:** Contract is a one-shot UTXO in the fixed-supply model (§9.9.2) — body cost is paid once at mint. Amortizing it into the Contract body rather than into the issue unlocking simplifies mint batches and avoids a 10 KB unlocking tx for issuance. On-chain block space wins in the typical lifecycle (1 mint + 1 issue per token).

**Caveat:** inlining couples Contract to a specific Normal body version. Any Normal-body patch requires redeploying Contract templates for new tokens. v2 has no upgrade mechanism anyway, so this is not a new constraint — but operationally means Contract's template hash `h_Contract` changes whenever Normal's does.

#### 5.5.3 Deployment manifest (off-chain)

A separate repository file lists all template body hashes and their deployment addresses. Used by SDK/indexer to assemble the constants during template compilation. Off-chain artifact. See §14 Phase 1 deliverable (SDK template hash verification tool — Gap 6 closure) for CI-level enforcement that manifest matches compiled bodies.

Same template `action_data`–keyed `h_X` values are also exposed via `@dxs/bntp-v2-manifest` (packaging detail; TBD Phase 1).

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

#### 7.2.1 Canonical null-data encoding (Gap 4 closure)

All three push fields (`tokenId`, `thisOutpoint`, `issuerPubkey`) have length ≤ 75 bytes (32, 36, 33 respectively), so each MUST be encoded using **direct-push minimal** (single length-byte 0x01–0x4b prefix + data). Use of `OP_PUSHDATA1` (0x4c) or longer push-opcodes for fields of length ≤ 75 is **rejected** — the script comparison is byte-exact, and a non-canonical encoding will not match the expected constant.

Rationale:

- Direct push is **3 bytes smaller per tx** than forcing `OP_PUSHDATA1` on all three fields.
- Template bakes expected null-data layout byte-exact; locking canonical encoding at spec level prevents ambiguity ("does the wallet use PUSHDATA1 or direct push?") and removes a class of "tx constructed correctly but script rejects" failure modes.
- If a future field exceeds 75 bytes, the rule promotes: direct-push minimal for ≤ 75 bytes, `OP_PUSHDATA1` for 76..255, `OP_PUSHDATA2` for 256+. Spec must be amended to enumerate the new field's canonical form.

SDK responsibility: tx-builder emits minimal pushes for all null-data fields; validator rejects txs that use non-minimal pushes.

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

`freezeAuthHash` / `confiscAuthHash` / `issuerPkh` / `owner_field` = `HASH160(compressed_pubkey)`. Unlocking provides pubkey + signature. Script performs **two** independent operations:

1. `HASH160(pubkey) == expected_hash` → `OP_EQUALVERIFY` (identity binding: pubkey is the expected entity's pubkey)
2. `OP_CHECKSIGVERIFY(sig, pubkey, preimage)` (authorization: entity's private key signed this tx)

**Both are required.** Neither alone is sufficient:

- Identity without CHECKSIG: anyone knowing the public key (which is revealed on every spend) could spend the UTXO.
- CHECKSIG without identity: the sig would only need to be valid over preimage under some key, not necessarily the owner's key.

**Relationship to covenant CHECKSIG (§3.2 pseudo-ASM):** the covenant's `OP_CHECKSIGVERIFY` verifies that the pushed preimage is the real tx sighash-preimage by using an algorithmically-constructed signature over two generator-point-derived pubkeys. This is a preimage-authentication mechanism, **not** owner authentication. The owner-auth CHECKSIGVERIFY specified here is a **separate, independently-required** signature check. This distinction is normative for v2 — template implementations MUST perform both checks explicitly.

Byte cost: identity + CHECKSIGVERIFY = ~10b (HASH160 + EQUALVERIFY + CHECKSIGVERIFY + stack setup) per PKH identity verified (owner, freeze auth, confisc auth, issuer as applicable per path).

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
[M (1 byte, ScriptNum, 1..4)]  ← NEW: explicit output count (Gap §2.2 closure)
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

`M` is pushed explicitly (rather than inferred via `OP_DEPTH` tricks) for auditability and deterministic stack arithmetic. Script reads `M`, unrolls output reconstruction loop gated on `i < M`.

**Normative: output_tuple field encoding (Gap 4.3 closure).** Each output_tuple field is pushed as **raw bytes, without push-opcode length prefix**:

- `amount`: 16 raw bytes (uint128 LE), pushed as a 16-byte push.
- `owner`: 20 raw bytes (PKH) OR 35-171 raw bytes (MPKH preimage); pushed as a single data push. Locking script determines PKH vs MPKH by reading the stored byte length (via `OP_SIZE`) and by the owner-MPKH flag bit 5 in tail.
- `new_depth`: 2 raw bytes (uint16 LE), pushed as a 2-byte push.
- `body_marker`: 2 raw bytes (e.g., `0x01 0xff` for Normal target), pushed as a 2-byte push.

The locking script, during output reconstruction, **constructs the push-opcode length prefix** from the stored owner's byte length to produce the canonical locking-script's variable prefix bytes for the target output. Specifically:

- 20-byte PKH owner → emit `0x14` (direct-push length byte) + 20 bytes.
- 35-171 byte MPKH preimage → emit `OP_PUSHDATA1 (0x4c)` + 1-byte length + preimage bytes.

SDK tx-builder responsibility: pack the owner field as raw bytes (no push prefix) into the output_tuple; locking script reconstructs the prefix on-chain. This keeps per-tuple push encoding predictable (no ambiguity about whether the first byte is a length or data).

**Script verifies:**

1. Owner sig valid (standard or MPKH per flag bit 5)
2. **Input contiguity invariant (Gap 3 closure):** BNTP inputs occupy positions `[0 .. N-1]` in `all_input_outpoints`; optional funding input sits at position `N` (last). This is enforced by `HASH256(all_input_outpoints ‖ funding_outpoint) == hashPrevouts` — the concatenation order binds the layout to consensus-verified `hashPrevouts`. SDK MUST construct txs with this input ordering; wallets MUST reject incoming BNTP txs whose input layout deviates.
3. `HASH256(all_input_outpoints ‖ funding_outpoint) == hashPrevouts` (binds shared state + layout)
4. `all_input_outpoints[selfPosition] == my_outpoint` (from preimage); additionally `selfPosition ∈ [0, N-1]` (BNTP input, not funding slot)
5. `amounts_in_array[selfPosition] == my_amount` (from scriptCode tail)
6. **Array length verification (Gap 2 closure):** `|amounts_in_array| == (|all_input_outpoints| / 36) × 16`. Derived from outpoints count (`N = |all_input_outpoints| / 36`) so that `amounts_in_array` cannot be shorter (malicious under-commit) or longer (unused tail bytes changing conservation sum). Script enforces both lengths byte-exact.
7. **Max N bound (Gap 5 closure):** `N ≤ 32`. Compromise between per-tx capability (consolidation of many small UTXOs) and worst-case unlocking size (~32 × (36+16) = 1664b for arrays alone, ~1.9 KB with tuples — workable). Consolidation of 1000 UTXOs takes 32 txs vs 63 under N≤16. Gate value lockable; widening to 64 requires spec amendment plus re-estimation of per-input script cost.
8. `N ≥ 1`, `M ∈ [1, 4]`
9. `my_depth ≤ max_input_depth` (each input verifies this slice of max — collective upper-bound enforcement; see §9.2.1)
10. Each output[i] for i ∈ [0, M-1]:
    - Is a Normal UTXO (body_marker = 0x01ff)
    - Has same tokenId as this UTXO
    - Has same issuerPkh, authorityFlags, freezeAuthHash, confiscAuthHash, optionalData (byte-exact)
    - **Depth saturation (Gap 1 closure):** `new_depth == min(max_input_depth + 1, 65535)`. Once a UTXO reaches depth 65535, subsequent flex-transfers saturate rather than overflow. A saturated UTXO is practically unusable (no well-behaved wallet will accept it; off-chain freshness policy will reject far earlier), but script stays safe from uint16 overflow. Saturated UTXOs can still be refreshed (depth resets to 0) or confiscated. **Implementation (Gap 4.4):** `min()` in BSV Script = explicit branch via `OP_DUP <65535> OP_GREATERTHAN OP_IF OP_DROP <65535> OP_ENDIF` (~8b) applied to `max_input_depth + 1` before comparing to output's `new_depth`.
    - `new_depth ≤ 65535` (uint16 bound check, redundant given saturation but kept as defense-in-depth)
    - `amount ≥ 1` (anti-dust)
11. `Σ amounts_in_array == Σ output_amounts` (conservation)
12. `hashOutputs` in preimage matches reconstructed outputs

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
[null-data attestation bytes]          ← MUST be at output index 2
[change_script_bytes?]                  ← optional; if present, output index 3 is a change output (see Gap 4.4 closure below)
[funding_outpoint]
[preimage]
[OP_2]                         path_id = 2
[issuer_sig] [issuer_pubkey]   or MPKH form
[owner_sig] [owner_pubkey]     or MPKH form
```

**Script verifies:**

1. Owner sig valid (identity via HASH160 match + explicit CHECKSIGVERIFY per §8.1; PKH or MPKH per flag bit 5)
2. Exactly **2 BNTP outputs** at indices 0, 1, followed by null-data at index 2, optionally followed by a single P2PKH-style change output at index 3. **No other outputs permitted.** Any extra output fails `hashOutputs` byte-exact reconstruction.
3. Output 0: `amount = my_amount − royalty`, `owner = my_owner`, `new_depth = 0`, tail fields match.
4. Output 1: `amount = royalty`, `owner = issuerPkh` (from my tail), `new_depth = 0`, tail fields match.
5. Conservation: `my_amount == (output_0.amount) + (output_1.amount)`, both positive.
6. **Null-data at output index 2 is normative (Gap 4.2 closure).** The locking script parses output[2] as the null-data attestation at fixed stack offset; SDK MUST emit null-data at index 2. Format: `OP_FALSE OP_RETURN <tokenId 32b> <thisOutpoint 36b> <issuerPubkey 33b>`, with canonical direct-push encoding per §7.2.1.
   - `tokenId` == my.tokenId
   - `thisOutpoint` == my_outpoint (from preimage)
   - `HASH160(issuer_pubkey)` == my.issuerPkh (for PKH issuer) OR `HASH160(issuer_pubkey_as_MPKH_preimage)` == my.issuerPkh (if flag bit 4 = 1)
7. Issuer identity + CHECKSIGVERIFY per §8.1: HASH160(issuer_pubkey or MPKH preimage) == my.issuerPkh AND OP_CHECKSIGVERIFY(issuer_sig, issuer_pubkey_or_first_MPKH_component, preimage). PKH vs MPKH branch on `authorityFlags bit 4`. **MPKH issuer is normative (Gap 4.1 closure) — implementations MUST support both PKH and MPKH issuer branches.** MPKH issuer branch mirrors `authorityIdentityAsm` pattern (+~75b body).
8. **Optional change output at index 3 (Gap 4.4 closure).** If the unlocking pushes `change_script_bytes` as a non-empty byte string, the locking script serializes the change output `(change_satoshis 8b LE ‖ varint(len) ‖ change_script_bytes)` and appends to the hashOutputs accumulator. `change_satoshis = funding_input_satoshis − refresh_fees − dust(2 sats)`, computed on-chain from `preimage.satoshis` of funding input (not directly accessible — SDK provides `change_satoshis` as a push and locking verifies via hashOutputs byte-exact match). If `change_script_bytes` is empty (or missing), no change output is appended. Change output is P2PKH-style (standard Bitcoin) — no BNTP semantics.
9. hashOutputs matches reconstruction (output[0] ‖ output[1] ‖ null-data[2] ‖ change[3]?).

**Royalty UTXO owner semantics:**

- For PKH issuer (flag bit 4 = 0): royalty UTXO `owner = issuerPkh` (20b PKH). Issuer spends via standard single-sig path with owner flag bit 5 = 0.
- For MPKH issuer (flag bit 4 = 1): royalty UTXO `owner = issuerPkh` (same 20b hash; hash of canonical MPKH preimage). Issuer spends via owner-MPKH path (owner flag bit 5 = 1 on royalty UTXO). Issuer must provide MPKH preimage + m signatures when spending. This means the royalty UTXO carries owner-MPKH semantics; no separate "issuer-spend PKH" is needed.

In both cases, royalty UTXO inherits all other tail fields from the source UTXO (tokenId, issuerPkh, authority block, authorityFlags). `attestation_depth` is 0 (freshly attested at refresh time).

### 9.4 Normal path 3 — freeze

**Unlocking:**

```
[frozen_body_bytes (~700b)]    ← Frozen template body, hash-verified on-chain (§5.5.1)
[frozen_output_tuple (amount=my_amount, owner=my_owner, new_depth=my_depth, body_marker=0xfeff)]
[funding_outpoint]
[preimage]
[OP_3]                         path_id = 3
[freezeAuth_sig] [freezeAuth_pubkey]  or MPKH form
```

**Normative: null-data and change outputs are DISALLOWED on freeze (Gap 4.3 closure).** The tx produced by freeze path consists of exactly one Frozen output plus optional funding/change handled externally. Any null-data or extra outputs beyond output[0] fail hashOutputs byte-exact reconstruction. Rationale: freeze is an authority operation with no audit-message use case requiring null-data, and change can be absorbed by the funding input's own P2PKH output outside the BNTP covenant scope.

**Script verifies:**

1. `authorityFlags bit 0` set (freezable)
2. Freeze authority sig valid (identity via HASH160 match + explicit CHECKSIGVERIFY per §8.1; PKH or MPKH per flag bit 2)
3. **Pushed Frozen body authenticity:** `SHA256(pushed_frozen_body_bytes) == h_Frozen` where `h_Frozen` is embedded as a 32-byte constant in the Normal template body (per §5.5.1). Rejects forged Frozen body pushes.
4. Candidate output[0] reconstruction uses `pushed_frozen_body_bytes` + dynamic fields: `owner_push ‖ action_data(0x02) ‖ OP_2DROP ‖ pushed_frozen_body_bytes ‖ OP_RETURN ‖ reconstructed_tail`.
5. Candidate output properties:
   - body_marker = 0xfeff (first two bytes of `pushed_frozen_body_bytes`; verified byte-exact)
   - amount = my_amount
   - owner = my_owner (owner unchanged)
   - new_depth = my_depth (depth preserved)
   - All other tail fields preserved byte-exact from source
6. hashOutputs match (output[0] serialization hashes into `hashOutputs` bound via covenant).

### 9.5 Normal path 4 — confiscate

**Unlocking:**

```
[normal_output_tuple (amount=my_amount, owner=new_owner, new_depth=0, body_marker=0x01ff)]
[funding_outpoint]
[preimage]
[OP_4]                         path_id = 4
[confiscAuth_sig] [confiscAuth_pubkey]  or MPKH form
```

**Normative: null-data and change outputs DISALLOWED on confiscate (Gap 4.3 closure).** Same rationale as §9.4 freeze. Tx produces exactly one Normal output.

**Script verifies:**

1. `authorityFlags bit 1` set (confiscatable)
2. Confiscation authority sig valid (identity via HASH160 match + explicit CHECKSIGVERIFY per §8.1; PKH or MPKH per flag bit 3)
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

Symmetric to freeze but Frozen → Normal. Frozen embeds `h_Normal` (32b constant per §5.5.1); unlocking pushes `normal_body_bytes (~2500b)` which locking script verifies `SHA256(pushed) == h_Normal` before using in output reconstruction.

**Unlocking:**

```
[normal_body_bytes (~2500b)]   ← Normal template body, hash-verified on-chain
[normal_output_tuple (amount=my_amount, owner=my_owner, new_depth=my_depth, body_marker=0x01ff)]
[null-data?]
[funding_outpoint]
[preimage]
[OP_3]                         path_id = 3
[freezeAuth_sig] [freezeAuth_pubkey]  or MPKH form
```

**Script verifies:** same shape as §9.4 freeze, reversed target — produces 1 Normal output with preserved amount, owner, depth, and tail fields. Uses `pushed_normal_body_bytes` for output reconstruction.

### 9.8 Frozen path 4 — confiscate

Confiscation from Frozen. Same as Normal confiscate but source is Frozen. Unlocking pushes `normal_body_bytes` identical to §9.7 (target is Normal template); `new_depth = 0` rather than depth-preserved.

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

1. Issuer sig valid (identity via HASH160 match + explicit CHECKSIGVERIFY per §8.1; PKH or MPKH per flag bit 4)
2. All N outputs reconstructed using Contract's **inlined** Normal body constant (per §5.5.2). Each candidate output = `owner_push[i] ‖ action_data(0x00) ‖ OP_2DROP ‖ NORMAL_BODY_INLINE ‖ OP_RETURN ‖ reconstructed_tail[i]`.
3. All N outputs have `body_marker = 0x01ff` (first two bytes of `NORMAL_BODY_INLINE`; byte-exact).
4. All N outputs share `tokenId = SHA256(genesisTxId ‖ contractVout ‖ issuerPkh)` where `issuerPkh` is from Contract's tail.
5. Tail fields (issuerPkh, authorityFlags, freezeAuthHash, confiscAuthHash, optionalData) match Contract's tail on every output.
6. All N outputs have `new_depth = 0` (fresh).
7. `Σ output_amounts == Contract.reserve_amount` (amount conservation — Contract's `amount` tail field set at mint time, enforces total supply).
8. Null-data attestation at index N (after all output_tuples) — same format as refresh attestation (§7.2).

No `h_Normal` hash-verify step is needed in Contract body because Normal body bytes are inlined directly (no trust boundary between hash and bytes). Any drift between Contract's `NORMAL_BODY_INLINE` constant and the canonical `Normal` template body would produce outputs with non-matching `h_Normal` when those outputs spend via Frozen unfreeze path — detectable by external consistency checkers (SDK deploy-time verification tool; see §14 Phase 1 deliverable).

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

**Contract body size note:** per §5.5.2, Contract body inlines the full Normal template body bytes (~2500b) as a constant plus its own issue-path logic (~500-600b), totaling **~3100b**. This is paid once at mint — one-shot Contract UTXO consumed at first issue. Trade-off favors this over pushing Normal body in issue unlocking (which would scale `N × 2500b`; see §5.5.2 for analysis).

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

| Template | PREFIX (common) | SUFFIX (path-specific) | Inlined Normal body | Body marker | **Body total (target)** | Pseudo-ASM (measured)                                                       |
| -------- | --------------- | ---------------------- | ------------------- | ----------- | ----------------------- | --------------------------------------------------------------------------- |
| Contract | ~350b           | ~250b                  | ~2500b (§5.5.2)     | 2b          | **~3100b**              | TBD Phase 1                                                                 |
| Normal   | ~830b           | ~1670b                 | —                   | 2b          | **~2550b**              | **2461b pre-audit / ~2550-2600b post-audit-amendments (est.) — upper PASS** |
| Frozen   | ~350b           | ~350b                  | —                   | 2b          | **~700b**               | TBD Phase 1                                                                 |

**Post-audit (A.1.0) body revisions to Normal:** +50-100b above prior 2496b estimate. Sources: explicit CHECKSIGVERIFY for PKH owner (+5b per §8.1), explicit M read from unlocking (+3b), Frozen body SHA256-verify hook in freeze path (+5b), safety margin for stack-management findings from audit (+30-80b). Remains under G5 ≤ 2500b **only if implementation is tight**; realistic landing zone 2500-2600b (upper PASS / edge PIVOT). **If A.1.1 measured real ASM exceeds 2600b, G5 gate lift to ≤ 2700b is the next fallback** (alternative to feature cuts). See `BNTP_V2_NORMAL_TEMPLATE_AUDIT.md` for detailed byte-budget audit.

**Contract** grew from estimated ~500b to ~3100b due to Normal body inline (§5.5.2). One-shot UTXO; cost amortized across token lifecycle favorably vs `N × 2500b` issue-unlocking alternative.

**Frozen** minor +100b for `h_Normal` constant embed.

### 11.2 Per-UTXO (owner 20b PKH, empty optionalData)

Fixed tail: 111b. Variable prefix: ~22b (owner push + action_data + OP_2DROP). Body per above.

| State    | Body  | Tail | Variable prefix | **Per-UTXO** | vs DSTAS (~3050b)             |
| -------- | ----- | ---- | --------------- | ------------ | ----------------------------- |
| Normal   | ~2550 | 111  | 22              | **~2683b**   | **−12%**                      |
| Frozen   | 700   | 111  | 22              | **~833b**    | **−73%**                      |
| Contract | ~3100 | 111  | 22              | **~3233b**   | N/A (one-shot, ≠ DSTAS shape) |

**Normal ~12% smaller per-UTXO than DSTAS** (post-audit revision; was −15% at 2496b estimate). Primary wins remain on Frozen (−73%) and merge operations (see §11.4). Smaller-Normal is a secondary benefit, not the goal.

**Contract per-UTXO is larger than DSTAS** at one-shot mint — expected per §5.5.2 inline trade-off. Amortized across token lifecycle it remains net positive.

### 11.3 Unlocking sizes (examples, no MPKH)

| Path                                               | Approx size                                                                  |
| -------------------------------------------------- | ---------------------------------------------------------------------------- |
| Normal flex-transfer (1 in, 1 out + change)        | ~260b                                                                        |
| Normal flex-transfer (4 in, 1 out) — consolidation | ~460b (amounts_array 64b + outpoints 144b + tuples 1×~40b + base ~210b)      |
| Normal flex-transfer (1 in, 4 out) — split         | ~410b                                                                        |
| Normal refresh                                     | ~420b (includes null-data attestation + issuer sig)                          |
| Normal freeze                                      | **~960b** (~260b base + ~700b Frozen body push per §5.5.1)                   |
| Normal confiscate                                  | ~260b                                                                        |
| Frozen unfreeze                                    | **~2760b** (~260b base + ~2500b Normal body push per §5.5.1)                 |
| Frozen confiscate                                  | **~2760b** (~260b base + ~2500b Normal body push, target is Normal template) |
| Contract issue (N=4)                               | ~470b (no body push — Normal body inlined in Contract body per §5.5.2)       |

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

### 13.6 Consensus-rules requirement

BNTP v2 requires **BSV post-Genesis consensus** (activated Feb 2020 on mainnet, default on all current testnets). Pre-Genesis consensus imposed per-script limits on:

- Max script size (10 KB)
- Max non-push opcodes per script (201)
- Max stack element size (520 bytes)

All three limits are exceeded by BNTP v2 templates:

- Normal script size: ~2550b body + ~150b per-UTXO overhead → fine for size, but exceeds 201 non-push opcodes (est. ~1200+ in current pseudo-ASM).
- `body_before_tail` cache in scriptCode walk: ~2300b single stack element → exceeds 520b limit.
- Contract body with inlined Normal body: ~3100b → also would exceed script size limit.

Post-Genesis BSV removed all three limits. Deployments MUST target BSV mainnet (post-Genesis) or equivalent testnets. Pre-Genesis chains (BTC, BCH in earlier eras, etc.) are not supported.

**SDK responsibility:** Phase 1 SDK must gate deploy operations to post-Genesis BSV networks. Templates should carry a minimum-consensus-version tag to prevent accidental deployment to incompatible chains.

### 13.7 Cross-template body push (attacker analysis)

Freeze (Normal→Frozen) and unfreeze (Frozen→Normal) paths accept the target template's body bytes via unlocking push (§5.5.1). Locking verifies `SHA256(pushed_body) == h_X` before using the pushed bytes in output reconstruction.

Attacker attempts to:

- **Push alternative body bytes** that hash-match `h_X`: blocked by SHA-256 preimage resistance. Collision probability ≈ 2⁻²⁵⁶; computationally infeasible.
- **Push a truncated body with correct hash**: SHA-256 of different-length inputs yields different hashes; length mismatch implicitly rejected.
- **Push attacker-chosen template body (e.g., one that allows attacker to spend without auth)**: rejected because hash doesn't match; deployment manifest (§5.5.3) publishes `h_X` values signed/attested by template deployer.

**Residual trust:** template deployer's honesty at deployment time — same trust model as v1 whitelist and DSTAS template publication.

---

## 14. Implementation phases

### Phase 1 — PoC (mint + transfer + refresh)

- Contract template, issue path
- Normal template paths: flex-transfer (1), refresh (2)
- Issuer service stub (off-chain signer)
- SDK builders for: mint-contract, issue, transfer, refresh
- Conformance vectors for all
- **Template hash verification tool (Gap 6 closure):** SDK CLI/lib that (a) compiles each template's body from source, (b) computes `SHA256(body_X)` deployment-time hash, (c) verifies embedded cross-template constants (`h_Frozen` in Normal, `h_Normal` in Contract, `h_Normal` in Frozen) match the actually-compiled bodies, (d) emits a machine-readable manifest for publication. Prevents accidental drift between template sources and the 32-byte constants baked into other templates (mis-matched hashes → broken freeze/issue/unfreeze paths at runtime). Tool runs in CI and is pre-publication gate for any template change.

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

| #   | Decision                                | Outcome                                                                                                                                                                                                                        |
| --- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------- | ----------------- | ------------------- | ------------------------------------------------------------------------------------- |
| 1   | Swap architecture                       | External protocol layer, not in BNTP core                                                                                                                                                                                      |
| 2   | Issuer liveness model                   | Rolling attestation (D+B combo) via depth counter; subscription business model                                                                                                                                                 |
| 3   | Owner PKH/MPKH                          | Both supported (flag bit 5)                                                                                                                                                                                                    |
| 4   | Amount precision                        | uint128 (ETH-compat)                                                                                                                                                                                                           |
| 5   | Attestation economics                   | Flat royalty paid in token amount (not satoshis), out of UTXO's own value                                                                                                                                                      |
| 6   | Attestation content                     | Minimal: tokenId + thisOutpoint + issuerPubkey (option A)                                                                                                                                                                      |
| 7   | On-chain freshness enforcement          | Off-chain advisory only (option A), no CLTV                                                                                                                                                                                    |
| 8   | Authority paths vs attestation          | Authority sig sufficient, no attestation required on freeze/confiscate (option B)                                                                                                                                              |
| 9   | Issue attestation                       | Required (option B) — for uniformity                                                                                                                                                                                           |
| 10  | OptionalData continuity                 | Preserved byte-exact (option A)                                                                                                                                                                                                |
| 11  | Attestation revocation                  | No separate mechanism; use confiscation if issuer mis-attested                                                                                                                                                                 |
| 12  | Naming                                  | BNTP (continuation of v1 research, not new protocol)                                                                                                                                                                           |
| 13  | `max_input_depth` sync on merge         | Free push + collective upper-bound enforcement. Over-reporting = self-harm, acceptable. See §9.2.1.                                                                                                                            |
| 14  | Issuer MPKH royalty owner               | royalty UTXO `owner = issuerPkh` with owner-MPKH flag bit 5 set for MPKH-gated spend. §9.3.                                                                                                                                    |
| 15  | Frozen body cross-template verification | Option β: embed 32b SHA256(Frozen_body) as constant in Normal. §5.5 body hash manifest.                                                                                                                                        |
| 16  | Tail layout                             | **111b** fixed, no `redemptionPkh`. Redeem collapsed into flex-transfer. §5.2, §9.6.                                                                                                                                           |
| 17  | Contract amount location                | In Contract tail as uint128 (mirrors Normal tail layout). §9.9.1.                                                                                                                                                              |
| 18  | uint128 vs ScriptNum arithmetic         | Storage format uint128; runtime cap ~int63 (9.2 × 10¹⁸). SDK validates. §9.11.                                                                                                                                                 |
| 19  | Body hash manifest pattern              | Accepted as WHITELIST replacement. 32b per cross-reference, not 128b block. §5.5.                                                                                                                                              |
| 20  | G5 gate target                          | Revised from ~2000b to ~2500b per Phase 0 pseudo-ASM validation. §11.1.                                                                                                                                                        |
| 21  | Depth overflow handling                 | **A: saturate at 65535.** `new_depth = min(max_input_depth + 1, 65535)`. §9.2 rule 10.                                                                                                                                         |
| 22  | `amounts_in_array` length               | **A: derive from outpoints count.** `                                                                                                                                                                                          | amounts_in_array | == N × 16`, N = ` | all_input_outpoints | /36`. §9.2 rule 6.                                                                    |
| 23  | Input layout contiguity                 | **A: BNTP inputs [0..N-1], funding at N.** Bound via `hashPrevouts` concatenation. §9.2 rule 2.                                                                                                                                |
| 24  | Null-data canonical encoding            | **A': force direct-push minimal** for all fields ≤ 75 bytes (32, 36, 33). Saves ~3b/tx vs forcing OP_PUSHDATA1. §7.2.1.                                                                                                        |
| 25  | Max N bound on flex-transfer            | **B': N ≤ 32.** Compromise between expressiveness (consolidate 32 in one tx) and worst-case unlocking (~1.9 KB). §9.2 rule 7.                                                                                                  |
| 26  | Deploy-time hash verification           | **A: SDK tool (Phase 1 deliverable).** Compiles bodies, verifies cross-template constants match, publishes manifest. §14.                                                                                                      |
| 27  | Cross-template body (Normal↔Frozen)     | **Hash + unlocking push.** Source embeds 32b hash; unlocking pushes target body (~700b freeze / ~2500b unfreeze), locking verifies SHA256 match. Rare paths → unlocking overhead acceptable. §5.5.1, §9.4, §9.7.               |
| 28  | Cross-template body (Contract→Normal)   | **Inline Normal body constant.** Contract body ≈3100b (one-shot mint). Issue unlocking stays small instead of `N × 2500b`. §5.5.2, §9.9, §9.9.1.                                                                               |
| 29  | Explicit PKH owner CHECKSIGVERIFY       | **Required.** Identity (HASH160 match) + authorization (CHECKSIGVERIFY) are independent; both mandatory. Covenant CHECKSIG is preimage-auth only, not owner-auth. +~5b PREFIX. §8.1.                                           |
| 30  | Explicit `M` push in flex-transfer      | **Required.** M ∈ [1,4] pushed as ScriptNum before output_tuples. Avoids fragile OP_DEPTH-based derivation. +~3b body. §9.2.                                                                                                   |
| 31  | Consensus-rules dependency              | **BSV post-Genesis required.** Normal body exceeds pre-Genesis opcode/stack-element limits. SDK gates deploys to post-Genesis networks. §13.6.                                                                                 |
| 32  | `body_before_tail` walk direction       | **Forward walk from start of scriptCode.** Deployment-time-known offset (`                                                                                                                                                     | PREFIX           | +                 | SUFFIX              | +2`) locates OP_RETURN. Backward scan rejected (optionalData may contain `0x6a`). §5. |
| 33  | `output_tuple` field encoding           | **Raw bytes, no push-opcode length prefix.** Locking script reconstructs the push prefix (`14` for 20b PKH, `4c XX` for MPKH preimage) on-chain during candidate output assembly. §9.2.                                        |
| 34  | MPKH issuer on refresh                  | **Required in v2.0 (Gap 4.1).** Path 2 locking branches on `authorityFlags bit 4`: PKH → HASH160+CHECKSIGVERIFY; MPKH → HASH160(preimage)+CHECKMULTISIGVERIFY. +~75b path 2. §9.3.                                             |
| 35  | Null-data index on refresh              | **Index 2 is normative (Gap 4.2).** Output[0]=refreshed, [1]=royalty, [2]=null-data. Locking parses at fixed offset; SDK emits at index 2. §9.3.                                                                               |
| 36  | Null-data / change on freeze/confiscate | **Disallowed (Gap 4.3).** Exactly 1 Normal/Frozen output. No null-data, no change. Funding handled externally. §9.4, §9.5.                                                                                                     |
| 37  | Change output on refresh                | **Optional (Gap 4.4).** If `change_script_bytes` non-empty in unlocking, locking appends P2PKH-style change at output index 3. +~30b path 2. §9.3.                                                                             |
| 38  | Path 1 FD-only varint retroactive opt   | **Apply (A.2.5).** A.2 showed candidate locking scripts always land in `[0xFD .. 0xFFFF]` range; retrofitting path 1 output reconstruction saves ~120b. Net impact with decisions #34+#37: body 2587 + 75 + 30 − 120 = ~2572b. |

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
- **2026-04-18** — Security / workflow review closed 6 spec gaps (decisions #21-#26, §15): depth overflow saturation (§9.2), `amounts_in_array` length derived from outpoints count (§9.2), input-layout contiguity rule BNTP inputs [0..N-1] + funding at N (§9.2), null-data canonical direct-push-minimal encoding (§7.2.1), max flex-transfer fan-in `N ≤ 32` (§9.2), and SDK deploy-time template hash verification tool as Phase 1 deliverable (§14). On-chain body impact: ~+35b added via extra checks → estimated Normal body ≈ **2496b**, still PASS under revised G5 gate (≤ 2500b) — edge case, exactly at boundary. Gap 4 is a **decrease** of ~3b per null-data tx (direct push < PUSHDATA1).
- **2026-04-18** — **A.2 real ASM completion + spec amendments** (`BNTP_V2_NORMAL_TEMPLATE_A2_REPORT.md`, delegated opus agent): paths 2 (refresh), 3 (freeze), 4 (confiscate) implemented. Full Normal body = **2587b PASS** (13b under G5 ceiling). A.2 agent discovered FD-only varint optimization saving ~160b across A.2 and retroactively applicable to A.1.1 for another ~120b. Surfaced 4 spec gaps; user ratified all 5 new decisions (#34-#38): (34) MPKH issuer on refresh normative per flag bit 4, +~75b; (35) null-data at output index 2 normative; (36) null-data and change disallowed on freeze/confiscate (simplest UX, no authority-op use case); (37) change output at index 3 optional on refresh, +~30b (UX: enables standard coin-selection); (38) retroactive FD-varint optimization on path 1 scheduled for A.2.5 agent round. Projected post-A.2.5 body: ~2572b PASS with ~28b margin. Full feature parity with spec (MPKH issuer on refresh, standard-UX change output).
- **2026-04-18** — **A.1.1 real ASM measurement** (`BNTP_V2_NORMAL_TEMPLATE_A1_1_REPORT.md`, artifact `src/bntp/v2/templates/normal-body.ts`): Normal PREFIX + flex-transfer SUFFIX compiled to **1901 bytes** via opus agent. Verdict: **PASS** (~37% under G5 ceiling 2600b, ~22% under pseudo-ASM claim 2461b). A.1.0 audit was asymmetrically miscalibrated: too pessimistic on PREFIX (preimage parse 121b vs predicted 180-300b, tail cache 164b in audit mid-range), too optimistic on output reconstruction (620b vs predicted 360-440b). Closed 2 new spec gaps surfaced during real ASM writing (decisions #32-#33, §15): (32) `body_before_tail` walk direction = forward from scriptCode start via deployment-time offset §5; (33) `output_tuple` field encoding = raw bytes, locking script reconstructs push prefixes on-chain §9.2. Also documented implementation detail for decision #21 depth saturation via explicit `OP_GREATERTHAN OP_IF` branch §9.2. A.2 remaining budget: ~700b slack (audit projects path 2+3+4 at 810-920b — tight, near PIVOT band). DSTAS finding: confirmed high-confidence that DSTAS PKH owner-auth relies solely on covenant CHECKSIG (no separate owner-sig), suggesting dormant DSTAS vulnerability — filed for separate investigation, does not block BNTP v2.
- **2026-04-18** — **A.1.0 pseudo-ASM audit** (`BNTP_V2_NORMAL_TEMPLATE_AUDIT.md`) closed 5 additional decisions (#27-#31): (27) cross-template body for rare paths via hash + unlocking-push (Normal↔Frozen) §5.5.1; (28) Contract inlines Normal body as constant (§5.5.2) — Contract body grows 500b → ~3100b but saves N×2500b in issue unlocking; (29) explicit PKH owner CHECKSIGVERIFY separate from covenant CHECKSIG §8.1; (30) explicit `M` (output count) push in flex-transfer unlocking §9.2; (31) BSV post-Genesis consensus requirement normative §13.6. Unlocking sizes revised: freeze ~960b, unfreeze/confisc-from-Frozen ~2760b (due to target body push). Normal body projection bumped 2496b → **~2550-2600b** (upper PASS band). Per-UTXO comparison to DSTAS adjusted: **−12%** Normal (was −15%), Frozen **−73%** (unchanged), Contract no longer per-UTXO-comparable (one-shot). Spec now frozen for A.1.1 real ASM writing.
