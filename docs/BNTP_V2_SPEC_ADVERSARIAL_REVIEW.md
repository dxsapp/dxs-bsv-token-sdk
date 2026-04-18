# BNTP v2 Spec Adversarial Review

**Reviewer:** external adversarial (Step C).
**Scope:** `BNTP_V2_SPEC.md` (frozen, feature-complete, 38 ratified decisions).
**Method:** 13-surface attack-probe pass. Prior findings from
`BNTP_V2_NORMAL_TEMPLATE_AUDIT.md`, `A.1.1`, `A.2`, `A.2.5` consulted first to
avoid duplication at the byte-budget / stack-choreography layer.
**Time:** ~90 min focused pass.

## Summary

- Findings: **1 critical, 6 moderate, 5 minor**
- Overall verdict: **SHIP-WITH-FIXES**
- One-paragraph overall impression: the architecture is structurally sound for
  its stated trust model — issuer-trusted B2G via attestation, conservation via
  a hashPrevouts-bound amounts array, per-input collective enforcement of
  tokenId and depth invariants. The 38 ratified decisions close most of the
  obvious attack classes. However, the spec still has **one critical
  trust-model edge** (confiscation depth-reset can be weaponised by a
  compromised or adversarial confiscAuth as a back-door refresh), a cluster of
  **moderate ambiguities around MPKH preimage structure** that let deployers
  silently ship weakened authorities without on-chain rejection, a **stale
  "redeem allows burn" clause in §4.2 rule 11** that directly contradicts §9.6,
  and **the issue path's `thisOutpoint` semantics are still undefined**
  (already flagged in §15 open question #2 but spec is supposedly frozen).
  None of these rise to protocol-breaking. They are fix-before-Phase-1B class.

## Critical findings

### Finding #1 — Confiscation is a back-door depth-refresh under adversarial/compromised confiscAuth

**Attack vector:** the confiscAuth key (distinct trust domain from the issuer;
typically a compliance officer, sometimes a regulator's HSM, in other deployments
a multisig federation) can cyclically confiscate and re-assign a UTXO to its
nominal owner, each cycle resetting `attestation_depth = 0` per §4.2 rule 4
and §9.5 rule 3. Because confiscation preserves `amount`, `tokenId`,
`issuerPkh`, and authority block and only changes `owner` (which confiscAuth
can freely set to anything, including the original owner), the end state is
indistinguishable from an issuer-attested refresh, but at zero royalty cost
and without issuer involvement.

Concrete scenario: a regulator-held confiscAuth on a regulated stablecoin
decides to pressure the issuer. Every N blocks it enumerates all live UTXOs
(via indexer), generates a confiscate-to-same-owner tx for each, and the
network of holders all end up with depth=0 UTXOs for free. The issuer loses
their attestation royalty stream permanently, degrading the protocol's
economic model (refresh subscription — §12, §7.4 "комиссия нарастает"). The
holders themselves see no harm; the harm is absorbed by the issuer. A
coordinated issuer-vs-confiscAuth dispute thus has a structural asymmetry
baked into the protocol.

A stronger version: if confiscAuth is compromised (key theft, insider rogue
compliance officer), the compromised key can mass-confiscate every UTXO and
**move them to attacker-controlled owners with depth=0**. Because each
output is depth=0 and the token's freshness policy says "trust depth ≤ N",
downstream wallets receiving these tokens from the attacker believe them
fresh — even though the issuer never touched them. The confiscAuth breach
cascades into a trust-model breach against downstream holders, not just
against the original holders.

**Why existing mitigations don't cover it:** §13.1 covers "issuer compromise"
but does not discuss confiscAuth compromise with equivalent severity. §4.2
rule 4 justifies depth reset with "confiscation implies authority has vetted
the new owner; fresh attestation semantically holds" — but this conflates the
confiscAuth trust domain with the issuer trust domain. The issuer's sign-off
was the anchor for depth=0 semantics; confiscAuth is a compliance-gated
authority with _different_ threat model. Decisions #8 (authority paths do not
require attestation) ratifies confiscAuth as an attestation-bypass. §13.3
(depth counter attacks) enumerates attacker-depth-manipulation via path 1 but
silently accepts path 4 depth=0 as legitimate.

**Minimum spec change to close:** either (a) preserve depth on confiscate
(symmetric with freeze/unfreeze, §4.2 rule 5-6), making path 4 a pure
ownership change with no freshness reset; or (b) require issuer attestation
on confiscate (mirror refresh), trading compliance latency for trust isolation.
Option (a) is the simpler fix and costs zero body bytes (the covenant already
reconstructs new_depth = my_depth for freeze).

**Confidence:** high.

**Steelman (team response):** "confiscation is a rare authority-gated operation;
compromised confiscAuth is game-over anyway, depth reset is the least of the
problems." **Refute:** depth-reset turns a targeted confiscation-compromise
into a _silent fresh-token forgery engine_ that downstream wallets cannot
distinguish from issuer-attested refresh. Without the reset, downstream
wallets see depth > 0 tokens and can at minimum apply freshness policy; with
the reset, the compromise is invisible. Also, this isn't only about compromise:
the _legitimate_ confiscAuth can undermine the issuer's royalty model with no
recourse, creating a governance attack surface. The fix is nearly free.

## Moderate findings

### Finding #2 — §4.2 rule 11 contradicts §9.6 (stale "redeem allows burn" wording)

**Attack vector:** specification ambiguity, not a direct exploit, but divergent
implementations are likely. §4.2 rule 11 states: "Amount sum conservation
enforced on flex-transfer and refresh. **Redeem allows burn** (P2PKH amount
does not need to match input; remaining goes to Normal remainders with
conservation: `input_amount == sum(remainder_amounts)`; P2PKH represents
out-of-protocol satoshi redemption tied to token being burned)." But §9.6 says
redeem is not a dedicated path — it is flex-transfer to issuer. §4.2 rule 1
says flex-transfer enforces `Σ input_amounts == Σ output_amounts` with no
burn allowance. The two rules collide. An implementer reading rule 11 in
isolation may attempt a "P2PKH-output-means-burn-allowed" exception to
conservation; a second implementer reading §9.2 rule 11 + §9.6 will implement
strict conservation. This is a protocol-level divergence.

**Why existing mitigations don't cover it:** the §15 ratified decisions
include "redeem collapsed into flex-transfer" (#16), but §4.2 rule 11 was not
purged. The language appears to be a v1 → v2 migration residue.

**Minimum spec change to close:** replace §4.2 rule 11 with: "Amount sum
conservation enforced on every spending path that produces BNTP outputs. No
burn path exists in v2; redeem is a flex-transfer to an issuer-owned address
with strict conservation (§9.6)."

**Confidence:** high.

### Finding #3 — MPKH preimage bounds `1 ≤ m ≤ n ≤ 5` are documentary, not normatively enforced on-chain

**Attack vector:** a deployer (honest or malicious) produces an
`owner_field` / `freezeAuthHash` / `confiscAuthHash` / `issuerPkh` that is
`HASH160` of an MPKH preimage with **m=0**. At spend time the unlocking
provides the preimage (which matches the hash), parsing yields m=0, and BSV's
`OP_CHECKMULTISIGVERIFY` with m=0 succeeds without consuming any signature.
The authority check becomes a no-op. §8.2 describes the check as:
`HASH160(mpkh_preimage) == expected_hash; Parse m and n from preimage;
OP_CHECKMULTISIGVERIFY against preimage-derived pubkey set` — with no
explicit normative `1 ≤ m ≤ n ≤ 5` verification step. The A.1.0 audit §3.2
_recommends_ the check (`OP_DUP 1 5 OP_WITHIN OP_VERIFY + OP_2DUP
OP_LESSTHANOREQUAL OP_VERIFY`, ~10b) but this is an implementation suggestion,
not a spec requirement.

Same attack: **m=n but all pubkeys are the same**. Preimage contains 5
identical pubkeys; m=3; any single signer produces 3 signatures from the same
key and spends. The per-UTXO "3-of-5 multisig" becomes "1-of-1". Spec does
not forbid pubkey duplicates.

Same attack: **m > n** (e.g., m=3, n=1). CHECKMULTISIG with m > n fails
consensus, so this is self-rejecting. But **m=0 and duplicate-pubkeys** are
real.

**Why existing mitigations don't cover it:** spec §8.2 text says "supports
m-of-n multisig, 1 ≤ m ≤ n ≤ 5 (per v1 identity-field spec)" as a descriptive
range, not a normative Script rule. The deployer's HASH160 commits to the
preimage, so the hash check alone does not constrain preimage content. Trust
model assumption ("deployer is honest") is hand-wave; authority deployers are
different from issuer and may be less vetted.

**Minimum spec change to close:** §8.2 normative block: "Script MUST enforce
`1 ≤ m ≤ n ≤ 5` AND MUST enforce that the n pubkeys parsed from the preimage
are pairwise distinct. Violation → OP_VERIFY-fail." Body cost ~20b per MPKH
verification (bounds + pairwise-distinct via n-choose-2 comparisons for n ≤ 5).

**Confidence:** high for m=0 bypass, medium for duplicate-pubkey attack
(self-harm if deployer misconfigures, but spec says nothing).

**Steelman:** "deployers vet their preimages off-chain; the hash commits to
whatever they chose." **Refute:** self-harm is one thing, but MPKH is used
for **freeze**, **confiscate**, **issuer** — authorities often deployed by
third parties (compliance shops, custody federations) who may not perform
byte-level preimage audits. A spec-level on-chain check at ~20b body cost
removes an entire class of silent-authority-bypass deployment bugs.

### Finding #4 — Issue-path `thisOutpoint` semantics undefined

**Attack vector:** §7.2 and §9.9 rule 8 both reference "null-data attestation"
at issue. §7.2 says the null-data `thisOutpoint` field is "UTXO being refreshed
(or first-issued outpoint at issue)". The phrase "first-issued outpoint" is
ambiguous:

- It cannot literally be a future outpoint of output[0] of the issue tx, because
  the tx's txid is not computable until after all sigs are in.
- It could be the Contract UTXO's outpoint (= the single spending input's
  outpoint) — but this is the _Contract's_ outpoint, not the new Normal's.
- SDKs implementing from spec alone may disagree. §15 open question #2
  literally says "Null-data at issue (path 6) — position of attestation
  null-data output when there are N token outputs. Simplest: always at index
  N. But varies with tx structure. Lock normative in Phase 1 Contract pseudo-ASM."
  — i.e., the spec _knowingly_ punts this. Phase 1B SDK will implement it
  one way, but nothing says a non-conformant SDK is rejected.

**Why existing mitigations don't cover it:** this is an explicit open question
in the spec's own §15 meta-list, yet the spec is labelled "frozen,
feature-complete". A frozen spec with open questions is a contradiction.

**Minimum spec change to close:** §9.9 rule 8: "Null-data output is at
index N (after all Normal outputs). `thisOutpoint` = spending Contract's
outpoint (from preimage). Verify byte-exact." Body cost negligible.

**Confidence:** high (verbatim open-question in spec).

### Finding #5 — Output-tuple `owner` encoding ambiguity: length vs flag-bit

**Attack vector:** §9.2 decision #33 says owner is pushed as raw bytes
without prefix; locking script emits `0x14` for 20b PKH, `0x4c LEN` for
35..171b MPKH. The rule says "determines PKH vs MPKH by reading the stored
byte length (via OP_SIZE) **and** by the owner-MPKH flag bit 5 in tail."
The conjunction is ambiguous — is flag bit 5 gating which prefix to emit,
or is it only an SDK hint? Two plausible implementations:

1. Emit prefix based on `OP_SIZE == 20 ? 0x14 : 0x4c+LEN` (length-only).
2. Emit prefix based on `flag-bit-5` (flag-only), with OP_VERIFY on size
   matching flag.
3. Both checked, fail if inconsistent.

Under (1), an attacker mismatches by pushing a 35-byte owner while source tail
has flag bit 5 = 0 (PKH). Script emits `0x4c 0x23` prefix, producing a target
locking script that uses an MPKH-shaped prefix but flag bit 5 = 0 (PKH). The
receiver of this UTXO, if their wallet parses by flag bit alone, reads the
first 20 bytes of owner as PKH when the actual push-opcode length is 35. A
spender-vs-receiver parse disagreement is a real divergent-implementation
surface. Under (2) similar issue in reverse. Only (3) closes the gap.

Consequence at worst: a receiver of a malformed UTXO might attempt to spend
it as PKH (20b interpretation), construct a sig, find the script rejects
(because on-chain it's 35b), and believe the UTXO is unspendable. More
likely just a UX glitch; not theft. But divergent implementations → confused
state → DoS against specific UTXOs.

**Why existing mitigations don't cover it:** decision #33 spec text does not
pick one of (1), (2), (3). Spec §9.2 rule 10 says "same authorityFlags
preserved byte-exact" — so flag bit 5 is preserved, but the OUTPUT's owner
length is controlled by the spender's tuple push.

**Minimum spec change to close:** pick option (3): "Script MUST verify
OP_SIZE of output owner matches flag bit 5 (`== 20` iff bit 5 = 0;
`∈ [35, 171]` iff bit 5 = 1); mismatch → fail."

**Confidence:** medium. No theft, but real divergence-DoS surface.

### Finding #6 — `change_satoshis` in refresh/issue is entirely unconstrained by the covenant

**Attack vector:** §9.3 rule 8 says `change_satoshis` is provided by the SDK
as an unlocking push; locking script uses it in the hashOutputs accumulator
and trusts it byte-exact. The spec text claims "`change_satoshis =
funding_input_satoshis − refresh_fees − dust(2 sats)`, computed on-chain from
`preimage.satoshis` of funding input (not directly accessible — SDK provides
`change_satoshis` as a push and locking verifies via hashOutputs byte-exact
match)" — but this is self-contradictory. The **covenant only verifies
hashOutputs**; it does not verify that `change_satoshis` equals
`funding_input_satoshis − fees`. The only constraint on `change_satoshis`
is BSV consensus: total_output_sats ≤ total_input_sats.

The practical consequence: the owner can set `change_satoshis` to any value
they like, including:

- Stealing from the funding input (set change_satoshis low, extra sats go to
  the miner fee).
- Overpaying if they want to burn satoshis.

This is owner self-harm, not theft against another party — so it's not a
security-severity finding per se. But the spec language misleads the reader
into thinking there is on-chain verification of change. This would matter if
someone builds a multi-party tx (e.g., an external swap) where **two
different parties fund different inputs** and the BNTP refresh consumes one.
An owner could siphon the other party's funding input via fee manipulation.

**Why existing mitigations don't cover it:** §9.3 rule 8 wording implies
verification that doesn't actually happen.

**Minimum spec change to close:** rewrite §9.3 rule 8: "`change_satoshis` is
owner-controlled (pushed via unlocking). The covenant only enforces
hashOutputs-byte-exact, not change value derivation. SDK builders MUST compute
`change_satoshis = funding_input_satoshis − fees − dust`; external-swap
protocols using refresh MUST treat `change_satoshis` as spender-controlled
and protect against fee-siphon by requiring co-signed commitment to fee
value." Also applies to §9.9 (issue-path change handling).

**Confidence:** medium. Real risk in multi-party txs; benign in single-signer
refresh.

### Finding #7 — Flex-transfer does not require a funding input, but the unlocking layout makes it non-trivial to omit

**Attack vector:** §9.2 unlocking has `[funding_outpoint]` required. The
contiguity invariant is `HASH256(all_input_outpoints ‖ funding_outpoint) ==
hashPrevouts`. If a tx has _no_ funding input (e.g., all BNTP inputs, fees
paid by leaving dust satoshis unclaimed in outputs), the hashPrevouts is
`HASH256(all_input_outpoints)`, and no extra bytes appended. The spec does
not say what `funding_outpoint` should be in that case — empty byte string?
Some sentinel? The locking script concatenates whatever the unlocking pushes.
Pushing an empty byte string gives `HASH256(all_input_outpoints ‖ "")` =
`HASH256(all_input_outpoints)` — so it works iff hashPrevouts was also
computed over just the BNTP inputs. This is fragile and under-specified.

**Why existing mitigations don't cover it:** spec §9.2 says
`funding_outpoint` unconditionally in unlocking layout. No explicit "may be
empty if no funding input" clause.

**Minimum spec change to close:** add: "If the tx has no funding input,
`funding_outpoint` MUST be pushed as a 0-byte string (empty push); the
contiguity invariant degenerates to `HASH256(all_input_outpoints) ==
hashPrevouts`. SDK validates `|funding_outpoint| ∈ {0, 36}`."

**Confidence:** medium. Under-specified, divergent-implementation risk.

### Finding #8 — Wallet-level: no on-chain defence against similar-`issuerPkh` UI attack

**Attack vector:** (mandatory probe #1). Two issuers with visually similar
wallet-display representations of `issuerPkh` — e.g., an attacker registers a
vanity address whose HASH160 shares a hex prefix with a legitimate issuer.
Wallet displays "0x4a3b1c...5f9e" alongside a trusted-registry match; user
glances, approves, ends up holding attacker-issued tokens indistinguishable
in wallet UI from the real ones. Attestation, depth, and conservation all pass
on-chain because the attacker's tokens are _internally_ consistent — the
deceit is purely off-chain identity.

**Why existing mitigations don't cover it:** §13 mentions trusted registry
dependency but does not flag the class of "registry spoof via visual
collision". §12.2 B2G pain resolution claims wallet verifies `issuerPkh`
against trusted registry, but nothing forces the wallet to do strict hex
compare vs Levenshtein-fuzzy UI presentation.

**Minimum spec change to close:** spec §13 new subsection: "Wallet MUST
compare `issuerPkh` against the trusted registry by raw-byte equality. Wallet
MUST NOT display truncated or Base58Check representations of `issuerPkh`
without indicating which representation is authoritative. Wallet MAY warn on
near-collisions to previously-approved issuers." Normative for wallet
vendors; not a Script change.

**Confidence:** medium (out of strict protocol scope, but belongs in spec
§13 as a wallet-guidance section).

## Minor findings

1. **§4.2 rule 10 "OptionalData byte-exact preserved across all token-leg
   outputs"** — good, but spec never states a _size_ bound on optionalData.
   §15 open question #3 punts to Phase 1. Larger optionalData = larger
   body_before_tail = larger per-output reconstruction cost. Miners may
   price this, but the protocol has no upper bound. Recommend setting the
   v1 limit (4096b) as spec default.

2. **Spec cross-references "§3.2 pseudo-ASM", "§3.3 (0x41 check)", "§3.6"**
   (the security §13.6 references §3.2; the attestation §7.5 references v1
   Способ C §3.2; §8.1 references §3.2; §9.11 references §3.2). None of
   these §3.x subsections exist in `BNTP_V2_SPEC.md` — they live in
   `BNTP_V2_TEMPLATE_NORMAL_ASM.md`. A reader of the spec alone hits
   dangling references. Editorial but misleading.

3. **Contract `attestation_depth` field is declared but unused (§9.9.1).**
   Reserved for layout uniformity. Contract issue path does not verify this
   field is zero at spend time (mint tx has no BNTP covenant on Contract
   output; §9.9.1 notes this). An attacker-issuer could set it to non-zero
   at mint — harmless (issue path does not copy it to Normal outputs; it's
   explicitly set to 0 per rule 6), but the spec could normatively say
   "Contract.attestation_depth SHOULD be zero at mint; issue path ignores
   it."

4. **§7.4 royalty "floor ≥ 1, ceiling none"** — no protocol-level cap on
   royalty. An issuer could charge royalty == my_amount, leaving user with
   depth=0 UTXO of amount=0. But amount=0 fails anti-dust (§9.2 rule 10
   "amount ≥ 1"). So refresh royalty ≤ my_amount − 1 effectively. Spec could
   make this explicit.

5. **§15 ratified decision #38 (FD-only varint optimisation)** assumes
   candidate locking script size ∈ [0xFD .. 0xFFFF]. A.2.5 report §3
   acknowledges this is a deployment-time invariant. If a future Normal
   body (e.g., with large optionalData) pushes above 65535b, the varint
   becomes malformed silently. Spec should add: "SDK deploy tool MUST
   reject template bodies where any candidate output may serialize to
   > 65535b."

## Probes that came back clean

- **Attestation replay across different outpoints (probe #2):** null-data
  binds `thisOutpoint`; script checks `thisOutpoint == my_outpoint` from
  preimage. Attestation cannot be applied to a different UTXO. ✓

- **Attestation replay of the same attestation against a later spend
  (probe #2 stale-reuse):** once a UTXO is refreshed, the outpoint is
  consumed; the same outpoint cannot be re-spent. Stale attestation
  reuse is impossible modulo chain reorganisation (see below).

- **Cross-input token mixing (probe #3):** each input's script requires
  all outputs share _its_ tokenId; mixing fails because two different
  tokenIds cannot both be satisfied by a single output tail. §13.4
  explicitly. ✓

- **`amounts_in_array` length mismatch (probe #3):** §9.2 rule 6 enforces
  `|amounts_in_array| == (|all_input_outpoints|/36) × 16` byte-exact. Short
  and long arrays both rejected. ✓

- **Input-contiguity violation (probe #3):** §9.2 rule 2 binds layout to
  hashPrevouts via concatenation order. Interleaved inputs yield different
  hashPrevouts than `HASH256(all_input_outpoints ‖ funding_outpoint)`.
  Reject. ✓

- **N=33 over-bound (probe #3):** §9.2 rule 7 explicitly `N ≤ 32`. Real
  ASM implementation (A.1.1, §4.1(b) N derive) would bounds-check. ✓
  **Caveat:** spec does not state the exact failure mode at N=33 (reject,
  or silently truncate?). Recommend explicit "N > 32 → OP_VERIFY fail".

- **Depth saturation at 65535 (probe #4):** §9.2 rule 10 Gap 1 closure,
  decision #21, implementation note in decision #38. Script enforces
  `new_depth == min(max_input_depth + 1, 65535)`. A saturated UTXO is
  still refreshable (resets to 0) or confiscatable. ✓

- **`max_input_depth` under-reporting (probe #4):** each input's script
  requires `my_depth ≤ max_input_depth`; under-report fails at least one
  input's check. §9.2.1. ✓

- **Cross-template body collision (probe #6):** SHA-256 preimage
  resistance of `h_Frozen`, `h_Normal` — 2⁻²⁵⁶. §13.7. ✓

- **Supply inflation via fake Contract (probe #7):** Contract's
  `reserve_amount` is in its own tail (scriptCode of the covenant); issuer
  sets it at mint time. An issuer choosing a huge reserve_amount is issuer
  self-attack (produces tokens indistinguishable from legit ones to
  off-chain validators that B2G via genesis — which is what §6
  "known limitation" explicitly acknowledges). Trust model: the issuer's
  registry entry commits to a specific `tokenId`, which commits to
  `SHA256(genesisTxId ‖ contractVout ‖ issuerPkh)`. A second mint by the
  same issuer produces a different tokenId (different genesisTxId), so
  clients querying for a specific tokenId cannot be confused across mints.
  Within a single tokenId, supply is fixed by Contract's reserve_amount.
  ✓ as long as off-chain registry maps tokenId → expected reserve_amount.

- **Contract mint-spend to P2PKH (probe #7):** Contract covenant requires
  issue-path reconstruction; a P2PKH-only spend of Contract would fail
  hashOutputs byte-exact. ✓ (Contract is spent via path 6 only.)

- **Tokens burned via amount=0 output (probe #13):** §9.2 rule 10 anti-dust
  `amount ≥ 1` per output. Enforced by script for every candidate output.
  Total Σ output_amounts must equal Σ input_amounts (§9.2 rule 11 strict
  after Finding #2 fix). No burn path. ✓ modulo Finding #2 ambiguity.

- **M < inputs with silent absorption (probe #13):** conservation is
  Σ in == Σ out, independent of the M/N ratio. Merging 4→1 requires the
  single output's amount = sum of inputs. Anti-dust prevents amount=0
  skimming. ✓

- **Sighash FORKID coverage (probe #9):** §3.3 (referenced from pseudo-ASM)
  explicit 0x41 check. BSV SIGHASH_FORKID covers hashPrevouts, hashSequence,
  hashOutputs — which is what the covenant relies on. ✓

- **Sequence-number mutation (probe #9):** hashSequence is covered by
  SIGHASH_FORKID. Mutating any input's sequence number invalidates the sig.
  ✓

- **Cross-chain replay (probe #10):** SIGHASH_FORKID includes a ChainID
  (`0x00` for BSV mainnet, different on testnet/fork). FORKID enforcement
  is a BSV consensus property; replay across forks blocked. ✓. Reorg
  within the same chain: a refreshed UTXO's outpoint is unique to the
  attesting tx's txid; reorgs that undo the attesting tx also undo the
  outpoint, so there is no "reusable" attestation stranded on an orphaned
  chain branch. ✓

- **tokenId collision (probe #11):** `SHA256(genesisTxId || contractVout ||
issuerPkh)` — 2⁻²⁵⁶ collision. ✓

- **Freeze/unfreeze/confiscate output count (probe #12):** §9.4, §9.5, §9.7
  each specify "exactly 1 output"; decision #36 says null-data and change
  disallowed on freeze/confiscate. Any extra output fails hashOutputs
  byte-exact. ✓ Confiscate from Frozen (§9.8) equally single-output.

- **Anti-dust on token amounts (probe #12):** §9.2 rule 10 amount ≥ 1 on
  flex-transfer. Refresh: both outputs have amount ≥ 1 (royalty ≥ 1, user
  amount = my_amount − royalty ≥ 1 iff my_amount ≥ 2 — spec does not
  explicitly require this; a refresh of an amount=1 UTXO would produce
  amount=0 user output, failing anti-dust on the reconstruction).
  Implicit: refresh requires my_amount ≥ 2. Minor spec gap; flag but
  unimpactful (amount=1 UTXO is trivially dust anyway).

- **Output ordering in refresh (probe #12):** decision #35 fixes
  output[0]=refreshed, [1]=royalty, [2]=null-data, [3]=optional change.
  Byte-exact hashOutputs match enforces ordering. ✓

## Meta-observations

1. **Three of the seven moderate findings (#2, #4, #5, partly #7) are
   spec ambiguities that the design process failed to fully close despite
   38 ratified decisions.** The pattern: a decision was ratified
   (redeem-collapses-to-flex-transfer, decision #16), but stale text
   elsewhere in the spec (§4.2 rule 11) was not purged. Or a decision was
   _deferred_ (issue-path null-data index, §15 open question #2) but spec
   was still labelled frozen. Recommendation: before Phase 1B, do a
   purge-pass of the spec cross-referencing every ratified decision
   against every mention in prose, tables, and rule-lists.

2. **MPKH preimage verification is systematically under-specified
   (finding #3).** The spec relies on deployer honesty for preimage
   integrity at multiple authorities (owner, freeze, confisc, issuer),
   but never normatively mandates the on-chain bounds / uniqueness
   checks that would catch deployer misconfiguration or malice. This is
   a spec-level MPKH hygiene gap; decision to close at spec level costs
   ~20b per MPKH verification block and is arguably cheap insurance.

3. **Depth-reset semantics have two policy domains (issuer vs
   confiscAuth) conflated via a single bit of freshness (depth=0).**
   Finding #1 is the concrete manifestation, but the underlying issue
   is that "depth=0" carries two different semantic payloads in the
   protocol: "issuer just vouched" (after refresh/issue) and "authority
   just vetted" (after confiscate). Wallets reading a depth=0 UTXO have
   no way to tell which path produced it. A field like
   `last_path_id ∈ {issue, refresh, confiscate}` in the tail (1 byte)
   would let wallets apply different trust weights. Deferrable to v2.1
   if Finding #1 is fixed by path-4 depth-preservation.

4. **Mandatory probe #11 (wallet-level attacks) is flagged as
   out-of-spec but is the trust-model's actual weakest point.** BNTP v2
   trades B2G chain-walk expense for "trust the issuerPkh registry".
   The registry itself is off-chain and unspecified; §13.1 addresses
   issuer-key compromise but not registry-spoof-via-UI-collision. If
   adoption is serious, spec §13 should include a normative "wallet
   display and registry lookup rules" subsection. Currently §13 is
   spec-thin on this.

## Reviewer confidence

**Probed deeply:**

- Conservation and tokenId enforcement on flex-transfer — §4, §9.2 read
  rule-by-rule; cross-referenced with A.1.1 and A.2 measured ASM.
- Attestation flow (§7, §9.3) — null-data binding, thisOutpoint coupling,
  replay surfaces.
- MPKH preimage structure (§8.2) — bounds, duplicate pubkeys, m=0 edge.
- Depth propagation semantics (§4, §9.2, §9.2.1) — saturation, confiscate
  reset, freeze preserve.
- Cross-template body hash mechanism (§5.5.1, §5.5.2, §13.7).

**Skimmed (follow-up recommended):**

- **Execution-trace of combined A.1.1 + A.2 + A.2.5 body (2574b).** A.2
  report §3.5 and A.2.5 §8 both explicitly defer formal stack
  choreography verification. Byte budget is confirmed; stack-correctness
  of the MPKH-issuer branch inside path-2 null-data parse (A.2.5 §4) is
  not independently traced. A stack-misalignment bug there would produce
  a silent fail-closed tx (not a security issue) but could also, in
  principle, produce a fail-open case if the altstack is mis-decoded.
  **Recommend:** a node-level execution trace with synthetic unlocking
  on testnet before Phase 1B SDK builder work commits.

- **Contract (path 6) issue reconstruction details.** Contract body is
  not yet written to real ASM (A.2 handles paths 2-4 in Normal only).
  §9.9 is spec-only; no byte-exact measurement. Issue-path attestation
  null-data thisOutpoint semantics (Finding #4) are therefore not yet
  closed _in implementation either_.

- **Frozen template body.** §5.5.1 embeds `h_Normal` in Frozen body.
  Frozen template body itself is not yet written; `h_Frozen` is a
  placeholder in A.2. Full round-trip freeze → unfreeze cannot yet be
  validated end-to-end.

- **Wallet-side verification flow.** Mandatory probe #11 flagged;
  wallet spec is out of scope of this review but belongs in a wallet
  guidance document co-ratified with §13.

**Not probed:**

- ZK-based B2G alternatives (§1 non-goal, deferred indefinitely).
- Swap protocol atomicity (§1 non-goal, external protocol).
- Economic modelling of royalty-scaled-by-depth at scale.

**Open items requiring follow-up before Phase 1B closes:**

1. Finding #1 fix (confiscate depth-preserve or attestation-required)
   — critical.
2. Finding #2 text purge (§4.2 rule 11) — moderate, trivial fix.
3. Finding #3 MPKH bounds normative — moderate, ~20b body cost.
4. Finding #4 issue-path thisOutpoint — moderate, spec-only fix.
5. Findings #5, #6, #7 — moderate, each a small spec edit.
6. Execution-trace of MPKH issuer branch in path 2 — implementation
   follow-up, not spec.
