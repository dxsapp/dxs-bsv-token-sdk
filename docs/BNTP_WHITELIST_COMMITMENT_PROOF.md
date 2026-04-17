# BNTP Whitelist Commitment Scheme — Soundness Analysis

**Slice:** Phase 0 / S2
**Status:** Phase 0 gate deliverable — rigorous prose argument (not symbolic proof)
**Scope:** the `h_X` / `WHITELIST` / `seriesId` construction as specified in `BNTP_SERIES_V1_SPEC.md` §§5.3, 6.1, 6.2, 7.2, 7.3, 7.4, 13.1, 13.2.

**Cryptographic assumptions used throughout:**

- `SHA256` is collision-resistant: finding `(x, y)` with `x ≠ y` and `SHA256(x) = SHA256(y)` is computationally infeasible.
- `SHA256` is preimage-resistant: given `h`, finding `x` with `SHA256(x) = h` is computationally infeasible.
- `SHA256` is second-preimage resistant: given `x`, finding `x' ≠ x` with `SHA256(x') = SHA256(x)` is computationally infeasible.
- The attacker is computationally bounded and cannot break any of the above.

All arguments reduce the soundness of the scheme to one of these three cryptographic assumptions, plus byte-exact comparison in the BSV script interpreter (`OP_EQUALVERIFY`).

---

## 1. Scheme recap

### 1.1 Template body structure

Every series template (Normal, Frozen, SwapReady; and also Contract, though Contract is out of whitelist) has a body of the following form, located between `OP_2DROP` and `OP_RETURN`:

```
BODY = PREFIX ‖ WHITELIST ‖ SUFFIX
```

- `PREFIX` is constant per template. It begins with a 2-byte **body marker** (§7.4 — `0x01ff` Normal, `0xfeff` Frozen, `0x0fff` SwapReady, `0xc0ff` Contract) and contains the spend-path dispatcher and opcodes that consume unlocking pushes.
- `WHITELIST` is a 96-byte block — byte-identical in all three series templates — defined below.
- `SUFFIX` is constant per template and contains the output-verification logic.

### 1.2 The shape hash `h_X`

For each template `X ∈ {Normal, Frozen, SwapReady}`:

```
h_X = SHA256(PREFIX_X ‖ SUFFIX_X)
```

Crucially, **`h_X` excludes `WHITELIST`** from its hash input. This is the self-reference-avoidance move that makes the whole scheme work (see §2 and Claim 1).

### 1.3 The whitelist block

```
WHITELIST = h_Normal ‖ h_Frozen ‖ h_SwapReady      (32 × 3 = 96 bytes)
```

This identical 96-byte sequence is embedded in all three series templates (and in Contract, for issue-path output validation). It is placed at a **fixed offset** from the start of `BODY` (immediately after `PREFIX_X`).

### 1.4 Identifiers

```
seriesId = SHA256(WHITELIST)
tokenId  = SHA256(genesisTxId ‖ contractVout ‖ issuerPkh)
```

`seriesId` commits to the entire whitelist; `tokenId` commits to issuance context. Both are pushed into the tail (§5.4) and checked per §7.3 on every descendant output.

### 1.5 Output verification — §7.2 in abstract form

Given a candidate output whose locking script the running UTXO must validate as a legitimate series sibling, the script performs (paraphrased from §7.2, steps 1–7):

1. Skip owner push and action-data push to reach `OP_2DROP`.
2. Skip `OP_2DROP` to reach the body.
3. Read the 2-byte body marker; dispatch to the known `PREFIX` length for that template variant.
4. Extract `output.WHITELIST` at the fixed offset (`|PREFIX_X|` bytes into body, 96 bytes long).
5. **Byte-match check:** `output.WHITELIST == this.WHITELIST` (compared via `OP_EQUALVERIFY` after concat).
6. Compute `h_candidate = SHA256(output.PREFIX ‖ output.SUFFIX)` — excluding `output.WHITELIST`.
7. **Membership check:** `h_candidate ∈ {h_Normal, h_Frozen, h_SwapReady}` where those three hashes are read out of `this.WHITELIST` (the same block we compared against in step 5).

These two checks — byte-match (step 5) and hash membership (step 7) — together with body-marker dispatch and tail consistency (§7.3), are the **entire novel primitive** we must prove sound.

### 1.6 Non-goals (for this document)

- We do **not** argue that a UTXO is legitimate back to genesis. `seriesId` and the whitelist scheme enforce a **forward** closed state only. See §6 below.
- We do **not** argue that issuer attestation (§9.4) is independently sound — it is treated as an orthogonal off-chain gate in §7.

---

## 2. Deterministic computation of `h_X`

A necessary preliminary: the scheme is only sound if `h_Normal`, `h_Frozen`, `h_SwapReady` can be deterministically computed from the template specifications alone, without circular dependency on the whitelist they will eventually embed. The procedure is:

**Step 0 — Fix the template shapes.** The designer finalises `PREFIX_Normal`, `SUFFIX_Normal`, `PREFIX_Frozen`, `SUFFIX_Frozen`, `PREFIX_SwapReady`, `SUFFIX_SwapReady` as byte strings (pseudo-ASM → concrete opcodes → byte encoding). These contain no reference to any hash of themselves.

**Step 1 — Compute the three shape hashes independently.**

```
h_Normal    = SHA256(PREFIX_Normal    ‖ SUFFIX_Normal)
h_Frozen    = SHA256(PREFIX_Frozen    ‖ SUFFIX_Frozen)
h_SwapReady = SHA256(PREFIX_SwapReady ‖ SUFFIX_SwapReady)
```

Each of these is a standard SHA256 over two fixed byte strings. No hash input contains any of `h_Normal`, `h_Frozen`, `h_SwapReady`, so there is no self-reference.

**Step 2 — Assemble the whitelist block.**

```
WHITELIST = h_Normal ‖ h_Frozen ‖ h_SwapReady
```

**Step 3 — Substitute the whitelist into each deployed template.**

```
DEPLOYED_BODY_X = PREFIX_X ‖ WHITELIST ‖ SUFFIX_X     (for X ∈ {Normal, Frozen, SwapReady})
```

All three deployed templates carry the **same 96 bytes** at a known offset.

**Step 4 — Compute seriesId.**

```
seriesId = SHA256(WHITELIST)
```

This sequence is a total function of the template shapes. There is no fixpoint equation to solve because `h_X`'s input excludes `WHITELIST`. Anyone given the three `(PREFIX_X, SUFFIX_X)` pairs can independently reproduce `h_X`, `WHITELIST`, and `seriesId` byte-for-byte.

**Reproducibility:** since the procedure is deterministic and parameter-free, two independent implementations (e.g., SDK vs auditor's tool) must agree on every byte of the final templates and on `seriesId`. This is important for trust: an auditor can recompute the whitelist from the claimed template shapes and verify the deployed templates match.

**Placeholder note.** During pseudo-ASM development it is common to write the template with 96 zero bytes as a placeholder for `WHITELIST` (purely to typeset fixed offsets correctly). Critical: the zero-placeholder is **not** an input to `h_X`. The hash is computed over `PREFIX_X ‖ SUFFIX_X`, skipping the 96-byte window entirely. The zero placeholder is only an editorial device for human readers of the pseudo-ASM listing; it never participates in any cryptographic computation.

---

## 3. Five claims — rigorous arguments

### 3.1 Claim 1 — Self-reference resolution is sound

**Claim.** There exists a unique, well-defined, efficiently-computable assignment of values to `(h_Normal, h_Frozen, h_SwapReady, WHITELIST, seriesId)` consistent with the definitions in §1.

**Why this claim is non-trivial.** In naive protocol design, one might try `h_X = SHA256(FULL_BODY_X) = SHA256(PREFIX_X ‖ WHITELIST ‖ SUFFIX_X)`, where `WHITELIST` itself contains `h_X`. That formulation is a fixpoint equation: solving it requires finding a 32-byte value `h_X` that equals its own SHA256 image over a specific context — computationally infeasible under preimage resistance, and unstable in practice.

**Argument.**

The scheme breaks the fixpoint by removing `WHITELIST` from the hash preimage:

```
h_X = SHA256(PREFIX_X ‖ SUFFIX_X)     (WHITELIST is excluded)
```

The preimage `PREFIX_X ‖ SUFFIX_X` is a fixed byte string determined entirely at template-design time (Step 0 in §2). The function `SHA256` is a total function on byte strings. Therefore `h_X` exists and is uniquely determined as `SHA256` of a concrete byte string — no fixpoint, no self-reference.

Given `h_Normal, h_Frozen, h_SwapReady`, the assembly `WHITELIST = h_Normal ‖ h_Frozen ‖ h_SwapReady` is simple concatenation, trivially well-defined. And `seriesId = SHA256(WHITELIST)` likewise.

**Formal-style fixpoint argument.** Let `f : BYTES^96 → BYTES^96` be the substitution "given a proposed whitelist `W`, replace the 96-byte window in each template body with `W`, then compute the fresh whitelist from the resulting bodies". For the scheme to admit a self-consistent whitelist, we'd in principle need a fixpoint `W* = f(W*)`. In our construction, `f(W) = h_Normal ‖ h_Frozen ‖ h_SwapReady` where each `h_X = SHA256(PREFIX_X ‖ SUFFIX_X)` **does not depend on the `W` argument** (since the hash skips the window). Therefore `f` is a constant function. A constant function has exactly one fixed point — its constant value. That fixed point is the deployed whitelist. No iteration, no solve, no SHA256 inversion needed.

**Conclusion.** The scheme is well-defined, non-circular, efficiently computable, and auditable. Claim 1 holds.

---

### 3.2 Claim 2 — Whitelist byte-match prevents series spoofing

**Claim.** An attacker cannot produce an output accepted by §7.2 whose `output.WHITELIST` differs from the running UTXO's `this.WHITELIST`.

**Attack model.** Attacker controls the spending transaction and therefore the bytes of any output script. The running UTXO is an honest series member. Attacker's goal: get the running UTXO's `SUFFIX` logic to treat the output as a legitimate series sibling while the output actually points at a **different whitelist** — for example, one containing `h` values of the attacker's own malicious templates with weaker spend paths.

**Argument.**

Step 5 of §7.2 performs a byte-exact 96-byte comparison via concat-and-`OP_EQUALVERIFY`:

```
output.WHITELIST == this.WHITELIST     (96 bytes)
```

`OP_EQUALVERIFY` on BSV script is byte-literal comparison; any single-bit difference in the 96 bytes aborts the script with FAIL. There is no variable-length encoding inside this check — the script extracts a known 96-byte window at a known offset (after reading body marker and advancing by `|PREFIX_X|`).

For the attack to succeed, the attacker would need to produce 96 bytes `W'` with `W' ≠ this.WHITELIST` but `OP_EQUALVERIFY(W', this.WHITELIST) == TRUE`. No such `W'` exists under the BSV script spec: `OP_EQUALVERIFY` is exact byte-for-byte.

Therefore every accepted output has `output.WHITELIST = this.WHITELIST` byte-for-byte. Combined with Claim 3 below, this binds the output to exactly the three templates whose hashes are listed in that shared whitelist — i.e., the running UTXO's own series.

**Conclusion.** Byte-match eliminates whitelist divergence at output-creation time. Claim 2 holds.

---

### 3.3 Claim 3 — Body hash binding prevents novel-template injection

**Claim.** An attacker cannot produce an output accepted by §7.2 whose body (PREFIX, SUFFIX) is not the body of one of the three templates `{Normal, Frozen, SwapReady}` in this series.

**Attack model.** Attacker controls output script bytes. Their goal: inject a "wannabe sibling" with some novel, attacker-favourable logic in `PREFIX` or `SUFFIX`, while correctly replaying `this.WHITELIST` in the middle (so Claim 2's check passes).

**Argument.**

Step 7 of §7.2 computes

```
h_candidate = SHA256(output.PREFIX ‖ output.SUFFIX)
```

and asserts `h_candidate ∈ {h_Normal, h_Frozen, h_SwapReady}`, where those three target hashes are read directly out of `this.WHITELIST` (already byte-matched, per Claim 2).

Suppose the attacker's body is `(PREFIX*, SUFFIX*)` with `SHA256(PREFIX* ‖ SUFFIX*) = h_candidate`. The check passes only if `h_candidate` equals one of `{h_Normal, h_Frozen, h_SwapReady}`. There are two cases:

- **Case A — the attacker's body is identical to one of the three legitimate templates.** Then the "attack" is just replaying a legitimate template body; no attack. Acceptance is correct.
- **Case B — the attacker's body differs from all three legitimate templates.** Then `(PREFIX*, SUFFIX*) ≠ (PREFIX_X, SUFFIX_X)` for all `X`, but `SHA256(PREFIX* ‖ SUFFIX*) = SHA256(PREFIX_X ‖ SUFFIX_X)` for some `X`. This is a SHA256 second-preimage find. Infeasible under the assumptions in §1.

**Completeness edge-case: equal preimages under different parses.** Could the attacker choose a body that is byte-identical to, say, `PREFIX_Normal ‖ SUFFIX_Normal` when concatenated, but parses differently because of, e.g., a different body marker? No: the script reads the body marker first (step 3), which forces a specific `|PREFIX_X|`, which forces a specific `output.PREFIX` slice. If the attacker alters the body marker to a different template's marker, the slice boundary moves, but the concatenation `output.PREFIX ‖ output.SUFFIX` is still the same total bytes (the concatenation just drops the middle 96-byte window). So the hash computed is over the exact template-X body-minus-whitelist, which must already match `h_X` for the dispatch to be valid. Body-marker spoof is further addressed in §3.4 and §4.2.

**Conclusion.** Only legitimate series templates can be output targets, unless SHA256 is broken. Claim 3 holds.

---

### 3.4 Claim 4 — Variant confusion resistance

Spec §13.2 already sketches this attack class informally. We make it rigorous.

**Claim 4a — PREFIX-SUFFIX hybrid.** An attacker cannot craft an accepted output whose `PREFIX` comes from template A and `SUFFIX` comes from template B ≠ A.

Attacker's candidate: `PREFIX_A ‖ WHITELIST ‖ SUFFIX_B`.
Hash computed by step 7: `SHA256(PREFIX_A ‖ SUFFIX_B)`.
This must ∈ `{h_Normal, h_Frozen, h_SwapReady} = {SHA256(PREFIX_Normal ‖ SUFFIX_Normal), …}`.
For acceptance, we need `SHA256(PREFIX_A ‖ SUFFIX_B) = SHA256(PREFIX_X ‖ SUFFIX_X)` for some `X ∈ {Normal, Frozen, SwapReady}`.

Three sub-cases:

- If `X = A`: `SHA256(PREFIX_A ‖ SUFFIX_B) = SHA256(PREFIX_A ‖ SUFFIX_A)`. Since `SUFFIX_B ≠ SUFFIX_A` (different template), this is a second-preimage on SHA256. Infeasible.
- If `X = B`: `SHA256(PREFIX_A ‖ SUFFIX_B) = SHA256(PREFIX_B ‖ SUFFIX_B)`. Since `PREFIX_A ≠ PREFIX_B`, second-preimage. Infeasible.
- If `X = C` (third template): both `PREFIX_A ≠ PREFIX_C` and `SUFFIX_B ≠ SUFFIX_C` typically. Second-preimage. Infeasible.

In all cases, acceptance requires a SHA256 second-preimage. Attack fails.

**Plus:** the body marker at byte 0 of `PREFIX_A` says "I'm template A". The dispatch in step 3 reads the marker and sets `|PREFIX_X| = |PREFIX_A|`. Therefore the script slices the body assuming A's prefix length. If `SUFFIX_B` is not at the offset implied by A's prefix length (which it almost certainly is not — different templates have different prefix lengths per §12.1), the slicing is wrong and `h_candidate` is computed over the wrong bytes, so the mismatch is even more decisive. This is a defence-in-depth layer on top of the hash argument.

**Claim 4b — PREFIX-WHITELIST-SUFFIX cross-series hybrid.** Attacker crafts `PREFIX_A ‖ WHITELIST_B ‖ SUFFIX_A` where `WHITELIST_B` is from a different series.

Step 5 byte-matches `output.WHITELIST` against `this.WHITELIST`. Since `WHITELIST_B ≠ this.WHITELIST = WHITELIST_A`, the comparison fails immediately. Attack caught at step 5. (See also Claim 5 for the full cross-series argument.)

**Claim 4c — body-marker confusion alone.** Attacker takes a legitimate body `PREFIX_Normal ‖ WHITELIST ‖ SUFFIX_Normal` but flips the first two bytes (marker) from `0x01ff` to `0xfeff` (Frozen marker).

The marker is physically inside `PREFIX_Normal`, so flipping it changes `PREFIX_Normal` to some `PREFIX_Normal'` that differs in the first two bytes. Then `SHA256(PREFIX_Normal' ‖ SUFFIX_Normal) ≠ h_Normal` (assuming no SHA256 collision). Nor does it equal `h_Frozen` (which hashes a completely different `PREFIX_Frozen ‖ SUFFIX_Frozen`). The membership check (step 7) rejects.

Additionally: the dispatch (step 3) read the marker as `0xfeff` → Frozen, so it set `|PREFIX_X| = |PREFIX_Frozen|` and sliced at that offset. Since the body's actual layout is still Normal-sized, the WHITELIST window and SUFFIX slice are at wrong offsets, so the byte-match in step 5 likely also fails. Two-layer defence.

**Conclusion.** Mixing components across templates or variants fails either at byte-match (step 5) or at hash-membership (step 7), with body-marker dispatch providing a second line of defence. Claim 4 holds.

---

### 3.5 Claim 5 — Cross-series spoofing resistance

**Claim.** Given two distinct deployed series `S_A` and `S_B` with different template shapes, an attacker cannot produce an `S_A`-accepted output that is structurally in `S_B`, nor vice versa.

**Attack model.** Attacker controls outputs. Running UTXO is a legitimate member of `S_A` with whitelist `WHITELIST_A` and `seriesId_A = SHA256(WHITELIST_A)`. Attacker wants an output that is acceptable to `S_A`'s SUFFIX logic but actually points at `S_B`'s templates (or some mix).

**Argument.**

The two series have distinct template shapes: `(PREFIX_X^A, SUFFIX_X^A) ≠ (PREFIX_X^B, SUFFIX_X^B)` for at least one `X` (otherwise they would be the same series). This implies at least one `h_X^A ≠ h_X^B`, which implies `WHITELIST_A ≠ WHITELIST_B` as 96-byte strings.

Case analysis on what the attacker's output carries:

- If the output carries `WHITELIST_B`: step 5 compares `output.WHITELIST = WHITELIST_B` against `this.WHITELIST = WHITELIST_A`. Since they differ as byte strings, `OP_EQUALVERIFY` FAILs. Attack rejected at step 5.
- If the output carries `WHITELIST_A` (i.e., impersonates `S_A`): then by Claim 3 the body hashes must match `{h_Normal^A, h_Frozen^A, h_SwapReady^A}`. These are the templates of `S_A`, so the output is _actually_ in `S_A`, not in `S_B`. No cross-series spoof — it's just a correct `S_A` output.
- If the output carries some mixed whitelist `WHITELIST_M` containing hashes from both series: step 5 requires `WHITELIST_M = WHITELIST_A` byte-for-byte. If it does, it _is_ `WHITELIST_A` — no mixing. If it doesn't, FAIL at step 5.

Separately: `seriesId_A = SHA256(WHITELIST_A)` is recorded in the tail and checked on every output by §7.3 step 1. If an attacker does find a whitelist `W'` with `SHA256(W') = SHA256(WHITELIST_A)` and substitutes it, that's a SHA256 second-preimage. Infeasible.

**Contrapositive phrasing.** "Two UTXOs have the same `seriesId` ⇒ they have the same `WHITELIST`" is contingent on SHA256 collision resistance. "Two UTXOs have the same `WHITELIST` ⇒ they agree on `{h_Normal, h_Frozen, h_SwapReady}`" is definitional. Hence "same `seriesId` ⇒ accept outputs only of the three templates in that shared whitelist" holds under the SHA256 assumption.

**Conclusion.** There is no cross-series spoofing path. Two series are cryptographically disjoint (up to SHA256 breakage). Claim 5 holds.

---

## 4. Attack surface enumeration

### 4.1 Whitelist spoofing — §13.1

**Attacker goal.** Produce an output that passes §7.2 but whose `WHITELIST` bytes point at attacker-controlled templates (e.g., templates with weaker spend paths or removed authority checks).

**What they control.** Entire output locking script bytes.

**Why it fails.** Step 5 byte-matches `output.WHITELIST == this.WHITELIST`. Any divergence FAILs `OP_EQUALVERIFY`. See Claim 2. Combined with Claim 3, whitelist tampering in _any_ form fails.

**Residual risk.** Zero under the stated cryptographic assumptions, modulo the body-parser correctly locating the 96-byte window. This is an implementation concern (not a scheme concern) — see §5 "OP_PUSHDATA malleability" discussion.

---

### 4.2 Body marker spoofing — §13.2

**Attacker goal.** Misclassify a body: e.g., present Normal body logic but trick the SUFFIX into dispatching as Frozen, or vice versa, hoping to bypass authority requirements specific to one state.

**What they control.** The first two bytes of body (the marker), and potentially all subsequent bytes.

**Why it fails.** The dispatch in step 3 reads the marker and maps to `|PREFIX_X|` for `X ∈ {Normal, Frozen, SwapReady, Contract}`. An invalid marker (not one of the four) aborts dispatch (§13.2: "Dispatch logic explicitly checks marker ∈ {0x01ff, 0xfeff, 0x0fff, 0xc0ff} and rejects otherwise"). A legal-but-wrong marker (§3.4 Claim 4c): the marker is part of `PREFIX`, so flipping it alters `PREFIX` and therefore alters `SHA256(PREFIX ‖ SUFFIX)`. The new hash is not in `{h_Normal, h_Frozen, h_SwapReady}` unless the attacker finds a SHA256 second-preimage. Hash membership (step 7) rejects.

**Additionally, Contract spoofing.** Contract's marker `0xc0ff` is dispatchable but `h_Contract` is NOT in the whitelist. If an attacker presents a Contract-shaped body with marker `0xc0ff`, step 7 looks for `h_candidate` in `{h_Normal, h_Frozen, h_SwapReady}`. Contract's hash is not in that set, so rejection is immediate. This confirms the spec's §3.1 claim that Contract cannot be re-emitted from a series UTXO.

**Residual risk.** Zero under the assumptions, provided the dispatch table is correctly hard-coded and the marker check `∈ {0x01ff, 0xfeff, 0x0fff, 0xc0ff}` is wired into the SUFFIX (see §5 for the recommendation).

---

### 4.3 Self-reference exploitation

**Attacker goal.** Exploit a circular-definition ambiguity in the whitelist scheme — e.g., find alternative assignments of `h_X` values that self-consistently embed in the whitelist but differ from the "canonical" ones.

**What they control.** Template design choices; but to be a real attack, the attacker must be able to swap values without being detected.

**Why it fails.** §2 established that the mapping `(template shapes) → h_X values` is a **constant function** — it does not depend on the whitelist value being assembled. Therefore the "valid assignment" is unique. There is no second self-consistent whitelist for a fixed set of template shapes — period.

If an attacker tries to claim "my `WHITELIST'` is also valid for these templates", then either (a) `WHITELIST' = WHITELIST` (no attack — same bytes), or (b) `WHITELIST' ≠ WHITELIST`, in which case it's not the assembly of the actual `h_X` values, so any template that claims to embed `WHITELIST'` is not a member of this series (seriesId differs, step 5 byte-match fails on any genuine UTXO of this series).

**Residual risk.** Zero — self-reference was structurally excluded.

---

### 4.4 Cross-series migration

**Attacker goal.** Migrate a UTXO from series `S_A` to series `S_B` (or to a fabricated series) without the off-chain validator or on-chain script noticing.

**What they control.** Spending tx; output bytes.

**Why it fails.** See Claim 5. Step 5 byte-match and §7.3 step 1 `seriesId` equality both force `output.seriesId == this.seriesId` and `output.WHITELIST == this.WHITELIST`. Cross-series is structurally blocked. Any "migration" output would be rejected by the running UTXO's SUFFIX.

Note: the `tokenId` check in §7.3 additionally prevents cross-token migration within a series (except in swap-exec's specific cross-token path, which is explicitly scoped and rate-checked in §9.9).

**Residual risk.** Zero for on-chain enforcement. Off-chain, a user could be tricked into **accepting** an attacker-operated series as genuine (phishing-style attack on identity), but that is not what the commitment scheme claims to defend against — it defends the forward state of a specific series, not the identity of the series itself to end users. See §6.

---

## 5. NEW attack surfaces (discovered during analysis)

This section enumerates additional attack concerns not called out in spec §13. Each is either dismissed with rigour or flagged as a concern (in which case a **SPEC AMENDMENT REQUEST** is raised).

### 5.1 Accidental `h_X` collision between templates

**Concern.** Could two templates in the series accidentally produce the same shape hash — e.g., `h_Normal = h_Frozen`? If so, body-marker dispatch would be ambiguous or the membership set `{h_Normal, h_Frozen, h_SwapReady}` would be smaller than 3.

**Analysis.** `h_X = SHA256(PREFIX_X ‖ SUFFIX_X)`. For two templates with different semantics (Normal vs Frozen), the bodies differ materially: different body markers (2 bytes), different dispatcher logic, different SUFFIX verification. The preimages differ in hundreds of bytes. For two different preimages to hash to the same SHA256 output is a collision — infeasible (2^128 work). We do not rely on "templates are very different"; we rely on SHA256 collision resistance.

**Dismiss.** No spec change needed.

### 5.2 Chosen-prefix or chosen-body SHA256 attacks

**Concern.** Could an attacker engineer a malicious `(PREFIX*, SUFFIX*)` such that `SHA256(PREFIX* ‖ SUFFIX*) = h_X` for some legitimate `X`? This is a second-preimage attack; currently infeasible for SHA256.

**Analysis.** SHA256 has 256-bit output; second-preimage complexity is ~2^256. No known cryptanalytic shortcut reduces this below 2^200. For the scheme to break by this route, SHA256 would have to be severely weakened. The BNTP protocol's assumptions are the same as Bitcoin's own (block-header hashing, merkle roots, signature hashing): any break here has far greater implications than a BNTP problem.

**Dismiss.** No spec change needed. If SHA256 ever is broken, BNTP is not uniquely endangered — it is endangered exactly as Bitcoin itself is.

### 5.3 Preimage-style coincidence on a crafted SUFFIX

**Concern.** Could an attacker pick a random `SUFFIX*` and by luck have `SHA256(PREFIX_Normal ‖ SUFFIX*) = h_Normal`? This is a preimage of `h_Normal` constrained to a specific PREFIX. Also infeasible under SHA256 preimage resistance.

**Dismiss.** Probability ≈ 2^-256 per trial.

### 5.4 Placeholder zero-byte special case

**Concern.** Earlier drafts might have accidentally included the 96 zero bytes as part of the hash input. If a reviewer reads pseudo-ASM with `WHITELIST = 00 × 96` and hashes it naively, they would compute a different `h_X` than the spec intends.

**Analysis.** §2 Step 1 is explicit: `h_X = SHA256(PREFIX_X ‖ SUFFIX_X)`. Zero bytes are not a hash input. The placeholder is only an editorial device. Any implementation that hashes the placeholder would diverge from spec and be caught at the first interop test (its `seriesId` would not match the auditor-recomputed `seriesId`).

**SPEC AMENDMENT REQUEST (minor):** add a clarifying sentence to §5.3:

> "When documenting a template in pseudo-ASM, the `WHITELIST` block is conventionally shown as `00 × 96` for readability. This placeholder is NEVER a hash input — `h_X = SHA256(PREFIX_X ‖ SUFFIX_X)` skips the 96-byte window entirely. Implementations must be careful not to accidentally include the placeholder bytes when computing `h_X`."

This is an editorial clarification to prevent implementer error, not a protocol change.

### 5.5 Pushdata-encoding malleability of the body

**Concern.** BSV has multiple ways to push the same byte string: direct-push (1–75 bytes), `OP_PUSHDATA1`, `OP_PUSHDATA2`, `OP_PUSHDATA4`. Could an attacker encode the output body using an alternative pushdata form so that `output.PREFIX ‖ output.SUFFIX` hashes identically to `h_X` but the on-chain bytes differ? This would be a way to produce an output whose raw script bytes differ from the legitimate template but whose "canonical body" agrees.

**Analysis.** Two things to consider:

1. **Where pushdata lives in the locking script.** The locking script has pushdata opcodes at the top (owner push, action-data push) — these are _variable_, known and handled by the parser (steps 1–2 of §7.2). After `OP_2DROP` the body begins. The body itself is a sequence of opcodes (comparisons, flow control, hash checks, etc.), not pushdata chunks — or at least the body's fixed portion is opcode-by-opcode. Any pushdata _inside_ the body is part of the fixed `PREFIX` or `SUFFIX` constants and must be byte-identical to the template spec. BSV's standard parsing is byte-literal — the bytes of `PREFIX_X` are fixed, including any pushdata prefix bytes they contain.

2. **Hash input.** `h_X` is computed over the literal bytes of `PREFIX_X ‖ SUFFIX_X`. Two pushdata encodings of the same payload produce different literal bytes and therefore different `h_X`. So "equivalent but different encoding" does not produce the same hash — and therefore cannot pass the membership check in step 7.

**Implication.** The scheme is _safe_ against pushdata malleability **in the body**, because it hashes raw bytes, not parsed opcodes. Two bodies that differ in pushdata encoding produce different `h_X` and thus different output acceptance.

**What about the outer locking script (owner push, action data)?** The owner push and action data are outside the body and outside the hash; they can be any valid pushdata encoding. This is fine because they are intentionally variable and are checked by other means (owner sig, action-data marker in §5.2).

**Dismiss with caveat.** No scheme-level vulnerability. **SPEC AMENDMENT REQUEST (clarifying):** add to §7.2:

> "Step 3's 'read fixed-length PREFIX' means reading a known _byte count_ `|PREFIX_X|` from the body; the script does not parse pushdata structure inside PREFIX. Likewise for SUFFIX. The hash in step 6 is SHA256 of the raw byte slices, not of a canonicalised-opcode form. This ensures pushdata-encoding variants are treated as distinct bodies (which is correct: a variant-encoded body has a different `h_X` and does not pass membership)."

### 5.6 Parser-offset ambiguity between SUFFIX end and OP_RETURN

**Concern.** The body ends at `OP_RETURN`. Could an attacker insert bytes between `SUFFIX` and `OP_RETURN` (or include `OP_RETURN` lookalikes earlier) to confuse parsing?

**Analysis.** The §7.2 parser advances by fixed offsets: `|PREFIX_X|` for PREFIX (after body marker), 96 bytes for WHITELIST, `|SUFFIX_X|` for SUFFIX. After that, the parser expects `OP_RETURN` at the exact next byte. Any extra byte before `OP_RETURN` shifts everything and the `h_candidate` slice is wrong, so step 7 fails. Any attempt to extend SUFFIX with attacker-chosen bytes also changes `h_candidate` and fails step 7.

**What if the attacker adds bytes AFTER `OP_RETURN` that look like fake tail?** That's fine — the tail is always after `OP_RETURN` and §7.3 reads fixed-length fields. Only the prefix/body is relevant for the commitment check.

**Dismiss.** No spec change needed — offsets are fixed, and hash-membership is strict.

### 5.7 Body-marker dispatch completeness

**Concern.** §7.2 step 3 dispatches on the body marker to select `|PREFIX_X|`. The spec lists four markers (`0x01ff`, `0xfeff`, `0x0fff`, `0xc0ff`). If the SUFFIX logic does not explicitly reject unknown markers, an attacker could push an unrecognised marker and hope the default branch is permissive.

**Analysis.** Spec §13.2 says the dispatch "explicitly checks marker ∈ {0x01ff, 0xfeff, 0x0fff, 0xc0ff} and rejects otherwise". This must be enforced at pseudo-ASM level as an explicit `OP_EQUAL` chain with `OP_VERIFY` (e.g., `marker == 0x01ff OR marker == 0xfeff OR marker == 0x0fff OR marker == 0xc0ff`, else FAIL). This is S1's concern; we note it here as a cross-reference.

**Additionally,** for outputs from a series template (Normal/Frozen/SwapReady), `0xc0ff` (Contract) should be rejected because Contract is not a valid output target for series-member spends (§3.1). The valid-output marker set for a series spend is `{0x01ff, 0xfeff, 0x0fff}`. Contract's marker may be recognised for dispatch-table completeness but must never pass the §7.2 membership check (it doesn't, because `h_Contract` is not in `{h_Normal, h_Frozen, h_SwapReady}` — see §4.2).

**SPEC AMENDMENT REQUEST (clarifying):** add to §7.2 or §7.4:

> "During output verification (§7.2 step 3), the running UTXO's SUFFIX accepts body markers in `{0x01ff, 0xfeff, 0x0fff}` (Contract's `0xc0ff` is rejected because series UTXOs cannot emit Contract outputs). Any other marker FAILs. The Contract template's own output verification, during the issue path (§9.10), accepts only `0x01ff` (Normal) because Contract issues only Normal outputs."

### 5.8 Contract's hash relationship to the whitelist

**Concern.** Contract embeds `WHITELIST` but `h_Contract` is not in it. Could this asymmetry open an attack — for example, a "Contract-looking" output produced by a series member?

**Analysis.** For a series member (Normal, Frozen, SwapReady) to emit a Contract output, step 7 of §7.2 would need `h_Contract ∈ {h_Normal, h_Frozen, h_SwapReady}`. By SHA256 collision resistance, this is false (Contract's body differs materially). So series members cannot emit Contract outputs — correct by design (§3.1).

Conversely, Contract emitting only Normal outputs is enforced in Contract's own SUFFIX (§9.10, "All N outputs are Normal (body_marker 0x01ff)").

**Dismiss.** Asymmetry is correct and does not open an attack.

### 5.9 Tail-swap attack on a legitimately-hashed body

**Concern.** Attacker uses a legitimate body (e.g., `PREFIX_Normal ‖ WHITELIST ‖ SUFFIX_Normal`) but swaps the tail — different `tokenId`, different `issuerPkh`, different authority. Does the commitment scheme catch this?

**Analysis.** The commitment scheme (§7.2) does not check tail fields — that is §7.3's job. Per §7.3, the running UTXO's SUFFIX checks:

- `output.tail.seriesId == this.tail.seriesId`
- `output.tail.tokenId == this.tail.tokenId` (for same-token paths)
- `output.tail.redemptionPkh == this.tail.redemptionPkh`
- `output.tail.authority == this.tail.authority`
- `output.tail.optionalData == this.tail.optionalData` (for token-leg continuity)

Any mismatch FAILs.

**Dismiss.** Tail-swap is out-of-scope for the whitelist commitment scheme but caught by §7.3. The whitelist scheme only promises: "if accepted, the output is one of the three templates in _this_ series's WHITELIST". Tail consistency is a separate orthogonal check.

### 5.10 seriesId recomputation mismatch

**Concern.** What if the `seriesId` in the UTXO's tail doesn't actually equal `SHA256(WHITELIST)`? Could a deployer ship templates with an arbitrary `seriesId` value?

**Analysis.** The tail's `seriesId` is set by the creator of each UTXO (via pushes in their unlocking script, replayed into output reconstruction). §7.3 requires `output.seriesId == this.seriesId`, preserving it across transitions. But if the **original** Contract UTXO (or the initial Normal UTXOs issued from Contract) was deployed with an incorrect `seriesId` (not equal to `SHA256(WHITELIST_embedded_in_its_body)`), nothing in-script catches it at issuance.

**This is a deployment-time correctness concern, not a runtime attack.** The off-chain SDK (that constructs the Contract UTXO and issues the first Normal batch) must compute `seriesId = SHA256(WHITELIST)` from the actual embedded `WHITELIST` and push it in the tail. If the SDK bugs or the deployer lies, the resulting series has a cosmetically-wrong `seriesId` — but this does not break the commitment scheme's forward-state guarantee within the series. It would just mean the `seriesId` advertised to off-chain validators is inconsistent with the whitelist they would recompute from the template.

**SPEC AMENDMENT REQUEST (possibly optional):** consider adding to §7.2 an on-chain sanity check for the Contract and issue paths:

> "During issue (§9.10), Contract's SUFFIX additionally checks `this.tail.seriesId == SHA256(this.body.WHITELIST)`. This ensures the deployer cannot ship a Contract with a mis-stated `seriesId` and propagate it to all issued Normal UTXOs."

Cost: one extra SHA256 + OP_EQUALVERIFY in Contract (~40 bytes). Benefit: closes a deployer-honesty gap at the cost of slight template growth. **Not a hard requirement** for scheme soundness — the scheme is sound for internal consistency either way — but it would prevent a class of trivially-mis-deployed series.

### 5.11 Unknown: is there any other commitment-breaking surface?

After rigorous enumeration above, no further attack surface was identified that is unique to the commitment scheme. All identified concerns either (a) reduce to standard SHA256 cryptographic assumptions, (b) reduce to byte-exact comparison correctness in BSV script (`OP_EQUALVERIFY`), or (c) are correctness-of-implementation concerns handled outside the commitment layer (tail checks §7.3, body-marker dispatch §13.2).

**No unmitigated NEW ATTACK SURFACE DISCOVERED.** All items in §5 are either dismissed with argument or flagged as spec-clarification requests (§5.4, §5.5, §5.7, §5.10 — none of which are soundness-breaking).

---

## 6. Relationship to closed forward state

Per `BNTP_CRITICAL_REVIEW.md` §2.2, the "closed forward state" claim is accurate but **local** in scope.

**What the commitment scheme proves.** Given a legitimate BNTP UTXO of some series `S`, every output of a transaction that spends it which passes §7.2 (series-membership) + §7.3 (tail-consistency) is:

- Byte-shaped as one of the three known templates of `S` (by Claims 1–3).
- In the same series `S` (by Claim 5).
- In the same token (for same-token paths) or same series (for swap-exec cross-token), with authority, redemption, and other tail fields preserved.

In other words: **descendants of a legitimate UTXO stay in a known-shaped, known-seriesed family**. The closed forward state is sound for "once inside, stays inside".

**What the commitment scheme does NOT prove.**

- It does not prove the _starting_ UTXO is legitimate. An attacker can deploy their own series `S_attack` that structurally mimics BNTP (same layout, same commitment scheme, same sizes), with attacker-chosen spend rules in the attacker's own `PREFIX`/`SUFFIX` bytes. That series will have its own internally-consistent `seriesId` and its own forward-state closure. The scheme cannot distinguish "my series" from "attacker's series" at the on-chain level — both look valid to their own UTXOs.
- It does not prove back-to-genesis: that a UTXO descends from a legitimate Contract, through a legitimate issue, through only legitimate transfers. Any legitimate-looking UTXO might be in a counterfeit series, or a legitimate series that the user has never heard of.

**Honest scope.** The whitelist commitment is a **local invariant**: within a series, state is closed forward and cryptographically constrained. It is **not** a global identity mechanism. Off-chain validation (indexers, issuer reputation) remains necessary to trust a series label or a token's origin. This matches `BNTP_CRITICAL_REVIEW.md` §1.1 explicitly:

> "Closed forward state solves provenance" → Не solves, narrows. **Local invariant, not global identity.**

This document's soundness claim is scoped to that local invariant. It is not a flaw of the scheme; it is the specified scope.

---

## 7. Relationship to issuer attestation (Способ C)

The whitelist commitment scheme and issuer attestation (§9.4) are orthogonal protections that compose:

- **Whitelist commitment** closes forward state within a series. Any UTXO descended from a legitimate series UTXO stays in the series. Protects against malice targeting descendant outputs.
- **Issuer attestation** gates entry to `SwapReady` state (the DEX on-ramp) with an issuer signature over `(tokenId ‖ outpoint ‖ timestamp)`. This signature is produced only after the issuer's off-chain back-to-genesis validator approves the UTXO. Protects against "phantom" tokens entering DEX liquidity (because DEX operators can refuse non-attested SwapReady).

**How they compose.** Suppose a DEX accepts only SwapReady UTXOs that are both (a) valid per §7.2 + §7.3 (commitment-sound) and (b) carry a valid issuer attestation (§9.4). Then:

- Commitment ensures the UTXO is in a legitimate forward closure of some series.
- Attestation ensures the UTXO has been individually vouched for by the issuer's off-chain B2G check.

The two together give the DEX confidence that the UTXO is both structurally consistent and provenance-validated, without on-chain B2G.

**Where each fails alone.** Commitment alone: attacker could run their own series that looks identical in shape; DEX would need off-chain identity to tell them apart. Attestation alone: a compromised issuer could sign off on any malformed UTXO; commitment still catches shape mismatches.

**This document only proves the commitment half.** Issuer attestation soundness is assumed per spec §9.4 and is out of scope here.

---

## Gate verdict

**PASS.**

**Rationale.**

- All five required claims are argued to rigorous standard, each reduced to either SHA256 cryptographic assumptions or BSV script byte-equality (`OP_EQUALVERIFY`). No claim requires ad-hoc reasoning or unsupported assumptions beyond those.
- All four spec-enumerated attack surfaces (§13.1 whitelist spoof, §13.2 body marker spoof, plus implicit self-reference and cross-series) are addressed and shown to fail under the scheme.
- §5 enumerates eleven additional attack-surface concerns discovered during analysis. Ten are dismissed with argument; four have associated **SPEC AMENDMENT REQUESTs** for clarifying or strengthening language (none of which are soundness-breaking; all are hardening against implementer error). No **NEW ATTACK SURFACE DISCOVERED** flag is raised — the scheme is sound as specified.
- The scope of what the scheme proves (local forward-state closure) is honestly stated and matches `BNTP_CRITICAL_REVIEW.md` §2.2. The scheme does not claim and does not need to claim back-to-genesis provenance; that is handled orthogonally by issuer attestation (§7) or off-chain indexers.

**Summary of spec amendment requests raised in this document.**

- **§5.4 (editorial):** Clarify in §5.3 that the 96-byte whitelist placeholder (`00 × 96` in pseudo-ASM listings) is never a hash input.
- **§5.5 (clarifying):** Clarify in §7.2 that `h_candidate` is computed over raw PREFIX/SUFFIX byte slices, not over a canonicalised opcode form.
- **§5.7 (clarifying):** Clarify in §7.2 / §7.4 that series-member SUFFIXes accept markers in `{0x01ff, 0xfeff, 0x0fff}` only (Contract's `0xc0ff` is rejected for series-emitted outputs); Contract's own issue-path SUFFIX accepts only `0x01ff`.
- **§5.10 (optional strengthening):** Consider adding to Contract's issue-path SUFFIX an on-chain check `this.tail.seriesId == SHA256(this.body.WHITELIST)` to catch deployer-mis-stated `seriesId`. Cost ~40 bytes in Contract template.

None of these amendments are required for scheme soundness; all are hardening against implementer error or deployer dishonesty at the margin.

**Recommendation:** proceed to Phase 1 (PoC skeleton). Whitelist commitment scheme is cleared for implementation. Carry the four spec amendment requests forward to the operator closeout for inclusion in the next spec revision.
