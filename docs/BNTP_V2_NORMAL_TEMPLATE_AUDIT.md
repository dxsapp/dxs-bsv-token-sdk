# BNTP v2 Normal Template — Pseudo-ASM Audit (Step A.1.0)

**Status:** Phase 1 Step A.1.0 audit pass. Adversarial review of `BNTP_V2_TEMPLATE_NORMAL_ASM.md` (opus agent output) before committing to real BSV Script ASM writing in A.1.1.

**Methodology:** for each claimed sub-block, (a) expand pseudo-ASM abstractions into concrete opcodes, (b) count bytes including push prefixes and stack-management overhead, (c) verify stack arithmetic (each op has needed inputs), (d) flag hidden abstractions, missing spec surfaces, and silent assumptions.

**Reference baselines:** real DSTAS locking template (`src/script/templates/dstas-locking-template.ts`, ~2500b compiled); BSV Script post-Genesis semantics (no practical opcode/stack/size limits).

---

## 1. Verdict

**audit-PIVOT.** Three critical spec-level gaps plus moderate byte-count uncertainty. Not ABORT — architecture sound. But spec must close 3 gaps before A.1.1 real ASM writing; otherwise the real implementation either diverges from spec or inflates body 150-500b above estimate.

| Verdict           | Condition                                                          |
| ----------------- | ------------------------------------------------------------------ |
| **audit-PASS** ✗  | would require no critical findings + byte-estimates confirmed ±50b |
| **audit-PIVOT** ✓ | critical findings exist but fixable within current architecture    |
| **audit-ABORT** ✗ | would require structural design problem                            |

**Projected body size after gap closures:** 2500-2600b (from claimed 2461b), landing in the upper end of G5 ≤ 2500b PASS band or edging into PIVOT. **G5 gate may need a third revision** to ≤ 2600b or a body optimization pass.

---

## 2. Critical findings (spec-level gaps)

### 2.1 [CRITICAL] Cross-template output reconstruction — how does Normal produce Frozen's full body bytes?

**Where:** §4.3 path 3 freeze; analogous issue in Contract path 6 issue (Contract must produce Normal output bytes).

**The claim:** Normal embeds a 32b constant `h_Frozen = SHA256(Frozen_body)` and verifies output's body hashes to it. Spec §9.4 rule 3.

**The problem:** BSV's `hashOutputs` in preimage is `HASH256(serialized_output_0 ‖ serialized_output_1 ‖ …)`. To match this via the covenant, Normal's script must reconstruct each output's **full serialized bytes** — including the full script. But Normal has only a 32b hash of Frozen's body; it cannot produce Frozen's ~600b body bytes from a 32b hash (SHA256 is one-way).

**Options:**

1. **Unlocking pushes Frozen body bytes.** Freeze-path unlocking adds a ~600b push of the Frozen body. Normal verifies `SHA256(pushed_body) == h_Frozen`, then uses `pushed_body` in output reconstruction. **Unlocking +600b, body +3-5b** (hash compare). Spec §9.4 unlocking format currently does NOT mention this push — **gap**.
2. **Normal inlines Frozen body as deployment-time constant.** Normal's body grows by ~600b. Blows body budget. **REJECT.**
3. **Different sighash mechanism.** Use SIGHASH_SINGLE or per-output binding. Breaks covenant's full-output-commitment property. Would require significant rearchitecture. **REJECT.**

**Recommendation:** Option 1. Amend spec §9.4 unlocking to include `[frozen_body_bytes]` push. Analogous amendment for Contract path 6 issue (spec §9.9 unlocking needs `[normal_body_bytes]` push — OR Contract inlines Normal body, but that would blow Contract body to ~3000b). Either way, 32b hash manifest (§5.5) is incomplete — needs companion rule "cross-template body is pushed in unlocking, hash-verified on-chain."

**Impact on A.1.1:** must implement push-body-from-unlocking pattern in path 3 SUFFIX. Spec must be updated FIRST; otherwise real ASM diverges from spec.

### 2.2 [CRITICAL] Output count `M` — how does script know how many outputs?

**Where:** §4.1 path 1 flex-transfer, dispatcher rule "M ∈ [1, 4]".

**The claim:** script verifies `M ∈ [1, 4]` and unrolls output reconstruction × 4 gated on `i < M`.

**The problem:** unlocking layout in spec §9.2 is:

```
[output_tuples... (M × ...)]
[amounts_in_array (N × 16b)]
[all_input_outpoints (N × 36b)]
[selfPosition] [max_input_depth] [null-data?] [funding_outpoint] [preimage] [OP_1] [owner_sig] [owner_pubkey]
```

M is **not explicitly pushed**. Script has no direct way to know how many output tuples are on stack. Options:

1. `OP_DEPTH`-based counting (like DSTAS does). Fragile: requires assuming no other pushes above/below.
2. Fixed-M templates (separate Normal-M1, Normal-M2 etc.). Rejected — destroys unified template goal.
3. **Explicit push of M in unlocking.** Clean. Adds 1-2b to unlocking.

**Recommendation:** Option 3. Amend spec §9.2 unlocking layout:

```
[M (1 byte, 1..4)]                    ← NEW, explicit count
[output_tuples... (M × ...)]
[amounts_in_array (N × 16b)]
...
```

Also applies to amount conservation: `N` (input count) is derivable from `|all_input_outpoints|/36`, so that's fine. Only M needs explicit push.

**Impact on A.1.1:** minimal on body (1-2b to read M). But spec must be amended; currently undefined.

### 2.3 [CRITICAL] Owner-sig verification — does covenant CHECKSIG double as owner-auth?

**Where:** §3.6 "single-sig CHECKSIG is NOT redone here — covenant §3.2 already verified sig against preimage; the sig owner signed is the same one whose pubkey matches HASH160(owner). This is standard pattern."

**The problem:** the OP_PUSH_TX covenant verifies `CHECKSIG(constructed_sig, generator_point_pubkey, preimage)`. The sig is **algorithmically constructed from the preimage hash** — anyone with the preimage can build it. It is **not** the owner's signature.

Owner authorization requires a **separate** sig from owner's private key, verified against owner's pubkey with HASH160-match to `owner_field`.

The pseudo-ASM's claim that covenant's CHECKSIG doubles as owner-auth is **incorrect** unless there's a subtle reuse pattern I'm missing in DSTAS. Looking at DSTAS template (`src/script/templates/dstas-locking-template.ts`): there's one visible `OP_CHECKSIGVERIFY` in the covenant block, and a subsequent `OP_CHECKMULTISIGVERIFY` **only in the MPKH branch** (gated by `OP_SIZE OP_NIP OP_IF`). For PKH owner, DSTAS appears to rely on the covenant CHECKSIG.

**Hypothesis (requires verification):** DSTAS may be using the owner's sig AS the covenant sig — i.e., the owner signs the preimage, and that signature happens to satisfy both (a) owner authorization and (b) covenant preimage-binding. This works if and only if the covenant block accepts the owner's sig-over-preimage in place of the constructed-sig-over-preimage. Given that CHECKSIG(sig, pubkey, preimage) is valid for _any_ correctly constructed sig/pubkey pair, this could work if the unlocking provides owner's (sig, pubkey) and the covenant block uses them instead of generator-point pubkeys.

**But:** the standard covenant trick uses generator-point pubkeys specifically because the _sig_ is algorithmically constructable. If we use owner's pubkey, the sig must come from owner's key — which is fine for owner-auth but means the covenant block needs substantial rework.

**Recommendation:**

- **Verify against DSTAS source:** look at DSTAS conformance vectors to see the actual unlocking format for owner-sig cases and understand the sig-reuse pattern.
- **Document explicitly in §3.6:** write out the precise owner-sig verification chain, covering: which sig is used, which pubkey, how HASH160-match works, whether covenant's CHECKSIG is reused or separate.
- **If separate CHECKSIG needed:** +30-40b to PREFIX §3.6.

**Impact on A.1.1:** without clarity here, I can't write correct real ASM. This must be resolved first.

---

## 3. Moderate findings (byte-count corrections)

### 3.1 §3.5 ScriptCode tail cache — undercount ~15-25b

**Pseudo claim:** 180b for 7-field tail cache + scriptCode parsing.

**Issues found:**

1. **Stack management for SPLIT+TOALTSTACK:** the pseudo sequence `<32> OP_SPLIT OP_TOALTSTACK` is stack-semantically backwards. OP_SPLIT produces `[left_part, right_part]` (right on top); OP_TOALTSTACK moves top. So `right_part` goes to altstack, leaving `left_part` = tokenId on main. BUT we need `right_part` as the remainder to split next. So actually: leave tokenId on main (to use later) OR swap. Either way, stack choreography adds **~7b across 7 fields** (OP_SWAP or OP_TOALTSTACK/FROMALTSTACK round-trips).

2. **OP_RETURN offset computation:** pseudo says "~25b to find OP_RETURN via scriptCode walk". But OP_RETURN offset in scriptCode is a deployment-time constant (PREFIX length + SUFFIX length). Pushing a 2b constant + SPLIT + NIP = **~7b, not 25b**. Potential save: ~18b — but this cascades: if PREFIX length is known, so is body size, so is the cache boundary.

3. **Altstack juggling to access fields from branches:** 7 fields on altstack; accessing them from path branches requires FROMALTSTACK (1b each) + often OP_DUP OP_TOALTSTACK (2b) to keep them. Across all 4 path branches, field access adds **~40-80b of plumbing** not counted in §3.5 but eventually paid for. This is probably already in opus's "~25b plumbing" line but could be under-budgeted.

**Net:** §3.5 net ±10b (some overcount on offset, some undercount on stack ops). Treat as **180b ±20b**.

### 3.2 §3.6 Owner MPKH branch — undercount 40-70b

**Pseudo claim:** 80b total (10b PKH branch + 60-80b MPKH + 15b header + overhead).

**Issue:** MPKH branch requires (for n ≤ 5):

- HASH160(preimage) == owner_field: 3b
- Parse m from preimage[0]: OP_1 OP_SPLIT OP_SWAP OP_BIN2NUM = 4b
- Parse n from preimage[-1]: OP_SIZE OP_1SUB OP_SPLIT OP_NIP OP_BIN2NUM = 5b
- Verify 1 ≤ m ≤ n ≤ 5: OP_DUP 1 5 OP_WITHIN OP_VERIFY + OP_2DUP OP_LESSTHANOREQUAL OP_VERIFY = ~10b
- Extract n pubkeys from preimage (n × 33b slots, unrolled for n ≤ 5 with gating): per slot ~8-12b × 5 = **50-60b**
- Stack arrangement for CHECKMULTISIGVERIFY: [OP_0, sig_1..sig_m, m, pk_1..pk_n, n] — m sigs from unlocking (already on stack above MPKH preimage), pubkeys pulled from preimage, m/n values computed. Arrangement: **10-20b** of PICKs, ROLLs, TOALTSTACK/FROMALTSTACK.
- CHECKMULTISIGVERIFY: 1b.

**Realistic MPKH branch: 85-120b.** Pseudo's 60-80b undercounts. **Net +20 to +50b** on §3.6.

### 3.3 §4.1 path 1 amount conservation — claim 205b may be accurate or overcount

**Pseudo claim:** 205b for unrolled ×4 input sum + unrolled ×4 output sum + compare.

**Per-iteration breakdown (input side):**

- Push offset (i × 16): 1-2b
- Extract slice from amounts_in_array: OP_OVER / OP_DUP + OP_SWAP + OP_SPLIT + OP_SWAP + OP_SPLIT + OP_DROP = ~6b with careful stack management
- OP_BIN2NUM: 1b
- Accumulate: OP_FROMALTSTACK OP_ADD OP_TOALTSTACK = 3b
- `i < N` gate: OP_DUP OP_ROT OP_LESSTHAN (or similar) + OP_IF ... OP_ELSE OP_DROP OP_ENDIF = ~8b
- Per iter: ~19b. × 4 = 76b.

Output side similar but amount is first 16b of tuple with variable-length owner following. Extracting amount from tuple is straightforward (OP_SPLIT with len 16 on tuple start). Per iter ~18b × 4 = 72b.

Compare + verify: 3b.

**Realistic: 150-180b.** Pseudo 205b is **25-55b overcount** — opus's estimate was conservative. Good news: we have slack if the pessimistic ~180b dominates.

### 3.4 §4.1 path 1 output reconstruction — highest uncertainty block

**Pseudo claim:** 420b for 4 outputs × ~105b each.

**Per-output breakdown (my audit):**

- Anti-dust on amount: OP_BIN2NUM OP_0 OP_GREATERTHAN OP_VERIFY = 4b
- Marker check (body_marker == 0x01ff): OP_DUP OP_EQUALVERIFY with 2b literal = 5b
- Depth check (new_depth ≥ max+1, ≤ 65535): OP_BIN2NUM (depth 2b LE → num) + 2 compares + 2 OP_VERIFYs = ~10b
- Candidate script construction:
  - owner_push (variable: direct push for 20b PKH, or OP_PUSHDATA1 for MPKH preimage): parse owner length from tuple + build push prefix + CAT owner + CAT prefix = **20-30b** (branchy)
  - action_data + OP_2DROP (literals `00 6d`): OP_CAT a 2b literal = 4b
  - body_before_tail (from altstack cache, ~2300b of bytes): OP_FROMALTSTACK + OP_OVER (to keep cache) + OP_CAT = 3b
  - OP_RETURN byte (`6a`): OP_CAT a 1b literal = 3b
  - Tail reconstruction (tokenId ‖ issuerPkh ‖ new_amount ‖ authFlags ‖ freezeAuthHash ‖ confiscAuthHash ‖ new_depth ‖ optionalData):
    - 6 fields from altstack + 2 from tuple (new_amount, new_depth)
    - 7 CATs × 2-3b (with FROMALTSTACK) = 14-21b
    - OptionalData needs OP_CAT = 2-3b
    - Subtotal: **20-25b**
  - Subtotal for candidate script: **50-65b**
- Output serialization: satoshis (8b `01 00 00 00 00 00 00 00` for anti-dust + CAT) + varint len (3-5b depending on size, ~5-10b build logic incl. varint branching) + candidate_script CAT = **15-20b**
- Accumulate into hashOutputs buffer (CAT prior outputs accumulator): 1-2b
- `i < M` gate (OP_IF outer for whole block): 5b header + 2b closer = 7b

**Per-output total: 90-110b.** Pseudo's 105b is accurate ✓.

**4-output total: 360-440b.** Pseudo 420b falls in range. ✓

**But:** there's a hidden cost — `body_before_tail` on altstack is ~2300b. Each OP_FROMALTSTACK pops it, each OP_CAT uses it. Across 4 outputs, we CAT it 4 times → 4 × 2300b = 9.2 KB of intermediate byte data. Modern BSV has no stack-size limit, but execution time scales with copied bytes. Miners may price this via fee.

**Fee implication not in byte-count gate, but a real cost for users.** Flag for Phase 1 user-facing cost estimation.

### 3.5 §4.2 path 2 refresh — claim 409b may be slight overcount

My per-block audit lands at ~320-360b for path 2 with spec-correct owner/issuer sig handling. **±50b vs claim.**

### 3.6 §4.3 / §4.4 — claims 275b / 213b approximate within ±30b

Path 3 has the critical finding (§2.1). Path 4 is well-estimated at ~213b. No additional moderate issues.

---

## 4. Minor findings

### 4.1 §3.1 Body marker — 5b correct per convention

Direct-push of 2 bytes would be 4b (`02 01 ff 75`), but convention uses `OP_PUSHDATA1 02 01 ff 75` = 5b for external-parser discoverability. Intentional. ✓

### 4.2 §3.3 Sighash-type check — 12b ✓

Opcodes + literals add up exactly.

### 4.3 §3.4 Preimage parse — claim 180b assumes DSTAS 5.1.A + 5.1.B optimizations applied

Pseudo states "DSTAS audit §5.1.A eliminates ~120b of redundant endian flips; §5.1.B removes ~60b of 4-byte-varint handling. Optimized estimate: 180b."

**These optimizations are not yet applied in the deployed DSTAS template.** If A.1.1 uses DSTAS as donor, it will bring the 300b unoptimized version. Applying optimizations may require additional engineering.

**Risk:** if optimizations prove infeasible, §3.4 = 240-300b, not 180b. **+60 to +120b to body.**

**Recommendation:** A.1.1 should start with unoptimized DSTAS port (honest 300b), measure, then optimize in separate pass if budget pressure.

### 4.4 §4.1 (a) hashPrevouts binding — undercount 5-10b

Pseudo claims 10b. Realistic with stack management (OP_DUP preserves all_input_outpoints for later use; FROMALTSTACK for hashPrevouts): 15-20b.

### 4.5 §4.1 (f) depth check — undercount 2-4b

Pseudo claims 6b. Actual with OP_BIN2NUM conversions: 8-10b.

### 4.6 §4.1 (i) null-data + hashOutputs closure — overcount ~15b

Pseudo claims 30b. Realistic: 12-18b.

---

## 5. Opcode count vs BSV consensus limit

Modern BSV (post-Genesis 2020): essentially no script-size or opcode-count consensus limits.

Pre-Genesis limit was 201 non-push opcodes per script. BNTP v2 body at ~2461b with heavy OP_SPLIT/OP_CAT usage has roughly 1200-1500 non-push opcodes. This would fail pre-Genesis by 6-7×.

**Recommendation:** spec §13 (security) should explicitly state "requires BSV post-Genesis consensus rules". Phase 1 SDK should gate deployments to post-Genesis networks (mainnet post-Feb-2020, all current testnets).

**No ABORT risk from this.** Flag for spec §13 amendment.

---

## 6. Aggregate byte-count revision

| Block                      | Pseudo claim | Audit revision         | Δ                |
| -------------------------- | ------------ | ---------------------- | ---------------- |
| §3.1 Body marker           | 5            | 5                      | 0                |
| §3.2 Covenant              | 350          | 350 (unoptimized: 470) | 0 to +120        |
| §3.3 Sighash check         | 12           | 12                     | 0                |
| §3.4 Preimage parse        | 180          | 180 (unoptimized: 300) | 0 to +120        |
| §3.5 Tail cache            | 180          | 180 ±20                | ±20              |
| §3.6 Owner identity (MPKH) | 80           | 100-150                | +20 to +70       |
| §3.7 Path dispatcher       | 26           | 26                     | 0                |
| **PREFIX subtotal**        | **833**      | **853-1023**           | **+20 to +190**  |
| §4.1 Path 1 flex-transfer  | 731          | 700-750                | -30 to +20       |
| §4.2 Path 2 refresh        | 409          | 320-380                | -90 to -30       |
| §4.3 Path 3 freeze         | 275          | 280-310                | +5 to +35        |
| §4.4 Path 4 confiscate     | 213          | 210-230                | -3 to +17        |
| **SUFFIX subtotal**        | **1628**     | **1510-1670**          | **-120 to +40**  |
| **TOTAL BODY**             | **2461**     | **2363-2693**          | **-100 to +230** |

**Realistic projection (DSTAS optimizations applied, moderate spec amendments in place):** 2500-2550b. **Landing in upper PASS band.**

**Pessimistic projection (DSTAS optimizations not applied, MPKH branch heavy):** 2600-2700b. **PIVOT — G5 gate may need third bump.**

**Optimistic projection (everything goes smoothly):** 2400-2450b. **PASS-with-margin.**

---

## 7. Recommendations — gating conditions for A.1.1

Before A.1.1 real-ASM writing can proceed with confidence, **close these 3 critical gaps:**

1. **Spec amendment for cross-template body push:** §9.4 (freeze) and §9.9 (issue) unlocking formats must specify that the target template's body bytes are pushed by unlocking. Normal/Contract locking verifies SHA256-hash match, then uses pushed bytes in output reconstruction. Unlocking +~600b for freeze; +~N×B for issue (N outputs × Normal body).
2. **Spec amendment for `M` explicit push:** §9.2 flex-transfer unlocking must push M (1 byte) before output_tuples.
3. **§3.6 owner-sig semantics clarification:** explicit documentation of how owner's sig is verified — either (a) covenant CHECKSIG reuses owner's sig (preferred if it works; needs reference to DSTAS pattern), or (b) separate CHECKSIG on owner (adds ~30-40b).

**Additionally, two moderate gaps to resolve before A.1.1:**

4. **§3.4 preimage parse — decide: optimized or unoptimized baseline.** Recommend start with unoptimized 300b, plan optimization pass as separate task if budget pressure in A.2.
5. **§13 security spec:** explicit note that v2 requires BSV post-Genesis consensus.

**Estimated effort to close gaps:** ~1 hour spec editing + ~1 hour validation via DSTAS source reading.

**After gap closure:** A.1.1 can proceed with realistic target 2500-2600b, under revised G5 or accepting upper-PASS-band landing. If gaps 1-2 reveal deeper architectural issues during implementation, return to A.1.0 with findings.

---

## 8. Process notes

- **This audit took ~1.5 hours.** Consistent with budget claim. Found 3 critical issues that would have cost 8-16h of real-ASM rework to discover. **Strong ROI confirmation for the A.1.0 / A.1.1 split.**
- **Hardest finding:** §2.1 cross-template body push — not visible from pseudo-ASM alone; required thinking about what hashOutputs actually needs to match. Pseudo-ASM reasoned at the wrong level of abstraction (opcode count per block) without crossing into tx-serialization semantics.
- **Missed by opus:** M explicit push (§2.2) — a pure spec gap; opus didn't notice unlocking layout didn't specify it. Humans reviewing layouts also routinely miss this class of omission.
- **Second-order self-check:** some byte-count findings (especially §3.5 stack management) may themselves be subject to "audit's blind spots" — the real ASM may reveal that opus's 180b was right and my -10b/+10b was wrong. Audit is probabilistic, not proof.

## 9. Next actions

1. **User decision point:** accept audit-PIVOT and close 3 critical gaps via spec amendments, OR re-run analysis if disagreement.
2. **If accept:** apply spec amendments to `BNTP_V2_SPEC.md` (§9.2, §9.4, §9.9, §3.6, §13 related notes).
3. **After spec amendments:** A.1.1 kick-off — write real PREFIX + flex-transfer ASM in `src/bntp/v2/templates/normal-body.ts`, assemble, measure.
4. **Acceptance threshold for A.1.1:** measured body ≤ 2600b (revised from 2500b, if user agrees to bump); otherwise PIVOT with optimization options.
