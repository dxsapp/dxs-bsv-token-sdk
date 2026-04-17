# BNTP Phase 0 — Slices

Per-slice execution briefs. Each slice is a standalone agent task with disjoint file ownership.

## Overview

- **S1:** Normal pseudo-ASM — biggest, owns template body design.
- **S2:** Whitelist commitment soundness proof — critical, load-bearing security claim.
- **S3:** Anchor/follower algorithm — tricky, position-determination has subtle attack surfaces.

All three parallel (no dependencies among them). Each produces one target doc. Agent is `general-purpose` with model `opus`.

## Dependency order

```
W0 (wave package docs) — sequential, local
  ↓
[S1, S2, S3] — parallel, delegated to agents
  ↓
Gates (G1, G2, G3) — sequential, local
  ↓
Closeout (A1 + closeout.md) — local
```

## Validation matrix

| Slice | Validation method                               | Specific check                                                                                                                                      |
| ----- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| S1    | Size budget audit + spend path completeness     | Sum PREFIX+WHITELIST+SUFFIX+marker ≤ 2400b; all 6 Normal spend paths specified (transfer, split, merge-K, prepare-swap, freeze, confiscate, redeem) |
| S2    | Formal soundness review                         | Cover 4 attack surfaces: self-reference, variant confusion, cross-series, whitelist-byte spoof                                                      |
| S3    | Algorithm walk-through against attack scenarios | Input-reorder attack, anchor-spoofing attack, follower-delegation attack each MUST fail under described algorithm                                   |

## Closeout requirements

Each slice doc must end with a `## Gate verdict` section containing:

- PASS/PIVOT/ABORT
- Rationale (1-3 paragraphs)
- If PIVOT: concrete scope reduction proposal
- If ABORT: explicit reason + whether pivot to simpler design is viable

---

## Slice S1 — Normal Template Pseudo-ASM

### Intent

Produce concrete opcode-level pseudo-ASM for the `Normal` template body, broken into PREFIX, WHITELIST, and SUFFIX sections per BNTP_SERIES_V1_SPEC.md §5. Count opcodes carefully and estimate total body bytes.

### Owned paths

- `docs/BNTP_TEMPLATE_NORMAL_ASM.md` (create)

### Forbidden

- Other docs (especially `docs/BNTP_WHITELIST_COMMITMENT_PROOF.md`, `docs/BNTP_ANCHOR_FOLLOWER_ALGORITHM.md`, spec docs)
- TypeScript code (no `src/bntp/**`)
- Editing `BNTP_SERIES_V1_SPEC.md`

### Exact task

1. Read `BNTP_SERIES_V1_SPEC.md` fully, especially §3 template catalog, §5 locking script layout, §7 output verification, §8 authority verification, §9 spend paths (§§9.2-9.6 for Normal), §12 size estimates.
2. Read `DSTAS_LOCKING_SCRIPT_AUDIT.md` for reference on what opcodes/patterns DSTAS uses (for orientation — BNTP Normal will be structurally different).
3. Write a pseudo-ASM breakdown of Normal template PREFIX + WHITELIST + SUFFIX.
4. For each section, provide:
   - Opcode sequence (commented with purpose, e.g., `OP_DUP OP_1 OP_8 OP_WITHIN OP_VERIFY  // path_id ∈ [1, 8]`)
   - Byte count estimate
   - Reference to spec section explaining what this code enforces
5. Cover ALL six Normal spend paths:
   - Path 1: transfer/split
   - Path 2: merge-K (both anchor and follower branches)
   - Path 3: prepare-swap (with issuer attestation — §9.4)
   - Path 4: freeze
   - Path 5: confiscate
   - Path 6: redeem
6. Include body marker dispatcher (0x01ff first two bytes).
7. Include whitelist block placement and purpose.
8. Include output verification logic (§7) — body hash check + whitelist byte-match.
9. Include sighash explicit check (`sighashType == 0x41 OP_EQUALVERIFY` — §15 Q3).
10. Include anti-dust check per output (§15 Q4).
11. End with `## Gate verdict` section per `slices.md` contract.

### What not to do

- Don't implement in TypeScript
- Don't refactor the spec
- Don't design the whitelist commitment scheme in detail — that's S2's job (reference it but don't deep-dive)
- Don't design anchor/follower position-check — that's S3's job (reference it but assume it works)
- Don't provide actual signed opcodes like `OP_RETURN` without byte sequence context
- Don't compute body size based on "feeling" — count each opcode byte (most are 1b, pushdata N is `N+1` where applicable)

### Validation

- Body size estimate ≤ 2400b → G1 PASS
- 2400 < size ≤ 2800b → G1 PIVOT (specify what to drop)
- Size > 2800b → G1 ABORT
- All 6 spend paths visible in doc with opcode sketches
- References spec §§ for each invariant enforced

### Completion signal

Doc exists at target path, all paths specified, `## Gate verdict` with explicit PASS/PIVOT/ABORT, byte count totals per section.

---

## Slice S2 — Whitelist Commitment Soundness Proof

### Intent

Provide a formal-style argument (not mathematical proof with symbols, but rigorous prose + reasoning) that the whitelist commitment scheme as specified in BNTP_SERIES_V1_SPEC.md §5.3, §6.1, §7.2 is sound — i.e., cannot be broken by the attacks enumerated in §13 of the spec plus any you can identify.

### Owned paths

- `docs/BNTP_WHITELIST_COMMITMENT_PROOF.md` (create)

### Forbidden

- Other docs (especially `docs/BNTP_TEMPLATE_NORMAL_ASM.md`, `docs/BNTP_ANCHOR_FOLLOWER_ALGORITHM.md`, spec docs)
- TypeScript code
- Designing the Normal template ASM (S1's job)
- Position-check algorithm (S3's job)

### Exact task

1. Read `BNTP_SERIES_V1_SPEC.md` §§5.3, 6.1, 7.2, 7.3, 13.1, 13.2.
2. Read `BNTP_CRITICAL_REVIEW.md` §2.2, 2.5 (Closed forward state claim, whitelist self-reference solution).
3. Write a rigorous analysis of the commitment scheme:
   - **Claim 1 (self-reference resolution):** `h_X = SHA256(PREFIX_X || SUFFIX_X)` excludes WHITELIST block from its own hash — prove this breaks any self-reference loop and that embedded whitelist values can be deterministically computed at series design time.
   - **Claim 2 (whitelist byte-match safety):** output verification step 5 checks `output.WHITELIST == this.WHITELIST` byte-for-byte. Argue this prevents an attacker from embedding a different whitelist (e.g., pointing at their malicious templates) while still being accepted by this series.
   - **Claim 3 (body hash binding):** step 7 verifies `h_candidate ∈ {h_Normal, h_Frozen, h_SwapReady}`. Combined with step 5, argue that only valid series templates can be output targets.
   - **Claim 4 (variant confusion resistance):** spec §13.2 claims PREFIX_A || SUFFIX_B doesn't match any h_X. Argue this rigorously — consider what happens if attacker crafts PREFIX from one template + WHITELIST from another + SUFFIX from a third.
   - **Claim 5 (cross-series spoofing resistance):** two different series have different seriesId (since whitelist bytes differ). Argue attacker cannot forge tokens that look like they're in Series A while actually being in Series B or unrelated Series C.
4. For each attack surface, provide:
   - Attacker capabilities assumed
   - Attack steps
   - Why it fails under the scheme
5. Explicitly enumerate and dismiss (or confirm as real) the attack surfaces from §13.1 and §13.2:
   - whitelist spoofing
   - body marker spoofing
6. Identify any NEW attack surface not yet in the spec. If found, mark `**NEW ATTACK SURFACE DISCOVERED:**` and describe.
7. Provide a concrete procedure for computing `h_Normal`, `h_Frozen`, `h_SwapReady` at series deployment time — show this is deterministic given the templates.
8. End with `## Gate verdict` section per `slices.md` contract.

### What not to do

- Don't write ASM for any template
- Don't design anchor/follower
- Don't hand-wave with "obviously this is secure" — trace each attack through the scheme
- Don't propose spec changes silently — use `**SPEC AMENDMENT REQUEST:**` markers

### Validation

- 5 claims each rigorously argued
- 4 spec-enumerated attack surfaces addressed
- Self-reference solution demonstrated sound
- If any `**NEW ATTACK SURFACE DISCOVERED:**` present and not mitigated → G2 PIVOT or ABORT

### Completion signal

Doc exists at target path, each claim has explicit argument, gate verdict with PASS/PIVOT/ABORT.

---

## Slice S3 — Anchor/Follower Position-Determination Algorithm

### Intent

Design a concrete, implementable algorithm by which (a) the anchor script verifies its own `inputPosition == 0` and (b) follower scripts verify their own position `∈ [1, K-1]` and that input[0] is a legitimate anchor. Prove the algorithm secure against reordering attacks and anchor-spoofing.

### Owned paths

- `docs/BNTP_ANCHOR_FOLLOWER_ALGORITHM.md` (create)

### Forbidden

- Other docs
- TypeScript code
- Writing Normal template ASM (S1's job)
- Designing commitment scheme (S2's job)

### Exact task

1. Read `BNTP_SERIES_V1_SPEC.md` §9.3 (merge-K path), §11 (unlocking catalog).
2. Read `BNTP_CRITICAL_REVIEW.md` §2.4 (anchor/follower pattern risks).
3. The spec already sketches that unlocking provides `all_input_outpoints 36b×K` and script verifies `HASH256(all_input_outpoints ‖ funding_outpoint) == hashPrevouts`. Take this as the starting point.
4. Provide a concrete algorithm:
   - **Anchor case** (input[0]):
     - Unlocking pushes
     - Script opcode sketch for position verification
     - Script opcode sketch for reconstructing each follower's prev tx and verifying
   - **Follower case** (inputs[1..K-1]):
     - Unlocking pushes
     - Script opcode sketch for position verification
     - Script opcode sketch for reconstructing anchor's prev tx and verifying it's Normal same-token
5. Enumerate ATTACK SCENARIOS and show how each fails:
   - **A1. Input reorder attack:** attacker moves follower to position 0 hoping its script thinks it's anchor.
   - **A2. Anchor-spoofing attack:** attacker fills unlocking `all_input_outpoints` with a forged list that puts their outpoint at position 0.
   - **A3. Follower-delegation escape:** follower delegates conservation to anchor. Can attacker construct tx where follower's check passes but no real anchor does conservation?
   - **A4. Mixed-token merge:** follower inputs[1..K-1] have different tokenId than anchor. Does the check catch this?
   - **A5. K-lie attack:** anchor claims `followerCount=3` but only 1 follower is real.
6. Consider edge cases:
   - K=2 minimum case
   - K=4 maximum case
   - What if a funding input is placed BEFORE the anchor? (spec assumes STAS inputs first, but is this enforced?)
   - Cross-series inputs (different seriesId)
7. End with `## Gate verdict` section per `slices.md` contract.

### What not to do

- Don't write Normal template ASM
- Don't design whitelist scheme
- Don't propose protocol changes silently — use `**SPEC AMENDMENT REQUEST:**`
- Don't hand-wave "the hash catches it" — show exactly which check catches each attack

### Validation

- Algorithm specified concretely (opcode sketches for both anchor and follower)
- All 5 attack scenarios (A1-A5) traced, each shown to fail
- All edge cases addressed
- If any attack succeeds or requires spec amendment → G3 PIVOT or ABORT

### Completion signal

Doc exists at target path, algorithm is implementable from the description, all attacks fail, gate verdict with PASS/PIVOT/ABORT.
