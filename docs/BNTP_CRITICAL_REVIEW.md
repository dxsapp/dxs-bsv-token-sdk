# BNTP v1 — Critical Review (Living Document)

Живой документ. Пересматривается в процессе design/impl/audit по мере получения новых данных.

Статус: active design review. Не является финальной оценкой — оценка меняется с каждым principal design change.

Связанные:

- `BNTP_SERIES_V1_SPEC.md` — спек v1, single-variant вариант
- `BNTP_VS_DSTAS_COMPARISON.md` — scenario-based comparison
- `DSTAS_LOCKING_SCRIPT_AUDIT.md` — findings из предшественника

---

## 1. Какую проблему BNTP v1 реально решает

Честный ответ:

**Решает:**

- Размер UTXO для Normal/Frozen/SwapReady состояний (−24% / −71% / −47%)
- Изоляцию spend paths по state (audit surface per-template)
- Explicit seriesId/tokenId commitment (лучше identity management для off-chain)
- Closed forward state (descendants stay in known templates) — **local property**, не global
- Мерж до 4 inputs за tx (DSTAS: только 2) — reduced tx count для heavy consolidation
- DEX-compatibility через issuer attestation gate (Способ C) — off-chain B2G через trusted issuer

**НЕ решает:**

- Full back-to-genesis (provenance доказать он chain нельзя — fundamental BSV script limitation)
- Cross-series swap (разные BNTP deployments не interop on-chain)
- Protocol upgrade path (whitelist immutable → changes break all existing tokens)
- Issuer rug via mis-stated genesisTxId (контракт не знает свой txid)
- Atomic multi-hop swap без off-chain orchestration

---

## 2. Design decisions — критическая оценка

### 2.1 Single-variant Normal (было N-2/N-4/N-8) — 🟢 STRONG

**Принято: 2026-04-17**

Решили оставить один Normal template (merge 2..4 inputs через variable followerCount).

Обоснование:

- Устраняет N-8 opcode budget risk (major unknown)
- −2 templates из whitelist (5 → 3)
- −40% audit cost
- Устраняет "variant lock-in" class of problems
- Prod use case (per user feedback): большей частью merge-4 → N-2/N-8 не оправданы

Trade-off:

- +200b на Normal UTXO vs гипотетический N-2 (low-value tokens переплачивают)
- Нет N-8 для heavy consolidation (но mempool chaining в BSV делает это некритичным)

**Assessment:** right call for v1. Extensions (N-2, N-8) можно добавить в v1.x если реальный prod показывает боль.

### 2.2 Closed forward state через whitelist — 🟡 LIMITED

**Принято: 2026-04-17**

Каждый template содержит 96b whitelist block (3×SHA256 body hashes). Output verification проверяет output's body hash ∈ whitelist.

Обоснование: выходные UTXO гарантированно в одном из 3 известных templates.

Критика:

- **Не proves provenance.** Атакующий может создать свою собственную series с другим seriesId, копируя внутреннюю структуру. Визуально его UTXO выглядят как BNTP.
- **Защищает от bugs, не от Malice.** Гарантирует что если UTXO — **наш**, его потомки — **наши**. Не гарантирует "этот UTXO — наш".
- **"Closed forward state" — это local property.** Global identity требует off-chain trusted source.

**Assessment:** полезно для internal consistency, но overstated как security feature. Не путать с back-to-genesis защитой.

### 2.3 Issuer attestation для DEX (Способ C) — 🟢 PRAGMATIC

**Принято: 2026-04-17**

Prepare-swap path требует дополнительную issuer signature в unlocking + royalty output. Это даёт off-chain B2G validation gate.

Обоснование:

- B2G validation off-chain (где дешёво, можно копать глубоко, integrate with indexer/KYC)
- On-chain лишь `CHECKSIGVERIFY` против issuerPkh в tail
- Natural royalty business model для issuer
- DEX принимает только attested SwapReady → trust-bound к reputation issuer'а

Критика:

- **Central point of failure** — issuer может отказаться attestить, или disappear
- **Mitigation:** issuerPkh может быть MPKH (federation). BUT мы не добавили `isIssuerMpkh` flag в tail — **это gap в спеке**, нужно исправить.
- **Issuer compromise → все tokens становятся trustless** (новые attestations подделываются). Risk равнозначен DSTAS confisc authority compromise.

**Assessment:** правильный pragmatic choice. TODO: добавить `isIssuerMpkh` flag.

### 2.4 Anchor/follower merge pattern — 🟡 NOVEL, UNVERIFIED

**Принято: 2026-04-17**

Merge-M: input[0] = anchor (reconstructs all followers' prev txs), inputs[1..K-1] = followers (reconstruct only anchor). Cost = 2(K-1) reconstructions vs naive K(K-1).

Обоснование: O(K) работы на tx вместо O(K²), позволяет K=4 практично.

Критика:

- **Never deployed on BSV production** — новая конструкция.
- **Position-determination attack surface** — как script точно знает что это anchor (position 0)? Через reconstruction hashPrevouts и сравнение self-outpoint. Это non-trivial; тонкие баги возможны.
- **Follower trust delegation** — follower assumes "anchor will verify conservation". Что если anchor есть, но его script не успел проверить (например, из-за script-level assertion failure перед merge logic)? Если anchor fail's first, tx rejected → safe. Но порядок script execution важен.
- **Requires formal correctness proof** перед production.

**Assessment:** elegant но требует rigorous proof. Pseudo-ASM должен включать formal verification того что follower не может быть spent outside а valid anchor-led merge.

### 2.5 Whitelist commitment self-reference solution — 🟡 NOVEL

**Принято: 2026-04-17**

`h_X = SHA256(PREFIX_X ‖ SUFFIX_X)` — исключает whitelist из input hash'а. Ломает self-reference loop.

Обоснование: whitelist bytes не участвуют в своём хэше → templates может embed whitelist без circular dependency.

Критика:

- **Novel construction** — я не видел этого паттерна в deployed BSV protocols.
- **Correctness не очевидна** без формального рассмотрения:
  - Что если attacker crafts output с PREFIX template A и SUFFIX template B?
  - h_candidate = SHA256(PREFIX_A || SUFFIX_B) — не совпадёт с h_A (нужен SUFFIX_A) или h_B (нужен PREFIX_B)
  - Вроде OK, но нужен formal proof
- **Implementation risk:** split points для PREFIX/SUFFIX должны быть deterministic. Body marker (2b) помогает, но off-by-one в offset parsing = disaster.

**Assessment:** elegant, но нужен rigorous formal write-up перед template pseudo-ASM. Без этого нельзя быть уверенным что scheme sound.

### 2.6 Body marker (2b tag) для variant dispatch — 🟢 ACCEPTABLE

**Принято: 2026-04-17**

Каждый template начинается с 2-байтового тега (e.g., `0x01 0xff` для Normal, `0xfe 0xff` для Frozen, `0x0f 0xff` для SwapReady). Dispatch по этому тегу.

Обоснование: compile-time known, O(1) dispatch.

Критика:

- Небольшой tag space (3 значения из 65k возможных) — безопасно
- Implementation risk: hand-pick value collision при добавлении template'ов → **freeze tag assignments в v1**
- Single-byte typo в pseudo-ASM → dispatch в wrong template → security failure

**Assessment:** ок, но нужен строгий testing. Добавить assertion что body starts with known tag.

### 2.7 Fixed 41b authority tail layout — 🟢 GOOD

Принято: 2026-04-17

Фикс 41b = 1b flags + 20b freeze auth hash + 20b confisc auth hash. Zero-padding когда disabled.

Обоснование:

- Uniform layout → simpler parsing
- MPKH через hash-in-tail (preimage в unlocking) — вместо variable в body

Критика:

- +40b overhead для non-governed tokens (где оба auth disabled)
- Это ~2% от UTXO size — негативно, но overshadowed общим −24% gain

**Assessment:** net positive, trade-off acceptable.

### 2.8 No protocol upgrade path — 🔴 LIMITATION

Принято: 2026-04-17

Whitelist immutable → bug in Normal = полная replacement серии.

Обоснование: простота v1, нет legacy coupling.

Критика:

- Real protocols evolve — soft-fork analog необходим
- V1 deploy = commit forever. Серьёзный bug найденный в 6 месяцев пост-launch = force re-mint всех tokens.

**Assessment:** принятый риск для v1. **TODO** для v2: upgrade mechanism (versioned whitelist with backward-compat path).

---

## 3. Known risks и их текущий status

| #   | Risk                                                 | Severity | Status                                                  |
| --- | ---------------------------------------------------- | -------- | ------------------------------------------------------- |
| R1  | Normal pseudo-ASM > 2200b estimate                   | Medium   | Not yet measured; block for Phase 1                     |
| R2  | Whitelist commitment scheme formal bug               | Medium   | Needs formal write-up; block for Phase 1                |
| R3  | Anchor/follower position-check attack                | Medium   | Needs rigorous pseudo-ASM design                        |
| R4  | Issuer attestation path — wrong issuerPkh            | Medium   | Needs MPKH flag addition to spec                        |
| R5  | Body marker collision при refactor                   | Low      | Freeze tag assignments at v1 spec lock                  |
| R6  | Protocol upgrade impossible w/o full re-mint         | Accepted | v1 limitation; plan for v2 upgrade mechanism            |
| R7  | Back-to-genesis still not solved for non-DEX flows   | Accepted | Off-chain validation mandatory (as DSTAS)               |
| R8  | Issuer compromise → all attestations fake            | Accepted | Same class as DSTAS confisc authority compromise        |
| R9  | Mempool ancestry limit hit при massive consolidation | Low      | 1000 cap в BSV default; consolidation tight но feasible |
| R10 | Cross-contamination DSTAS↔BNTP via shared /bsv       | Medium   | Hard isolation rules, CI enforcement                    |

---

## 4. Open spec gaps (must resolve before Phase 1 ASM)

1. **Issuer MPKH support** — tail layout нужно флаг `isIssuerMpkh` в authorityFlags byte. Currently spec forces single-sig issuer. See R4.
2. **Anchor position-determination algorithm** — spec §9.3 говорит "inputPosition == 0" без конкретного алгоритма. См. Critical review §2.4.
3. **Cross-token swap optionalData semantics** — spec §9.9 двусмыслен о том, какой optionalData у principal outputs в cross-token swap.
4. **SwapReady rate floor** — прорекомендовать SDK-level minimum denominator чтобы избежать "rate so high nobody can partial-execute" traps.
5. **Anti-dust enforcement** — spec open question #5. Decide: enforce `satoshis >= 1` per output (+4 opcodes) или passive.
6. **OptionalData max size** — spec open question #6. Decide cap (e.g., 4KB) vs unlimited.
7. **Issuer attestation TTL semantics** — нужно explicit rule: attestation включает timestamp? expires? renewable?
8. **Royalty amount enforcement** — spec не говорит minimum royalty satoshis. SDK default или on-chain minimum?

---

## 5. Priority actions перед committing to BNTP v1

### 5.1 Phase 0 (pre-impl, ~2 weeks)

- [ ] **Pseudo-ASM Normal template** — confirm body size ≤ 2400b estimate
- [ ] **Formal whitelist commitment write-up** — prove scheme soundness
- [ ] **Anchor/follower position check** — concrete algorithm с formal verification
- [ ] **Address all 8 open spec gaps** (§4 above)

### 5.2 Phase 0 gates

Proceed to Phase 1 only если:

- ✅ Normal pseudo-ASM ≤ 2400b
- ✅ Whitelist scheme formally proven sound
- ✅ Anchor position-determination algorithm reviewed и approved
- ✅ All §4 gaps resolved in spec

Pivot если:

- ❌ Normal > 2600b → reconsider design (remove features? reduce scope?)
- ❌ Whitelist scheme has fundamental flaw → redesign commitment
- ❌ Anchor/follower can't be made secure → simplify to 2-merge only (back to DSTAS parity)

### 5.3 Phase 1+ gates

После pseudo-ASM complete:

- External security review of commitment scheme
- Fuzzing output verification logic
- Conformance vectors covering all paths × all authority configurations

---

## 6. Sizing honesty

Самые "маркетинговые" BNTP numbers и their reality:

| Claim (prior)                            | Reality                                            | Revised framing                                                           |
| ---------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------- |
| "−35% per UTXO"                          | Normal-2 only; N-4 = −24%; N-8 = −19%              | Dropped N-2/N-8; **single variant = −24% stable**                         |
| "Merge 8 inputs за tx"                   | Hypothetical, N-8 feasibility unknown              | Dropped. **Merge 4 = max**                                                |
| "6× faster consolidation"                | Was wrong (compared 1 tx/block которого нет в BSV) | **−3× tx count** (1000 → 334), wall-clock similar due to mempool chaining |
| "Closed forward state solves provenance" | Не solves, narrows                                 | **Local invariant, not global identity**                                  |
| "Full DEX compat"                        | Без issuer attestation требует off-chain           | **DEX-compat через issuer gate (Способ C)**                               |

---

## 7. When to kill BNTP

Не-exhaustive список scenarios где лучше отбросить дизайн:

1. **Normal pseudo-ASM выходит > 2800b** — savings vs DSTAS испаряются (DSTAS = 2900b + tail ≈ 3050b; BNTP 2800+tail ≈ 2950b = −3% только). Не стоит инвестиции.
2. **Whitelist commitment fundamentally broken** — если self-reference solution не sound, весь scheme падает. Redesign или abandon.
3. **Anchor/follower doesn't compose with BSV opcode semantics** — если formal проверка показывает position-check невозможна securely, пусть max merge = 2 (DSTAS parity) → теряем главный functional gain.
4. **External auditor определяет series commitment scheme как unsound** — pivot к простому template without whitelist.
5. **Issuer attestation не economically viable** (royalty model не работает) — DEX-gate теряет смысл, BNTP v1 становится "DSTAS со slightly меньшими UTXO".

В этих случаях: публикуем lessons learned, оставляем DSTAS как research reference, ищем другую архитектурную основу.

---

## 8. Revision history

- **2026-04-17** — initial critical review. Accepted decisions: single-variant Normal, Способ C issuer attestation. Raised open spec gaps (§4). Defined Phase 0 gates (§5).
- **2026-04-18** — **Alternatives research phase complete.** Single sonnet agent evaluated 8 architectural alternatives (`BNTP_ALTERNATIVES_EVALUATION.md`). Synthesis in `BNTP_ALTERNATIVES_RECOMMENDATION.md`. **Option A confirmed as winner (33/35 vs next-best 31/35).** Key finding: cross-input introspection gap in BSV Script structurally blocks 3 out of 7 alternatives (Action UTXO, Two-UTXO split, Intent+Execute). This is a protocol-level constraint, not a design oversight. Cost: ~$0.30 sonnet (vs original $14-16 opus estimate). Phase 0.1 cleared to proceed: (1) resolve S1 AMR #1 issuer attestation redesign, (2) merge remaining 10 SPEC AMRs, (3) pseudo-ASM NormalBase to opcode depth, (4) optional OP_CODESEPARATOR investigation.
- **2026-04-18** — **BNTP v1 research arc closed. v2 pivot initiated.** Full-tx footprint comparison (`BNTP_FULL_TX_FOOTPRINT_COMPARISON.md`) revealed body-size was the wrong metric: v1 NormalBase at 4054b, while smaller than v1's Normal monolith, made transfer txs 34% LARGER than DSTAS because per-UTXO overhead grew too much. DSTAS scored 56/105, Option A scored 59/105 — marginal win driven entirely by K=4 merge. **User pushback** ("самая частый вид транзакции это мерж") reframed the problem: protocol success is **pain resolution** (merges, B2G), not footprint. Swaps declared external protocol layer (not BNTP primitive). v1 artifacts preserved as research record; v2 design started from scratch.
- **2026-04-18** — **BNTP v2 spec drafted** (`BNTP_V2_SPEC.md`). Core changes vs v1: (a) amount in tail as uint128, not satoshis — enables flex-transfer N→M with on-script conservation; (b) issuer attestation only on refresh path (not every tx), with uint16 depth counter for rolling freshness; (c) templates collapsed 4→3 (Normal, Frozen, Contract) — no SwapReady, no NormalSwapOnRamp, no whitelist commitment; (d) MPKH owner support added for compliance; (e) no anchor/follower pattern — merge via amounts_in_array push bound to hashPrevouts. 12 design decisions documented via user consultation (see spec §15).
- **2026-04-18** — **BNTP v2 validation dispatched in parallel** (opus pseudo-ASM + sonnet pain analysis, ~$2.80 total). Results:
  - **Pain-resolution (sonnet):** BNTP v2 = 61/105 vs DSTAS = 26.5/105 (weighted, merge+B2G at 4× weight). Merge pain delta +4 (1→5, fully resolved). B2G pain delta +3 (1→4). Adoption friction regression -1 (3→2, due to issuer liveness dependency). Final recommendation: proceed to Phase 1.
  - **Pseudo-ASM (opus):** Normal body = 2461b vs target ≤2000b (G5 gate) — **PIVOT verdict** (landed low in 2300-2800b PIVOT band, 161b above PASS-with-margin). Major vs v1: −1593b (−39%) — savings from no whitelist, no anchor/follower, no redeem path. Flex-transfer alone: 731b (biggest single path). Amount conservation arithmetic +205b (slightly more than estimated). Recommended: accept PIVOT and revise G5 target to 2500b (SPEC AMENDMENT REQUEST #3), OR cut M≤2 / drop MPKH owner / uint64 to hit PASS.
  - **Net BNTP v2 verdict:** directionally correct (solves the right pains at reasonable cost), 39% smaller than v1 NormalBase, 20% per-UTXO smaller than DSTAS. 5 OPEN QUESTIONs and 3 SPEC AMRs to resolve before Phase 1 kick-off.
- **2026-04-18** — **Post-validation spec cleanup.** User ratified 6 remaining OPEN QUESTIONs + 3 SPEC AMRs from pseudo-ASM agent:
  - `max_input_depth` collective enforcement (free push + per-input upper-bound check; over-reporting = self-harm, acceptable) → §9.2.1
  - Issuer MPKH royalty owner = issuerPkh with owner-MPKH flag set → §9.3 clarification
  - Frozen body cross-template verification: embed 32b `h_Frozen` as constant in Normal → §5.5 body hash manifest
  - Tail locked at 111b (no redemptionPkh); redeem collapsed into flex-transfer to issuer-owned address → §9.6 rewritten
  - Contract has `amount` field in tail (uint128, mirrors Normal layout); single-spend Contract enforces fixed supply → §9.9.1
  - uint128 storage format; runtime ScriptNum cap at ~int63 (9.2 × 10¹⁸); SDK validates → §9.11
  - Body hash manifest pattern (32b per cross-reference) replaces v1's 128b whitelist block → §5.5
  - `max_input_depth` semantics normative in §9.2.1
  - G5 gate target revised from ~2000b to ~2500b (matches pseudo-ASM reality, features intact) → §11.1
  - **Status: BNTP v2 spec cleanup complete. Normal body at 2461b = PASS under revised gate.** Spec ready for Phase 1 planning. All design ambiguities resolved.
- **2026-04-17** — **Phase 0 executed** via wave package `docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/`. Three parallel opus agents (S1 Normal pseudo-ASM, S2 whitelist proof, S3 anchor/follower algorithm). Results:
  - G1 (Normal body ≤ 2400b): **PIVOT** — actual ~4640b, optimized floor ~3600b. Budget was unrealistic.
  - G2 (whitelist soundness): **PASS** — 5/5 claims defended, 11 new surfaces enumerated 0 unmitigated, scheme formally sound (constant-function argument).
  - G3 (anchor/follower security): **PASS** — 7/7 attacks defended, `selfPosition` cryptographically derived from hashPrevouts.
  - **Overall: PIVOT**, not ABORT. Core primitives sound; scope reduction required before Phase 1.
  - 11 SPEC AMENDMENT REQUESTs surfaced (4 clarifications, 7 structural). Must be resolved before Phase 1.
  - Three pivot options (see `evidence/closeout.md`): (A) split Normal → NormalBase + NormalSwapOnRamp, rebaseline to ~3000b [recommended]; (B) drop prepare-swap from v1 protocol (loses DEX story); (C) abort BNTP v1 entirely.
  - **Human decision required on pivot option before Phase 0.1 / Phase 1 kicks off.**
