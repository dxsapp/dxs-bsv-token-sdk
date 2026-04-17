# BNTP v1 vs DSTAS 1.0.4 — Comparison

Практическое сравнение по сценариям, размерам, сложности, безопасности. Статус — research, BNTP ещё не имплементирован.

Все размеры — estimates. Точные значения появятся после pseudo-ASM pass. Сравнение производится на идентичных параметрах (owner 20b PKH, both authorities enabled как 20b PKH, optionalData пусто).

---

## 1. Высокоуровневое сравнение

| Параметр                           | DSTAS 1.0.4                     | BNTP v1                                                        | Δ                                       |
| ---------------------------------- | ------------------------------- | -------------------------------------------------------------- | --------------------------------------- |
| Templates в серии                  | 1 (монолит)                     | 3 (+ Contract)                                                 | +2 файла, проще per-template аудит      |
| Body size (Normal UTXO)            | 2900b                           | ~2000b                                                         | **−31%**                                |
| UTXO on-chain, Normal              | ~3050b                          | ~2200b                                                         | **−28%**                                |
| UTXO on-chain, Frozen              | ~3050b                          | ~900b                                                          | **−70%**                                |
| UTXO on-chain, SwapReady           | ~3072b                          | ~1660b                                                         | **−46%**                                |
| Merge ширина                       | 2                               | 2..4 (variable K per tx)                                       | **+2×**                                 |
| Swap action_data                   | recursive (`.next` chain)       | single-level only                                              | упрощение                               |
| Authority layout                   | flags + variable service fields | fixed 41b tail slot                                            | simplification                          |
| seriesId                           | нет                             | 32b commitment к whitelist                                     | new                                     |
| Closed forward state               | нет                             | да (whitelist check)                                           | new                                     |
| tokenId                            | неявно через redemptionPkh      | явный 32b в tail                                               | new                                     |
| issuerPkh в tail                   | нет                             | 20b + MPKH flag                                                | new (enables robust redeem/attestation) |
| Back-to-genesis on-chain           | не решён                        | closed forward state (local) + issuer attestation gate для DEX | significantly better DEX story          |
| Issuer attestation на prepare-swap | нет                             | обязательна (Способ C)                                         | new                                     |
| DEX-compat                         | требует off-chain trust         | built-in via issuer gate                                       | new                                     |
| Sighash enforcement                | имплицитно                      | эксплицитно (+5b)                                              | better                                  |
| Dispatch механизм                  | spending_type 1..4              | path_id 1..8 per template                                      | cleaner                                 |

---

## 2. Per-scenario breakdown

Обозначения:

- **UTXO_in** — размер спенженого (уже на chain, не платим за это в этой tx, но видим в вводе)
- **UTXO_out** — размер создаваемого UTXO (платим за storage)
- **Unlock** — размер unlocking script для STAS input
- **Tx total** — приблизительный размер всей tx (1 STAS in + 1 funding in + outputs + overhead)

Funding input считается как ~147b (40b outpoint + 107b unlocking). Funding output (change) ~34b. Overhead tx (version+locktime+counts) ~10b.

### 2.1 Mint + Issue

**DSTAS:** 2-tx flow. Contract tx → Issue tx.

- Contract UTXO: ~600b
- Issue tx: spend Contract + funding, produce N STAS outputs (~3050b каждый)
- Для 4-way issue: Issue tx ≈ 4×3050 + 600_in + 147_fund + 34_change + overhead = ~12.6 KB

**BNTP:** 2-tx flow, идентичная структура.

- Contract UTXO: ~800b (includes 96b whitelist + 145b tail)
- Issue tx: 4×2200 (Normal) + 800_in + 147_fund + 34_change + overhead = ~9.8 KB

| Метрика              | DSTAS    | BNTP    | Δ        |
| -------------------- | -------- | ------- | -------- |
| Issue tx, 4 outputs  | ~12.6 KB | ~9.8 KB | **−22%** |
| Issue tx, 10 outputs | ~31 KB   | ~23 KB  | **−26%** |

### 2.2 Simple transfer (1 in → 1 out + change)

**DSTAS:**

- UTXO_in: 3050b (на chain, не платим)
- UTXO_out: 3050b
- Unlock: ~230b (preimage 180b + sig+pk 107b + output tuples + funding outpoint)
- Tx total: 40 + 230 + 4 (STAS input) + 147 (funding) + 3050 + 8 + 3 (STAS out) + 34 (change) + 10 (overhead) = **~3526b**

**BNTP Normal:**

- UTXO_out: ~2200b
- Unlock: ~230b (identical structure)
- Tx total: 40 + 230 + 4 + 147 + 2200 + 11 + 34 + 10 = **~2676b**

| Метрика       | DSTAS     | BNTP      | Δ         |
| ------------- | --------- | --------- | --------- |
| Transfer tx   | ~3526b    | ~2676b    | **−24%**  |
| Fee @ 1 sat/b | 3526 sats | 2676 sats | −850 sats |

### 2.3 Split (1 in → 4 out + change)

**DSTAS:**

- Unlock: ~330b (4 output tuples вместо 1)
- Tx total: 40 + 330 + 4 + 147 + 4×3061 + 34 + 10 = **~12.8 KB**

**BNTP Normal:**

- Unlock: ~330b
- Tx total: 40 + 330 + 4 + 147 + 4×2211 + 34 + 10 = **~9.4 KB**

| Метрика   | DSTAS    | BNTP    | Δ        |
| --------- | -------- | ------- | -------- |
| Split 1→4 | ~12.8 KB | ~9.4 KB | **−27%** |

### 2.4 Merge 2-in

**DSTAS:**

- Unlock per STAS input: ~230 + reconstruction_pieces (~3000b prev tx) = ~3230b
- Merge 2→1: 2 × (40 + 3230 + 4) + 147 + 3061 + 34 + 10 = **~9.8 KB**

**BNTP Normal (K=2):**

- Anchor unlock: ~340 + 2500b prev tx = ~2840b
- Follower unlock: ~270 + 2500b = ~2770b
- Merge 2→1: (40+2840+4) + (40+2770+4) + 147 + 2211 + 34 + 10 = **~8.1 KB**

| Метрика     | DSTAS   | BNTP    | Δ        |
| ----------- | ------- | ------- | -------- |
| Merge 2 → 1 | ~9.8 KB | ~8.1 KB | **−17%** |

### 2.5 Merge 4-in (BNTP only)

**DSTAS:** невозможно в одной tx. Требуется 3 последовательных 2-merge ≈ 3 × 9.8 KB = ~29.4 KB total.

**BNTP Normal (K=4):**

- Anchor unlock: ~380 + 3 × 2500b = ~7880b
- Follower unlock: ~270 + 2500b = ~2770b
- Merge 4→1 tx: (40+7880+4) + 3×(40+2770+4) + 147 + 2211 + 34 + 10 = **~18.9 KB**

| Метрика                          | DSTAS           | BNTP            | Δ               |
| -------------------------------- | --------------- | --------------- | --------------- |
| Merge 4→1 (1 tx)                 | невозможно      | ~18.9 KB        | —               |
| Consolidate 4 UTXO (total bytes) | ~29.4 KB (3 tx) | ~18.9 KB (1 tx) | **−36%, −2 tx** |

### 2.6 Large-portfolio consolidation

Для honest comparison считаем "N merges" = consolidation из (N+1) UTXO в 1 UTXO. В DSTAS 2-merge, 1 merge tx = 1 reduction (−1 UTXO). В BNTP Normal с K=4, каждый merge-4 tx = −3 reductions. При "rough" подсчёте tail (последние 1-3 UTXO через 2-merge) учтён с overhead ~10%.

**Важное замечание про BSV wall-clock:** в BSV нет необходимости ждать block confirmation между зависимыми tx — mempool поддерживает chain tx. Consolidation 100+ tx fits в один блок или в пределах нескольких минут propagation. Wall-clock estimates ниже — это реалистичные значения для BSV mempool chaining (ограничение: default 1000-cap unconfirmed chain depth).

#### Consolidate 10 UTXO → 1 (9 merges в DSTAS)

| Подход            | Tx count        | Total bytes | Fee @ 1 sat/b | Wall-clock |
| ----------------- | --------------- | ----------- | ------------- | ---------- |
| DSTAS 2-merge     | 9 tx × ~9.8 KB  | ~88 KB      | ~88 K sats    | ~5-10 мин  |
| BNTP Normal (K=2) | 9 tx × ~8.1 KB  | ~73 KB      | ~73 K sats    | ~5-10 мин  |
| BNTP Normal (K=4) | 3 tx × ~18.9 KB | ~57 KB      | ~57 K sats    | ~5 мин     |

#### Consolidate 101 UTXO → 1 (**100 merges** в DSTAS — real production scale)

| Подход                 | Tx count          | Total bytes | Fee @ 1 sat/b | Wall-clock |
| ---------------------- | ----------------- | ----------- | ------------- | ---------- |
| DSTAS 2-merge          | 100 tx × ~9.8 KB  | ~980 KB     | ~980 K sats   | ~10-20 мин |
| BNTP Normal (K=2 only) | 100 tx × ~8.1 KB  | ~810 KB     | ~810 K sats   | ~10-20 мин |
| BNTP Normal (K=4)      | ~34 tx × ~18.9 KB | ~642 KB     | ~642 K sats   | ~5-10 мин  |

**Выгода BNTP K=4 vs DSTAS:** −338 KB bytes, −66 tx.

#### Consolidate 1001 UTXO → 1 (**1000 merges** в DSTAS — "heavy trader" scale)

| Подход                 | Tx count           | Total bytes | Fee @ 1 sat/b            | Wall-clock                                  |
| ---------------------- | ------------------ | ----------- | ------------------------ | ------------------------------------------- |
| DSTAS 2-merge          | 1000 tx × ~9.8 KB  | ~9.8 MB     | ~9.8 M sats (~0.098 BSV) | ~30 мин – несколько блоков (ancestor limit) |
| BNTP Normal (K=2 only) | 1000 tx × ~8.1 KB  | ~8.1 MB     | ~8.1 M sats              | ~30 мин                                     |
| BNTP Normal (K=4)      | ~334 tx × ~18.9 KB | ~6.31 MB    | ~6.31 M sats             | ~10-20 мин                                  |

**Выгода BNTP K=4 vs DSTAS:**

- −3.49 MB суммарных байт (**−36%**)
- −666 tx (**3× меньше транзакций**) — важно для mempool ancestor limit (default 1000)
- Fee savings: ~0.035 BSV на один heavy-consolidation run
- Wall-clock: comparable в BSV из-за mempool chaining, но **−666 tx** даёт существенный запас до ancestor cap

#### Per-UTXO efficiency (bytes per UTXO reduction)

Более универсальная метрика — сколько байт тратится на каждое "удаление" UTXO из set'а:

| Approach          | Bytes per UTXO reduction |
| ----------------- | ------------------------ |
| DSTAS 2-merge     | ~9.8 KB                  |
| BNTP Normal (K=2) | ~8.1 KB                  |
| BNTP Normal (K=4) | ~6.3 KB (18.9/3)         |

BNTP K=4 даёт **~36% снижение суммарной нагрузки на blockchain** при массовой консолидации vs DSTAS.

**Комментарий:** для активного оператора с прода 100-1000 merges за раз — BNTP K=4 даёт:

- Меньше on-chain footprint (~36% снижение)
- Меньше tx count (~3× меньше)
- Меньше pressure на mempool ancestor chain limit
- Сопоставимое wall-clock (BSV не требует block confirmations между chained tx)

Wall-clock savings по сравнению с предыдущими оценками пересмотрены — в BSV mempool поддерживает chains of dependent tx, поэтому разница между 1000 и 334 tx не "дни vs часы", а "больше vs меньше давление на ancestor limit".

### 2.7 Freeze

**DSTAS:**

- UTXO_in: 3050b, UTXO_out: 3050b (та же серия, action_data меняется)
- Unlock (auth sig): ~260b (+action data output)
- Tx total: ~3570b

**BNTP:**

- UTXO_in: 2200b (Normal), UTXO_out: 900b (**Frozen — существенно меньше**)
- Unlock: ~260b
- Tx total: 40 + 260 + 4 + 147 + 911 + 34 + 10 = **~1406b**

| Метрика              | DSTAS  | BNTP   | Δ        |
| -------------------- | ------ | ------ | -------- |
| Freeze tx            | ~3570b | ~1406b | **−61%** |
| Frozen UTXO на chain | ~3050b | ~900b  | **−70%** |

**Frozen UTXO economics:** для токенов, которые часто замораживаются (compliance scenarios), BNTP радикально экономит on-chain storage. Замороженный UTXO — в 3.4× меньше.

### 2.8 Unfreeze

Симметрично freeze, но Frozen → Normal.

**DSTAS:** ~3570b (same как freeze, структурно идентично).

**BNTP:** input Frozen (~900b), output Normal (~2200b). Tx total: 40 + 260 + 4 + 147 + 2211 + 34 + 10 = **~2706b**.

| Метрика     | DSTAS  | BNTP   | Δ        |
| ----------- | ------ | ------ | -------- |
| Unfreeze tx | ~3570b | ~2706b | **−24%** |

### 2.9 Confiscation (from Normal)

**DSTAS:** ~3570b (аналог freeze).

**BNTP:** input Normal (~2200b), output Normal (~2200b). Tx total: **~2706b**.

| Метрика      | DSTAS  | BNTP   | Δ        |
| ------------ | ------ | ------ | -------- |
| Confiscation | ~3570b | ~2451b | **−31%** |

### 2.10 Prepare-swap (Normal → SwapReady) — **with issuer attestation**

**DSTAS:** спецфлоу, меняет action_data в том же монолитном скрипте. Output UTXO той же серии, но с swap descriptor. No issuer gating.

- Tx total ≈ ~3600b (action_data push ~63b больше)

**BNTP:** Normal → SwapReady через issuer attestation (Способ C).

- Input: 2200b, Output: 1660b (SwapReady меньше)
- Unlocking: +~200b на issuer attestation sig + pubkey + timestamp
- Royalty output (P2PKH to issuer): +34b + 1000 sats default
- Tx total: 40 + 430 (unlock incl. attestation) + 4 + 147 + 1672 + 34 (change) + 34 (royalty) + 10 = **~2371b**

| Метрика                                  | DSTAS  | BNTP                | Δ               |
| ---------------------------------------- | ------ | ------------------- | --------------- |
| Prepare-swap tx                          | ~3600b | ~2371b              | **−34%**        |
| + DEX B2G gate                           | no     | **yes, via issuer** | qualitative win |
| + Royalty (sustainable issuer biz model) | no     | yes                 | new             |

### 2.11 Swap execute (2 SwapReady → 2 Normals + 2 optional remainders)

**DSTAS:**

- 2 STAS inputs, each ~3072b, unlocking with reconstruction ~3300b
- 2-4 STAS outputs
- Tx total, 2 principals + 2 remainders: 2×(40+3300+4) + 147 + 4×3072 + 34 + 10 = **~19.1 KB**

**BNTP:**

- 2 SwapReady inputs, unlocking with cross-leg reconstruction ~2730b
- Tx total, 2 principals (Normal) + 2 remainders (SwapReady): 2×(40+2730+4) + 147 + 2×2211 + 2×1672 + 34 + 10 = **~13.5 KB**

| Метрика             | DSTAS    | BNTP     | Δ        |
| ------------------- | -------- | -------- | -------- |
| Swap execute, 4 out | ~19.1 KB | ~13.5 KB | **−29%** |

### 2.12 Swap cancel

**DSTAS:** spending_type = 4, output Normal. Tx total ≈ ~3570b.

**BNTP:** SwapReady → Normal. input 1660b, output 2200b. Tx total: 40 + 260 + 4 + 147 + 2211 + 34 + 10 = **~2706b**.

| Метрика     | DSTAS  | BNTP   | Δ        |
| ----------- | ------ | ------ | -------- |
| Swap cancel | ~3570b | ~2706b | **−24%** |

### 2.13 Redeem (full burn)

**DSTAS:** 1 STAS → P2PKH.

- Tx total: 40+230+4 + 147 + 34 + 34 + 10 = **~499b** (small — no STAS output)

**BNTP Normal:** identical semantics.

- Tx total: 40+260+4 + 147 + 34 + 34 + 10 = **~529b**

Слегка больше в BNTP (+30b) из-за проверки `issuerPkh` (теперь эксплицитно). Незначимо.

| Метрика   | DSTAS | BNTP  | Δ   |
| --------- | ----- | ----- | --- |
| Redeem tx | ~499b | ~529b | +6% |

### 2.14 Partial redeem (1 STAS → P2PKH + 3 remainder STAS)

**DSTAS:**

- Tx total: 40+380+4 + 147 + 34 + 3×3061 + 34 + 10 = **~9.8 KB**

**BNTP Normal:**

- Tx total: 40+380+4 + 147 + 34 + 3×2211 + 34 + 10 = **~7.3 KB**

| Метрика                       | DSTAS   | BNTP    | Δ        |
| ----------------------------- | ------- | ------- | -------- |
| Partial redeem + 3 remainders | ~9.8 KB | ~7.3 KB | **−25%** |

---

## 3. Aggregate cost analysis

### 3.1 Fees per operation (@ 1 sat/byte, worst realistic BSV)

| Операция                               | DSTAS fee        | BNTP fee                | Savings          |
| -------------------------------------- | ---------------- | ----------------------- | ---------------- |
| Transfer                               | 3526 sat         | 2676 sat                | 850 sat          |
| Split 1→4                              | 12800 sat        | 9400 sat                | 3400 sat         |
| Merge 2→1                              | 9800 sat         | 8100 sat                | 1700 sat         |
| Merge 4→1 (N/A in DSTAS)               | 29400 sat (3 tx) | 18900 sat (1 tx)        | 10500 sat + 2 tx |
| Freeze                                 | 3570 sat         | 1406 sat                | 2164 sat         |
| Unfreeze                               | 3570 sat         | 2706 sat                | 864 sat          |
| Confiscation                           | 3570 sat         | 2706 sat                | 864 sat          |
| Prepare-swap (+ attestation + royalty) | 3600 sat         | 2371 sat + 1000 royalty | 229 sat (net)    |
| Swap execute                           | 19100 sat        | 13500 sat               | 5600 sat         |
| Swap cancel                            | 3570 sat         | 2706 sat                | 864 sat          |
| Redeem (full)                          | 499 sat          | 529 sat                 | −30 sat          |

**Typical active token portfolio (1 year, 1000 transfers + 100 merge-4's + 10 swaps):**

- DSTAS: 1000×3526 + 100×29400 (forced 2-merge chains) + 10×19100 ≈ **6.66 M sats** (~0.067 BSV)
- BNTP: 1000×2676 + 100×18900 + 10×(13500 + 2×2371 + 2×1000 royalty) ≈ **4.75 M sats** (~0.048 BSV)

Saving: **~1.9 M sats (~29%)** over typical usage, **плюс 10K sats в royalties to issuer** (sustainable business model).

### 3.2 UTXO set storage cost (global perspective)

Допустим 1M активных BNTP токен-UTXO в экосистеме:

- DSTAS: 1M × 3050b = **3.05 GB** в UTXO set
- BNTP среднее (95% Normal, 3% SwapReady, 2% Frozen):
  - 950K × 2200 + 30K × 1660 + 20K × 900
  - = 2.09 GB + 0.05 GB + 0.018 GB ≈ **2.16 GB**

UTXO set saving: **~0.89 GB (~29%)**.

---

## 4. Security & audit

| Dimension                                          | DSTAS 1.0.4                     | BNTP v1                                                   |
| -------------------------------------------------- | ------------------------------- | --------------------------------------------------------- |
| Back-to-genesis on-chain (non-DEX flows)           | ❌ не решён                     | ❌ не решён (closed forward state только)                 |
| Back-to-genesis для DEX                            | ❌ off-chain only               | ✅ **issuer attestation gate on prepare-swap** (Способ C) |
| Closed series (выходы принадлежат whitelisted set) | ❌                              | ✅ (whitelist hash check)                                 |
| seriesId commitment                                | ❌                              | ✅ (32b)                                                  |
| tokenId commitment                                 | implicit (redemptionPkh)        | ✅ explicit (32b)                                         |
| issuerPkh in tail (supports MPKH)                  | ❌                              | ✅ (20b + flag)                                           |
| Sighash enforcement                                | implicit (structural)           | **explicit check** +5b                                    |
| Authority layout                                   | flags + variable service fields | fixed 41b, byte-exact                                     |
| Action data states                                 | ambiguous (multi-level swap)    | **3 discriminated states**                                |
| Attack surface: fake token same params (non-DEX)   | possible                        | possible (same as DSTAS)                                  |
| Attack surface: fake token accepted by DEX         | possible                        | **blocked by issuer attestation**                         |
| Attack surface: fake series (across deployments)   | possible (tokenId collision)    | **blocked** (seriesId ≠)                                  |
| Attack surface: whitelist spoofing                 | N/A                             | blocked (hash + byte-match)                               |
| Attack surface: issuer compromise                  | equivalent (confisc auth)       | equivalent (issuer key), mitigated by MPKH                |

**Net security improvement:** BNTP strictly больше (closed state + seriesId + explicit sighash + DEX gate). Back-to-genesis для non-DEX flows остаётся той же ограниченной off-chain моделью, что и DSTAS — но для DEX добавлен on-chain gate через issuer attestation.

### 4.1 Audit complexity

| Metric                         | DSTAS                             | BNTP                                                          | Δ                             |
| ------------------------------ | --------------------------------- | ------------------------------------------------------------- | ----------------------------- |
| Template files                 | 1 (2900b body)                    | 3 (avg ~1370b body)                                           | +2 files                      |
| LoC audit surface per template | ~2900 opcodes                     | ~600-2000 per template                                        | **simpler each**              |
| Cross-template dependencies    | N/A                               | whitelist + seriesId + issuer attestation                     | new dependencies              |
| Spending paths per template    | 4 (via spending_type dispatch)    | 1-6 (via path_id, template-scoped)                            | cleaner scope                 |
| Branch complexity              | high (everything in one dispatch) | low (frozen has 2 paths, etc.)                                | ✅                            |
| Unit-testability               | coarse (one template)             | fine (per template)                                           | ✅                            |
| Novel primitives to audit      | 0                                 | 3 (whitelist commitment, anchor/follower, issuer attestation) | adds formal verification work |

Audit time estimate для полного security review:

- DSTAS 1.0.4: ~2 недели эксперт-часов на один монолит
- BNTP v1: ~**5-7 недель** (3 templates × 1-2 недели + novel primitives formal review)

Trade-off: суммарно аудита больше, но риск "скрытого bug в сложном branch" drастично снижается. Single-variant design сократил audit time на ~40% vs первоначальный BNTP дизайн с N-2/N-4/N-8.

---

## 5. Feature delta

### 5.1 BNTP gains

- ✅ **Merge до 4 inputs** в одной tx (DSTAS: только 2)
- ✅ **Explicit seriesId/tokenId/issuerPkh** в tail
- ✅ **Closed forward state** (outputs гарантированно в whitelist 3 templates)
- ✅ **Issuer attestation gate для DEX** — off-chain B2G через trusted gatekeeper с royalty model
- ✅ **Fixed tail layout** — проще для indexers и wallets parsing
- ✅ **Frozen UTXO на 70% меньше** (важно для compliance-heavy токенов)
- ✅ **SwapReady UTXO на 46% меньше**
- ✅ **Normal UTXO на 28% меньше**
- ✅ **Single-level swap** — меньше parsing surface
- ✅ **issuerPkh с MPKH support** — redeem path и attestation устойчивы к одиночному compromise

### 5.2 DSTAS features не перенесённые в BNTP

Перенос не делаем — DSTAS остаётся research artifact, не production. Ниже — технические различия как reference, не как regression checklist.

- **Recursive swap chains (`.next`)** — BNTP single-level only.
  - _Impact:_ multi-leg atomic swaps требуют ручной chain'инг в off-chain orchestration.
- **Variable service fields** — BNTP всегда 41b authority block, даже если оба disabled (40 zero bytes + flags byte).
  - _Impact:_ +40b на UTXO без authorities vs DSTAS с пустым service field. Для non-governed tokens небольшая регрессия в per-UTXO size, компенсируется общей −35% за счёт body сокращения.
- **MPKH preimage в body (vs hash-in-tail):** DSTAS хранит полный MPKH preimage как owner field. BNTP хранит 20b HASH160(preimage) в tail — preimage подаётся в unlocking при auth paths.
  - _Impact:_ +40..160b в unlocking для MPKH authority spend paths. Compensated by overall UTXO size savings.

---

## 6. Protocol status & SDK coexistence

### 6.1 Production status

- **DSTAS 1.0.4** — **research artifact**. Не идёт в production. Остаётся в репозитории как reference (показывает дефекты монолитной архитектуры, которые и мотивировали BNTP). Никакой migration path от DSTAS к BNTP не делаем — DSTAS токенов в prod нет.
- **BNTP v1** — **production target**. Новый протокол, чистый старт, никакого legacy coupling с DSTAS.

### 6.2 SDK coexistence rules

`dxs-bsv-token-sdk` содержит оба протокола как независимые surfaces:

```
src/
  bsv/     — low-level primitives (shared, минимальный surface)
  stas/    — legacy p2stas
  dstas/   — DSTAS 1.0.4 (research-only, frozen API)
  bntp/    — BNTP v1 (active development)
```

**Hard isolation rules (см. §7):**

- `src/bntp/**` НЕ импортирует из `src/dstas/**`, и наоборот. CI проверяет grep-правилом.
- Отдельные subpath exports: `"./dstas"` и `"./bntp"`. Root index не ре-экспортирует оба.
- Разные namespaces для функций: `buildDstasLockingScript` vs `buildBntpLockingScript`. Никаких перегрузок.
- Отдельные test suites, отдельные conformance fixture files, независимые regeneration flags.
- Нет migration utility в SDK — если когда-то появится, живёт в отдельном пакете.
- Shared: только `/bsv` примитивы (curve math, hashing, buffer-utils, identity-field, script reader). Любое изменение в shared code тестируется на обоих surfaces.

---

## 7. Risk assessment

| Risk                                                                       | Probability         | Impact                                                                                                                        | Mitigation                                                                                                   |
| -------------------------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Normal-8 не влезет в BSV opcode budget                                     | Medium              | Cap на Normal-4, убираем N-8 from whitelist                                                                                   | Pseudo-ASM pass в Phase 1                                                                                    |
| BNTP pseudo-ASM существенно больше estimates                               | Medium              | Если >2× roughly — перепроектировать                                                                                          | Iterative sizing during impl                                                                                 |
| Whitelist commitment схема содержит subtle bug                             | Low                 | Fundamental design flaw                                                                                                       | Formal write-up + comprehensive eval tests + external review                                                 |
| Shared primitives регрессия в /bsv ломает один из протоколов               | Medium              | Оба протокола используют `/bsv` (identity-field, script reader, curve). PR в shared code может сломать dstas tests и наоборот | CI matrix: test:dstas и test:bntp независимо, оба обязательны на PR в `/bsv`                                 |
| Cross-contamination dstas↔bntp через copy-paste или ambiguous imports      | Medium              | Developer случайно использует DSTAS helper на BNTP UTXO → silent invalid tx                                                   | Hard isolation rules (§6.2), namespace-prefixed function names, ESLint rule запрещающий cross-folder imports |
| DSTAS API меняется из-за "research" changes, ломая тех кто зависит от него | Low (no prod users) | Minimal — research artifact                                                                                                   | Заморозить DSTAS API как есть (1.0.4 final), все changes помечать `@research-only`                           |

---

## 8. Recommendation

**Proceed with BNTP v1** по phased roadmap (см. `BNTP_SERIES_V1_SPEC.md` §14), если все Phase 0 gates пройдены:

1. Pseudo-ASM `Normal` template ≤ 2400b body
2. Formal whitelist commitment scheme proven sound
3. Anchor/follower position-check algorithm reviewed and approved
4. Open spec gaps (`BNTP_SERIES_V1_SPEC.md` §15) resolved

**Stop BNTP если (see `BNTP_CRITICAL_REVIEW.md` §7):**

- Pseudo-ASM `Normal` > 2800b — savings vs DSTAS vanish
- Whitelist commitment scheme fundamentally unsound
- Anchor/follower pattern cannot be made secure — fallback к 2-merge only убивает главное functional gain
- Issuer attestation economic model не жизнеспособен

**Phase 0 timeline:** ~2 недели параллельной работы над pseudo-ASM + formal write-up + gaps resolution.

---

## 9. TL;DR

- **Status:** DSTAS 1.0.4 = research-only, BNTP v1 = production target. Никакой миграции между ними не делаем.
- **Templates:** single-variant design — 3 templates (Normal, Frozen, SwapReady) + Contract, вместо начальных 5.
- **Size:** BNTP −24% Normal UTXO, −70% Frozen UTXO, −46% SwapReady. Transfer tx −24%, split −27%, merge-4 vs 3×merge-2 chains: −36%.
- **Throughput:** K=4 merge даёт −3× tx count при consolidation 1000 UTXO (1000 → 334 tx). Wall-clock в BSV через mempool chaining — сопоставимый.
- **DEX-compat:** issuer attestation gate (Способ C) даёт off-chain B2G validation с royalty model. Новая capability без аналога в DSTAS.
- **Security:** strictly better (closed state + seriesId + explicit sighash + DEX gate). Non-DEX back-to-genesis остаётся той же off-chain моделью.
- **Complexity:** 3 templates vs 1 монолит, каждый проще для аудита. Audit estimate ~5-7 weeks (vs ~2 weeks DSTAS, но параллелится).
- **SDK coexistence:** hard isolation rules — отдельные папки/namespaces/exports/tests. Shared только `/bsv` примитивы.
- **Risk:** Normal pseudo-ASM budget — main unknown. Resolvable in Phase 0 (~2 weeks).

---

## 10. Change log

- 2026-04-17 — initial draft, estimates based on BNTP_SERIES_V1_SPEC.md §12 sizing.
- 2026-04-17 — updated: DSTAS declared research-only, BNTP is sole production path. Removed migration-path section (§6), replaced with SDK coexistence rules. Added consolidation scenarios 100/1000 merges (§2.7). Risk matrix updated.
- 2026-04-17 — **major revision**: single-variant Normal design (dropped Normal-2/Normal-8), whitelist 96b (3 hashes), added issuer attestation (Способ C) on prepare-swap, corrected wall-clock estimates for BSV mempool chaining. Normal UTXO size revised 1975b → 2200b (single variant trade-off). Phase 4 dropped. Audit estimate revised 8-12 weeks → 5-7 weeks.
