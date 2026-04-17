# DSTAS Locking Script — Security Audit & Optimization Notes

Статус: **research-only**. DSTAS 1.0.4 не идёт в production — выявленные в этом документе архитектурные дефекты (монолитный template, отсутствие closed forward state, имплицитный sighash check) мотивировали создание нового протокола BNTP v1 (см. `BNTP_SERIES_V1_SPEC.md`). Audit findings ниже сохраняются как reference и как обоснование проектных решений в BNTP.

Документ фиксирует результаты разбора canonical locking template (версия 1.0.4, body `540b` = 2900 байт).

Связанные документы:

- `DSTAS_LOCKING_TEMPLATE_NOTES.md` — высокоуровневое описание template
- `DSTAS_SCRIPT_INVARIANTS.md` — инварианты flows
- `DSTAS_CONFORMANCE_MATRIX.md` — conformance vectors
- `BNTP_SERIES_V1_SPEC.md` — преемник, production target
- `BNTP_VS_DSTAS_COMPARISON.md` — сравнение по сценариям/размерам

---

## 1. Архитектура скрипта (краткий обзор)

**Общая структура template:**

```
<owner 20b> <action_data> OP_2DROP     ← плейсхолдеры (доступ через preimage, не через стек)
[Signature verification — OP_PUSH_TX]   ← ~400 байт: доказывает подлинность preimage
[Preimage parsing]                      ← извлекает hashPrevouts, outpoint, satoshis, hashOutputs
[Spending type dispatch]                ← ветвление: 1=transfer, 2=freeze, 3=confiscation, 4=swap
[Flags & service field parsing]         ← freeze/confiscation authority проверки
[Merge/Swap reconstruction OR simple]   ← реконструкция counterparty prev tx
[Output reconstruction & hashing]       ← собирает outputs, сравнивает hash с hashOutputs
[Satoshi conservation check]            ← NUMEQUALVERIFY: sum(in) == sum(out)
OP_RETURN <redemptionPkh> <flags> <serviceFields...> <optionalData...>
```

**OP_PUSH_TX (covenant mechanism):**

Стандартный BSV-паттерн: DER-подпись конструируется со значением `r = G.x` (x-координата генератора secp256k1: `79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798`). Значение `s` вычисляется из хеша preimage через арифметику в скрипте. `OP_CHECKSIGVERIFY` проверяет сконструированную подпись против одного из двух фиксированных публичных ключей (`038ff83d...` или `023635...`, выбор зависит от чётности `s`). Если `CHECKSIGVERIFY` проходит → preimage гарантированно является sighash preimage текущего инпута.

Даёт скрипту ковенант-доступ ко всем полям транзакции: version, hashPrevouts, hashSequence, outpoint, scriptCode, satoshis, sequence, hashOutputs, locktime, sighashType.

---

## 2. Security findings

### 2.1 🔴 CRITICAL — Back-to-Genesis не верифицируется

**Проблема:** Скрипт НЕ проверяет происхождение токена. Любой может создать фальшивый DSTAS UTXO с идентичным locking script (те же `redemptionPkh`, `flags`, `serviceFields`), и он будет неотличим от настоящего на уровне скрипта.

**Атака — подделка токена для свопа:**

1. Атакующий видит swap-оффер (action data с `requestedScriptHash` + `requestedPkh`)
2. Создаёт фальшивый DSTAS UTXO с правильным `redemptionPkh` (копирует из целевого токена)
3. Locking script фальшивого UTXO идентичен настоящему → `requestedScriptHash` совпадает
4. Совершает swap: получает настоящий токен, жертва получает фальшивый
5. На уровне скрипта всё валидно — обе стороны проходят проверку

**Почему скрипт не может это предотвратить:**

- OP_PUSH_TX даёт доступ только к текущей транзакции (через preimage)
- Merge/swap реконструкция проверяет `hash256(counterparty_prev_tx) == txid` в hashPrevouts, но это доказывает лишь что prev tx существует, не что это валидный DSTAS
- Скрипт проверяет one level back, но не может пройти дальше (нет рекурсии)
- `redemptionPkh` задаётся эмитентом произвольно — нет криптографической привязки к genesis

**Impact:** Критическая уязвимость для trustless-сценариев (DEX, atomic swaps). Любой swap без off-chain верификации provenance — рискован.

Решения — см. раздел 4.

### 2.2 🟡 MEDIUM — SIGHASH type: имплицитное ограничение

Скрипт **не проверяет sighash type напрямую** (нет эксплицитного `OP_SPLIT` последних 4 байт preimage с `41 OP_EQUALVERIFY`). Защита — косвенная через структурные проверки:

- `hashPrevouts` сравнивается через `OP_EQUALVERIFY` / `OP_BOOLOR OP_VERIFY` против реконструированного значения
- С `SIGHASH_ANYONECANPAY` → `hashPrevouts = 0x00...00` → проверка провалится (реконструированное значение ≠ 0)
- С `SIGHASH_NONE` → `hashOutputs = 0x00...00` → проверка outputs провалится
- С `SIGHASH_SINGLE` → `hashOutputs = hash(одного output)` → не совпадёт с `hash(всех outputs)`

**Вердикт:** Косвенная защита работает. Рекомендация — добавить эксплицитную проверку `sighashType == 0x41` (стоит ~5 опкодов, +5 байт). Даёт ясную гарантию и упрощает аудит.

### 2.3 🟡 MEDIUM — Merge reconstruction: segCount bounds

**Текущее ограничение:**

```
OP_DUP OP_2 OP_8 OP_WITHIN OP_VERIFY    // segCount ∈ [2, 8)
```

Означает от 2 до 7 сегментов → counterparty script встречается 1-6 раз в prev tx. Если реальная транзакция содержит counterparty script 7+ раз, реконструкция невозможна и merge/swap заблокирован.

**Impact:** Функциональное ограничение. Транзакции с 7+ одинаковыми DSTAS outputs не смогут быть counterparty в merge/swap. В практике редкий случай (split ≤ 4 outputs), но стоит документировать.

### 2.4 🟢 LOW — Integer arithmetic в swap rate

**Механизм:** `rateNumerator * outputSatoshis / rateDenominator <= inputSatoshis`

BSV использует arbitrary-precision bignum → overflow невозможен. Но `OP_DIV` округляет к нулю, создаёт rounding dust:

**Пример:** rate = 3/7, input = 100 sats → `100 * 3 / 7 = 42` (floor), точное значение 42.857. Атакующий отдаёт 42, теряется 0.857 на каждом свопе.

**Impact:** Потеря до `rateDenominator - 1` сатоши на своп. Для малых denominators — пренебрежимо. Для экстремальных (rate 1/0xFFFFFFFF) loss приближается к полному input.

**Mitigation (SDK-level):** Предупреждать/отклонять свопы с экстремальными rate fractions.

### 2.5 🟢 LOW — OP_DEPTH stack validation

Скрипт использует `OP_DEPTH ... OP_EQUALVERIFY` для проверки структуры стека. Extra items в unlocking → depth увеличится → проверка провалится. Корректно и безопасно.

### 2.6 🟢 LOW — Frozen marker parsing edge case

**Pattern:**

```
OP_DUP OP_DUP OP_IF OP_1 OP_SPLIT OP_DROP OP_ENDIF OP_2 OP_EQUAL
```

Проверяет первый байт action data == 0x02 (frozen). Разобрали все edge cases (пустое action data как OP_0, как OP_2, как байт 0x52, как pushdata 0x52) — во всех случаях parsing корректный. Дефектов нет.

### 2.7 🟢 LOW — Spending type bounds

`OP_1 OP_5 OP_WITHIN OP_VERIFY` — spending type ∈ [1, 5). Types 0, 5, 6, 7 исключены. Корректно.

### 2.8 🟢 LOW — Merge reconstruction collision resistance

Unlocking передаёт pieces, скрипт склеивает `piece[0] || cp_script || piece[1] || cp_script || ... || piece[N]` и сравнивает `hash256(result)` с txid из hashPrevouts. Коллизия hash256 (double SHA-256) вычислительно невозможна → reconstruction криптографически sound для one level back.

---

## 3. Frozen token protection matrix

| Action                     | Frozen? | Allowed?                    |
| -------------------------- | ------- | --------------------------- |
| Transfer (type 1)          | Yes     | ❌ Blocked                  |
| Freeze/Unfreeze (type 2)   | Yes     | ✅ (authority path)         |
| Confiscation (type 3)      | Yes     | ✅ (confiscation authority) |
| Swap cancel (type 4)       | Yes     | ❌ Blocked                  |
| Merge (type 1, merge path) | Yes     | ❌ Blocked                  |

Проверки frozen state выглядят полными.

---

## 4. Back-to-Genesis: анализ решений

### 4.1 Почему проблема фундаментальна

Bitcoin Script — stateless. Каждый скрипт видит только:

- Unlocking script data (стек при входе)
- Sighash preimage (через OP_PUSH_TX)

Нет доступа к blockchain state, block headers, chain of transactions back to genesis.

### 4.2 Подходы и trade-offs

**A. Recursive covenant chain (полный back-trace)**

Каждый DSTAS output хранит в `optionalData` хеш-цепочку доказательств к genesis. При траке unlocking содержит genesis_tx_raw + все intermediate proofs.

- ❌ Unlocking растёт линейно: после 100 трансферов ~3200 байт только proofs
- ❌ Genesis tx raw нужен каждый раз (~500+ байт)
- ❌ O(N) opcodes на верификацию
- ❌ Практический лимит — ~50-100 трансферов до BSV script limits
- **Вердикт:** не масштабируется для долгоживущих токенов

**B. Merkle accumulator proof**

Внешний сервис поддерживает Merkle tree валидных DSTAS UTXO. При merge/swap unlocking включает Merkle proof.

- ❌ Требует trusted 3rd party или federation
- ❌ Proof обновляется при каждом спенде (O(log N))
- ❌ Централизация
- **Вердикт:** работает для федеративных решений

**C. SPV proof (block header chain)**

Доказать что counterparty prev tx включена в блок через Merkle proof + block header.

```
Unlocking: [block_header 80b] [merkle_path 32b × log₂(tx_count)] [cp_prev_tx]
Locking: verify merkle_root(path, hash256(cp_prev_tx)) == block_header.merkle_root
```

- ❌ Не доказывает что block header валиден (без PoW верификации)
- ❌ Не доказывает longest chain
- ❌ +80 + 320 байт в unlocking на SPV proof
- ⚠️ PoW-check в скрипте возможен (~300 опкодов), но миtigating только против non-mining атакующего
- **Вердикт:** partial protection, сомнительна для BSV (низкий hashrate)

**D. One-level-deep prev output validation (прагматичный on-chain подход)**

После реконструкции counterparty prev tx, парсить её в скрипте и верифицировать что output at vout содержит DSTAS locking script с правильным `redemptionPkh`.

- ✅ Атакующий не может создать fake UTXO из воздуха — нужна prev tx с DSTAS outputом
- ✅ Сдвигает атаку на уровень глубже (нужна fake chain of 2+ tx)
- ✅ Масштабируется на 2-3 уровня глубины
- ⚠️ Cost: ~200-300 доп. опкодов в template, ~100-200 байт
- ⚠️ Парсинг raw tx в Script хрупок
- ❌ Всё ещё не доказывает genesis
- **Вердикт:** лучший компромисс для on-chain hardening

**E. Off-chain verification (текущий стандарт индустрии)**

Большинство STAS/token-протоколов на BSV используют off-chain:

- Кошельки верифицируют chain back to genesis через indexer API
- Биржи проверяют provenance перед листингом
- SDK может включить helper для back-trace verification

- ✅ Нулевой overhead в скрипте/unlocking
- ✅ Неограниченная глубина
- ❌ Зависимость от indexer/API
- ❌ Не trustless в сильном смысле
- **Вердикт:** практический стандарт

### 4.3 Рекомендуемый многослойный подход

1. **On-chain (опция D):** добавить 1-level prev output validation для merge/swap
2. **Off-chain (must-have):** SDK helper `verifyTokenProvenance(utxo, indexer)` → trace chain до genesis
3. **Swap guard:** SDK автоматически проверяет counterparty chain перед сборкой swap tx
4. **Optional SPV (C):** для high-value свопов — SPV proof в unlocking (configurable)

---

## 5. Оптимизация размера скрипта

Текущий body size: **2900 байт** (marker `540b`).

### 5.1 Повторяющиеся паттерны

**A. Hash byte reversal (endian swap) — × 4 вхождения, ~200 байт каждое**

```
OP_16 OP_SPLIT OP_15 OP_SPLIT OP_SWAP OP_14 OP_SPLIT OP_SWAP ... OP_CAT ×15
OP_SWAP OP_15 OP_SPLIT ... OP_CAT ×15 OP_CAT
```

BSV не имеет OP_REVERSE или subroutines. Если использовать txids/hashes в native endian повсюду (пушить txid в big-endian в unlocking), 2 из 4 reversal-блоков можно убрать.

**Savings:** ~400 байт.

**B. VarInt decoding — × 8-10 вхождений, ~30 байт**

```
OP_DUP FC00 OP_GREATERTHAN OP_IF FD00 OP_GREATERTHAN OP_IF OP_4 OP_ELSE OP_2 OP_ENDIF OP_SPLIT OP_SWAP 00 OP_CAT OP_BIN2NUM OP_ENDIF
```

Для output parsing (outputs < 65535 байт) 4-byte varint path (OP_4) можно убрать.

**Savings:** ~60-80 байт.

**C. Pushdata length encoding — × 3-4 вхождения, ~50 байт**

Если ограничить owner field в outputs до 20 байт (без MPKH), pushdata encoding упрощается до `14 OP_CAT`.

**Savings:** ~100 байт (но теряется MPKH в outputs — не рекомендуется).

**D. Duplicate output processing blocks**

Обработка до 4 DSTAS outputs повторением блока ~200-300 байт.

В Bitcoin Script нельзя сделать loop → единственный вариант снижения — max outputs с 4 до 2.

**Savings:** ~300-500 байт, но теряется функциональность (split 1→4). Не рекомендуется.

### 5.2 Итоговый потенциал оптимизации template

| Оптимизация                         | Savings           | Trade-off                              |
| ----------------------------------- | ----------------- | -------------------------------------- |
| Убрать 2 hash reversal блока        | ~400 байт         | Требует BE txids в unlocking           |
| Убрать 4-byte varint ветки          | ~60 байт          | Ограничение на script size < 65535     |
| Упростить pushdata encoding         | ~100 байт         | Только 20-byte PKH в outputs, без MPKH |
| Добавить эксплицитный sighash check | +5 байт           | Добавляет                              |
| **Итого**                           | **~460-560 байт** | **target body ~2340-2440 байт**        |

### 5.3 Оптимизация unlocking script

Unlocking для merge/swap содержит:

- Preimage: ~180+ байт (несжимаемо, протокольное)
- Sig + pubkey: ~107 байт (несжимаемо)
- Output tuples: ~(9 + 21 + action_data) × num_outputs
- Merge pieces: зависит от prev tx size
- Spending type: 1 байт

**Потенциальные approaches:**

**A. Убрать output action data из unlocking (~60 байт на swap output)**

Не работает: скрипт должен верифицировать action data в output. Без action data в unlocking невозможно собрать output для hashOutputs check.

**B. Компактное представление merge pieces**

Вместо pieces — full prev tx + offsets. Скрипт разбивает по counterparty script через OP_SPLIT.

Не работает: скрипт уже делает reconstruction из pieces. Поиск cp_script в full tx требует loop, которого нет в Bitcoin Script.

**Вердикт:** unlocking size оптимизировать в текущей Script-модели невозможно.

---

## 6. Дополнительные наблюдения

### 6.1 Counterparty script extraction

`extractDstasCounterpartyScript()` отрезает первые 2 поля (owner + action_data). Остаток — общий для всех DSTAS токенов с одинаковыми параметрами. By design: позволяет merge одинаковых токенов. Но делает невозможным различение оригинала от подделки на уровне скрипта.

### 6.2 Data marker coupling

Маркер `540b` (2900) жёстко вкомпилирован в template и используется для extraction `redemptionPkh` из counterparty script:

```
OP_DUP 540b OP_SPLIT OP_NIP 14 OP_SPLIT OP_SWAP
```

Любое изменение body size требует обновления маркера. Формула: `marker = bytes_before_OP_RETURN + 2`. Хрупкий coupling — при оптимизации обязательно пересчитать.

### 6.3 Spending type coverage

| Type | Use             | Script checks                                             |
| ---- | --------------- | --------------------------------------------------------- |
| 1    | Transfer/Merge  | Owner sig, output conservation, hashOutputs               |
| 2    | Freeze/Unfreeze | Authority sig, frozen flag toggle, hashOutputs            |
| 3    | Confiscation    | Confiscation authority sig, output redirect, conservation |
| 4    | Swap cancel     | Owner sig, swap action data parsing, rate validation      |

Покрытие полное, gaps не обнаружены.

---

## 7. Итоговые рекомендации

**Disclaimer:** DSTAS 1.0.4 declared research-only (см. заголовок). Рекомендации ниже сохраняются как reference — **не планируются к имплементации в DSTAS**. Вместо этого все релевантные findings учтены при проектировании BNTP v1:

| DSTAS finding               | BNTP v1 treatment                                                                                           |
| --------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Back-to-genesis отсутствует | Same limitation on-chain, но добавлен closed forward state (whitelist + seriesId) → narrower attack surface |
| Sighash type implicit       | Explicit check `== 0x41` в каждом template (+5b)                                                            |
| Merge только 2-input        | Three Normal variants: N-2, N-4, N-8                                                                        |
| Monolithic 2900b body       | 5 templates по 700-2300b, каждый для своего state                                                           |
| Counterparty spoofing       | `seriesId` 32b commitment к whitelist исключает cross-series подделку                                       |
| Data marker coupling        | Retained как body_marker (2b), но теперь доменно-специфичен                                                 |
| Hash reversal × 4           | Планируется убрать 2 из 4 в BNTP pseudo-ASM pass                                                            |
| Variable service fields     | Fixed 41b authority tail layout                                                                             |

### 7.1 Что НЕ делаем (deprecated)

- ~~`verifyTokenChain` helper для DSTAS~~ — DSTAS токенов в prod нет.
- ~~Swap guard для DSTAS~~ — same reason.
- ~~Эксплицитный sighash check в DSTAS template~~ — не патчим research artifact.
- ~~1-level prev output validation в DSTAS~~ — same.
- ~~SPV proof extension в DSTAS~~ — same.
- ~~Оптимизация DSTAS template size~~ — same.

### 7.2 Что переносится в BNTP

Все рекомендации из §4.3, §5 и §7 выше отражены в `BNTP_SERIES_V1_SPEC.md` (явные sighash check, closed forward state через whitelist, авторитет в fixed tail, отсутствие recursive action_data). См. детали в BNTP спеке §1 (design goals) и §13 (security considerations).

### 7.4 Общий вывод

Скрипт криптографически корректен для своей модели (covenant enforcement). Основная уязвимость — отсутствие provenance verification (back-to-genesis) — является фундаментальным ограничением Bitcoin Script. Оптимальная стратегия: многослойная защита (on-chain structure validation + off-chain chain verification + SDK-level guards).

---

## 8. Status log

- 2026-04-17 — первичный аудит по версии 1.0.4, canonical template (body 2900 байт).
- 2026-04-17 — DSTAS 1.0.4 declared research-only. Mitigation work deprioritized. Findings preserved as reference and as motivation for BNTP v1 design (см. `BNTP_SERIES_V1_SPEC.md`). API frozen; дальнейшая работа протокола только в `/bntp`.
