# BNTP Execution Playbook — Claude Code Adapted

Адаптация двух Codex-скиллов под Claude Code Agent tool для работы над BNTP v1:

- **Execution Operator** (Codex) → orchestration mode для Claude Code
- **Durable Wave Package** (Codex) → repo-backed execution artifacts

Задача этого документа: дать оператору (мне) чёткие правила как запускать subagents, выбирать модели, делить работу, и закрывать task package'и в Claude Code runtime, с учётом BSV SDK project context.

Связанные:

- `BNTP_SERIES_V1_SPEC.md` — protocol спек
- `BNTP_CRITICAL_REVIEW.md` — risks и gates
- `BNTP_VS_DSTAS_COMPARISON.md` — size/scenario metrics

---

## 1. Ключевые отличия Claude Code от Codex runtime

| Capability         | Codex                     | Claude Code                                          | Impact                                   |
| ------------------ | ------------------------- | ---------------------------------------------------- | ---------------------------------------- |
| Agent spawn        | custom operator           | `Agent` tool with `subagent_type` + optional `model` | Запуск одинаковый                        |
| Model selection    | per-agent config          | `model: "haiku" \| "sonnet" \| "opus"`               | Explicit на каждом вызове                |
| Parallel execution | multi-agent operator      | multiple Agent calls в одном message                 | До 10+ параллельно                       |
| Background run     | operator-driven           | `run_in_background: true`                            | Явный флаг                               |
| Agent lifecycle    | running/completed/closed  | one-shot или SendMessage continue                    | Нет `close_agent`, агент сам завершается |
| Worktree isolation | workspace copies          | `isolation: "worktree"` на Agent                     | Для conflict-risk zones                  |
| Status ledger      | master.md/slices.md files | `TodoWrite` tool + durable package files             | Dual tracking                            |
| Continuation       | same agent persists       | `SendMessage` to recently-ended agent                | Ограниченно                              |

**Следствие:** "close_agent" / "wait_agent" в Codex = agent returns result, я интегрирую, agent dead. Нет long-lived agents в Claude Code modeвыпуска. Если нужно "продолжить" — SendMessage в recently-ended, иначе новый Agent с полным контекстом.

---

## 2. Subagent type + model selection matrix

Для каждого запуска Agent я должен выбрать пару `(subagent_type, model)`. Правила:

### 2.1 По типу задачи

| Тип задачи                                        | subagent_type             | model                | Rationale                                      |
| ------------------------------------------------- | ------------------------- | -------------------- | ---------------------------------------------- |
| Найти файлы по паттерну, grep конкретного символа | `Explore` (quick)         | `haiku`              | Детерминированно, не нужно reasoning           |
| Открытый поиск ("как работает X")                 | `Explore` (medium)        | `sonnet`             | Reasoning о связях                             |
| Глубокий end-to-end research                      | `Explore` (very thorough) | `sonnet`             | Large context + synthesis                      |
| Архитектура нового template / protocol            | `Plan`                    | **`opus`**           | Novel synthesis, high-stakes                   |
| Pseudo-ASM написание template                     | `general-purpose`         | **`opus`**           | Критично для корректности, worth cost          |
| Formal proof / commitment scheme write-up         | `general-purpose`         | **`opus`**           | Rigor нужен                                    |
| Security review конкретного кода                  | `general-purpose`         | **`opus`**           | Depth reasoning                                |
| Implementation по чёткому спеку                   | `general-purpose`         | `sonnet`             | Следование инструкциям                         |
| Test writing по спеку                             | `general-purpose`         | `sonnet`             | Standard mapping                               |
| Code refactor (mechanical rename, extract)        | `general-purpose`         | `sonnet` или `haiku` | Sonnet если judgment, haiku если чисто правило |
| Summarize large file                              | `Explore` (quick)         | `haiku`              | Info extraction, no reasoning                  |
| Claude Code / SDK вопросы                         | `claude-code-guide`       | (inherit)            | Specialized                                    |
| Git/build status checks                           | Direct Bash, **НЕ Agent** | —                    | Overhead delegation не оправдан                |

### 2.2 Rules of thumb

1. **Default model = `sonnet`.** Не escalate до opus без причины (стоимость ~5× haiku, ~1× opus vs 1× sonnet на typical ratio).
2. **Haiku только для:** deterministic transforms, file search, grep, simple file reads, config checks. Если задача требует хоть минимального reasoning о design — sonnet.
3. **Opus только для:** novel design, formal proofs, security-critical reasoning, deep debugging с неясной root cause. Bad usage = opus на "найди где используется функция X" (тратит токены zря).
4. **Override model явно,** не полагаться на default.

### 2.3 BNTP-специфичные маппинги

| BNTP задача                                                 | subagent + model                                            |
| ----------------------------------------------------------- | ----------------------------------------------------------- |
| Написать pseudo-ASM `Normal` template с output verification | `general-purpose` + `opus`                                  |
| Написать pseudo-ASM `Frozen` (проще чем Normal)             | `general-purpose` + `sonnet` (если design уже зафиксирован) |
| Formal write-up whitelist commitment soundness              | `general-purpose` + `opus`                                  |
| Anchor/follower algorithm design + proof                    | `Plan` → `general-purpose` + `opus`                         |
| Найти все места где DSTAS template парсится                 | `Explore` (medium) + `sonnet`                               |
| Refactor: rename `DSTAS_*` → `BNTP_*` в новой папке         | `general-purpose` + `haiku` (mechanical)                    |
| Генерация conformance vectors по спеку                      | `general-purpose` + `sonnet`                                |
| Audit один BNTP template после impl                         | `general-purpose` + `opus`                                  |
| Проверить build/tests после изменения                       | Bash напрямую, не Agent                                     |

---

## 3. Execution loop adaptation

### 3.1 Intake (начало orchestration turn)

1. **Restate task** в одно предложение.
2. **Extract constraints:** scope, deadline, forbidden changes, validation, delivery artifact expectations.
3. **Спросить follow-up только если ответ меняет execution** (architecture choice, env/credential availability, compat target). Не спрашивать уточнений если user уже дал достаточно.
4. Перейти к планированию.

### 3.2 Plan by ownership zones

Перед dispatch — один explicit план. Каждая zone:

- **Goal** (одно предложение)
- **Owned files/modules** (конкретные пути)
- **Inputs/dependencies**
- **Validation**
- **Completion signal**
- **Dependency order:** `sequential` или `parallel`

Формат ledger: `zone | subagent_type | model | status | depends_on | validation | done_when`

Status vocabulary (для TodoWrite и ручного tracking):

- `pending` / `in_progress` / `completed` (TodoWrite native)
- **Mental states** (не в TodoWrite, но в голове): `blocked`, `stale`, `not_opened`

Для durable (repo-backed) orchestration — добавить wave package по §4.

### 3.3 Delegation rules

Delegate только когда работа:

1. **Bounded** (clear scope)
2. **Self-contained** (minimal external context)
3. **Materially useful** (saves time vs doing locally)
4. **Не immediate blocker** для next local action

Каждый delegated prompt содержит:

1. Exact objective
2. Ownership boundaries (exact files/modules)
3. File/module scope (что можно trogать)
4. Forbidden scope (что нельзя)
5. Validation expected
6. Commit expectation (если применимо)
7. Warning: "you are not alone in codebase, do not revert unrelated work"
8. Explicit closeout: что в final reply должно быть

**Compact prompt form:**

```
Objective: <one concrete deliverable>
Owned scope: <exact paths>
Forbidden scope: <paths to not touch>
Context: <minimal local facts>
Validation: <exact commands / proof expected>
Commit expectation: <none / docs-only / per milestone>
Closeout: <what final reply must include>
```

### 3.4 Parallel launch

**Rule:** если N agents работают на disjoint ownership zones — launch all in **one message** с multiple Agent tool calls.

```
<single message>:
  Agent(zone A) + Agent(zone B) + Agent(zone C)
```

**НЕ:** sequential Agent calls (один, ждём, другой) — тратит wall-clock.

**Background `run_in_background: true`** — только когда результат не нужен немедленно для следующего step'а и я могу продолжать другой работой пока он выполняется. Если буду сразу ждать — foreground.

### 3.5 Worktree isolation

Использовать `isolation: "worktree"` когда:

- 2+ agents могут писать в **те же файлы** (unlikely если ownership zones грамотно spilt)
- Agent делает **экспериментальные** изменения которые можно потом отбросить
- Нужна проверочная sandbox копия репозитория

**Не использовать** для disjoint-zones — zbytечный overhead.

### 3.6 Stale-agent protocol

Agent вернул результат но:

- Output incomplete / не решает задачу → decide: **narrower redirect** (SendMessage с tight follow-up) VS **discard + local finish**
- Output touched files outside owned scope → re-read affected files, integrate или reassign boundary, не паниковать
- Output empty / generic → considered failed, redo с better prompt или finish locally

### 3.7 Recovery mode

Вхожу в recovery только когда:

- Repeated stale agents на том же slice
- Remaining work become integration-glue, не independent zone
- Delegation cost > doing locally

Recovery rules:

1. State explicitly: "entering recovery mode, finishing locally"
2. Keep write scope **narrower**, not broader
3. Validate по той же acceptance criteria
4. Update TodoWrite с recovery intervention visible

---

## 4. Durable wave package adaptation

Когда применять: **задача bounded, долгая (2+ часа execution), multi-zone, нужно survive across sessions**.

### 4.1 Output shape (для BNTP)

```
docs/stream-tasks/<slug>/
  master.md         ← executive brief
  slices.md         ← decomposition
  launch-prompt.md  ← handoff to execution-operator mode
```

Closeout дополняет:

```
docs/stream-tasks/<slug>/
  audits/A1.md           ← what landed, validated, residuals
  evidence/closeout.md   ← result, key files, behavior
```

### 4.2 Naming

Slug: hyphenated outcome-focused, не implementation detail.

Примеры для BNTP:

- `bntp-phase-0-pseudo-asm-wave` (wave, один bounded milestone)
- `bntp-phase-1-skeleton-wave` (wave)
- `bntp-v1-full-program` (program, multi-wave container)

### 4.3 `master.md` layout (wave)

1. Goal
2. Product Decision / Core Decision
3. Scope (in/out)
4. Core Rules (invariants, forbidden changes)
5. Ownership Zones (paths, owners)
6. Wave Ledger (table: zone | subagent_type | model | status | depends_on | validation | done_when)
7. Definition of Done
8. Delivery Notes (commit hashes after execution)

### 4.4 `slices.md` layout

1. Overview (одна строка на slice)
2. Slice-by-slice breakdown (per slice: intent, owned paths, exact task, forbidden, validation, completion signal)
3. Dependency order
4. Validation matrix
5. Closeout requirements

### 4.5 `launch-prompt.md` layout

Должен быть **directly executable** как prompt для следующего запуска (меня самого в новом session):

1. Mission
2. Package path
3. Constraints
4. Required execution order (по slices.md)
5. Validation commands
6. Closeout expectations
7. Commit/report expectations

Для BNTP проекта добавить:

- Reminder: shared primitives в `/bsv`, DSTAS изолирован в `/dstas`
- Reminder: все BNTP work в `src/bntp/` (когда начнётся impl)

### 4.6 Quality gate перед commit package

- [ ] slug стабильный и короткий
- [ ] `master.md` имеет real ledger + definition of done
- [ ] `slices.md` ownership-safe (нет overlap)
- [ ] `launch-prompt.md` directly executable без extra context
- [ ] validation explicit (конкретные команды/criteria)
- [ ] closeout path defined

### 4.7 Commit policy для package

- Docs-only commit создания: `docs(bntp): add <wave-name>`
- Implementation commits — separate per milestone, НЕ batching unrelated zones
- Record commit hashes в `master.md` Delivery Notes

---

## 5. Integration with execution loop

Типичный flow для BNTP work:

```
User: "execute Phase 0 of BNTP"
  ↓
[Intake] restate, extract constraints, ask only blocking questions
  ↓
[Plan] create wave package: docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/
        write master.md + slices.md + launch-prompt.md
        TodoWrite: 3 tasks for 3 zones
  ↓
[Commit docs-only]: docs(bntp): add phase-0 pseudo-asm wave
  ↓
[Launch parallel agents in ONE message]:
  Agent A: Normal pseudo-ASM (general-purpose, opus)
  Agent B: whitelist commitment proof (general-purpose, opus)
  Agent C: anchor/follower algorithm (Plan → general-purpose, opus)
  ↓
[Monitor] integrate results as they return
  ↓
[Per-zone]: update TodoWrite, update master.md ledger row,
            commit per bounded milestone, close agent
  ↓
[Phase 0 gates check] — see BNTP_CRITICAL_REVIEW.md §5.2
  ↓
[If gates pass] — write audits/A1.md + evidence/closeout.md,
                   mark wave done, commit closeout
[If gates fail] — recovery mode or pivot per critical review §7
```

---

## 6. Output discipline

### 6.1 Progress update (compact)

```
Status: <what moved>
Active zones: <zone=status>, <zone=status>
Next: <immediate next action>
```

### 6.2 Blocker update

```
Blocked on: <blocker>
Impact: <what cannot proceed>
Attempted: <what was tried>
Need: <exact user input or external dependency>
Fallback: <if unanswered>
```

### 6.3 Closeout (final user message)

```
Result: <delivered outcome>
Zones done: <list>
Validation: <commands/checks actually run>
Residuals: <real remaining risks only, or 'none'>
Ledger: <wave package updated if durable>
```

### 6.4 Escalation format

```
blocker | impacted zone | why local failed | smallest decision needed | fallback
```

---

## 7. Token economy guidelines

### 7.1 Общие принципы

1. **Opus** expensive — только для truly novel design / rigor-critical tasks.
2. **Sonnet** default — balanced quality/cost.
3. **Haiku** cheap — для deterministic/search tasks.
4. **Parallel > sequential** — не столько экономия, сколько wall-clock.
5. **Agent overhead** — не делегировать trivial task (< 30 сек локально).

### 7.2 Concrete rules

- Exploration задача? → Explore agent, не general-purpose.
- "найди где X" → haiku + Explore quick.
- "объясни как X работает в context" → sonnet + Explore medium.
- "спроектируй X" → opus + Plan или general-purpose.
- "напиши код по спеку X" → sonnet + general-purpose.
- "докажи что X корректно" → opus + general-purpose.
- Simple bash commands → direct Bash, not Agent.

### 7.3 Anti-patterns (не делать)

- ❌ Opus на "list files in dir" — waste.
- ❌ Haiku на "design new protocol template" — insufficient.
- ❌ Sequential agents когда independent — waste time.
- ❌ Delegate "decide X or Y" без giving agent both options and trade-offs — подэкономил context, потерял quality.
- ❌ Не закрывать context tight — agent читает всю conversation history если не briefed carefully (spec says brief like smart colleague who just walked in).

---

## 8. BNTP Phase 0 ready-to-execute example

Skeleton wave package для Phase 0 (as documented in `BNTP_CRITICAL_REVIEW.md` §5.1):

```
docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/
  master.md
  slices.md
  launch-prompt.md
```

Three ownership-safe slices:

| Slice                          | Owned path                                | subagent_type   | model    |
| ------------------------------ | ----------------------------------------- | --------------- | -------- |
| S1: Normal pseudo-ASM          | `docs/BNTP_TEMPLATE_NORMAL_ASM.md`        | general-purpose | **opus** |
| S2: Whitelist commitment proof | `docs/BNTP_WHITELIST_COMMITMENT_PROOF.md` | general-purpose | **opus** |
| S3: Anchor/follower algorithm  | `docs/BNTP_ANCHOR_FOLLOWER_ALGORITHM.md`  | general-purpose | **opus** |

All three parallel (disjoint file ownership, no cross-deps).

Phase 0 gates (from critical review):

- S1: `Normal` body estimate ≤ 2400b
- S2: no self-reference loop in commitment scheme
- S3: position-check algorithm sound against shuffled-input attacks

Phase 0 wall-clock estimate: ~4-8 hours agent time (parallel) + integration per slice.

---

## 9. Status log

- **2026-04-17** — initial playbook. Adapted Codex `execution-operator` + `durable-wave-package` for Claude Code Agent tool. Added model selection matrix, parallel launch rules, token economy guidelines, BNTP Phase 0 skeleton example.
