# AGENTS.md — Autonomous Agent Guide for UBC

This file tells an AI coding agent (Codex) how to build UBC **on its own**: implement,
test, verify, fix, and loop until a phase's goal is met — with the least human prompting.

It applies [loop engineering](https://addyosmani.com/blog/loop-engineering/): you do not
prompt turn-by-turn; you run a loop that drives the work against verifiable stopping
conditions, with a strict **maker ≠ checker** split.

Authority order: [`spec/SPEC.md`](./spec/SPEC.md) (normative) > `docs/*` > this file.
When unsure about bytes/algorithms/errors, SPEC.md wins. Never invent format or crypto.

---

## 1. Operating principles

1. **Design the loop, not the prompt.** Pick a goal, run maker→checker→fix until the goal's
   verifiable criteria pass. Stop only when a fresh checker confirms completion.
2. **Maker ≠ checker.** The model that wrote code MUST NOT be the model that approves it.
   Grading your own homework is banned. Verification runs on a different model with a fresh
   context (see §4 model split).
3. **Vectors are the contract.** Behavior is proven against `spec/vectors/`, never against
   self-authored expectations. If code disagrees with a vector, the code is wrong.
4. **Fail closed, read the code.** Automation does not remove comprehension: every change is
   diff-reviewed by the checker against SPEC.md and the relevant `docs/*`.
5. **Isolate work.** Independent tasks run in separate git worktrees to avoid file conflicts.
6. **Persist state.** Progress lives in `docs/ROADMAP.md` so a loop resumes across runs.

---

## 2. The build loop

Each iteration targets one **task** (a checkbox under "Active work" or a Phase in docs/ROADMAP.md).

```
loop(task):
  1. PLAN     — read SPEC.md + relevant docs; write/confirm the task's acceptance criteria
  2. MAKE     — implement in an isolated worktree (maker model)
  3. TEST     — run the task's tests + conformance vectors locally
               fails? → back to MAKE (same task), iterate
  4. CHECK    — fresh checker model reviews diff vs SPEC/docs, runs vectors independently
               fails? → feed findings back to MAKE (same task), iterate
  5. SECURITY — run a Codex security review of the change:
                  codex review --uncommitted "Security review: crypto correctness,
                  fail-closed decoding, nonce/AAD handling, DoS bounds on untrusted
                  lengths, injection, unsafe parsing. Flag anything exploitable."
               any real finding? → back to MAKE (same task), fix, re-run TEST+CHECK+SECURITY
  6. RECORD   — update docs/ROADMAP.md (tick the task, keep its status line current)
  7. COMMIT   — Conventional Commit on the feature branch, then push:
                  git add -A && git commit -m "<type>: <task>" && git push
               (never main; no secrets; no Co-Authored-By)
  8. NEXT     — start the first remaining unchecked task; repeat until none remain
```

Order is strict: TEST must pass before CHECK, CHECK before SECURITY, SECURITY before
COMMIT. A failure at any gate sends the task back to MAKE — never commit a task that has
not passed all three of TEST, CHECK, and SECURITY.

Stopping condition per task = its **goal criteria** (see §3). The loop keeps going,
committing and pushing each passed task, until "Active work" is empty and the current
Phase's exit gate (§5) is green.

---

## 3. Goal criteria (verifiable stopping conditions)

A task is done ONLY when a fresh checker confirms all that apply:

- **Format tasks:** encoder output is byte-exact to the relevant vectors; decoder rejects
  every negative vector with the exact error identifier (SPEC.md §5).
- **SDK tasks:** 100% conformance-vector pass (plain + fixed-nonce encrypted),
  round-trip property holds, cross-decode with the other reference SDK passes.
- **Crypto tasks:** per-chunk AEAD verified-before-release; nonce = base XOR index; AAD =
  header ‖ index; no plaintext emitted on tag/root failure.
- **Security tasks:** DoS caps enforced on untrusted length fields (SECURITY.md §5).
- **CLI tasks:** each verb behaves per API.md and passes vector-based CLI tests.

"It compiles" and "tests pass locally under the maker" are NOT goal criteria. The checker
re-runs and re-reads independently.

---

## 4. Model split (route task → model)

Codex model roster. Route by task difficulty and role. **Checker MUST differ from maker.**

| Role / task | Model | Why |
|-------------|-------|-----|
| Architecture, crypto correctness, spec reasoning, tricky bugs | `gpt-5.6-sol` (or `gpt-5.5`) | Frontier reasoning; correctness-critical, no room for error |
| Everyday implementation (SDK code, CLI, glue) | `gpt-5.6-terra` | Balanced agentic coding for routine work |
| **Verification / code review (checker)** | `gpt-5.5` or `gpt-5.6-sol` | Independent strong reasoner, distinct from the maker model |
| Mechanical work (format tweaks, SDK port scaffolding, docs sync) | `gpt-5.6-luna` | Fast, cheap for low-ambiguity tasks |
| Trivial/repetitive (rename, boilerplate, simple fixes) | `gpt-5.4-mini` | Small, fast, cost-efficient |

Run a model explicitly: `codex -m <model_name>` (or set in `config.toml`).

Routing rules:
- Anything touching **crypto, nonce/AAD, root hash, or reader accept/reject rules** →
  maker on `gpt-5.6-sol`, checker on `gpt-5.5` (or swap; just keep them different).
- Porting an SDK from the frozen spec+vectors → maker `gpt-5.6-terra`/`luna`,
  checker `gpt-5.5`.
- Never let `mini`/`luna` be the **checker** on security- or format-critical tasks.

---

## 5. Cross-cutting gates (must stay green)

Before any phase is marked complete:

- All conformance vectors pass on every implemented SDK (byte-exact + negatives).
- Cross-decode passes across implemented SDKs.
- No SDK carries bespoke expected values (only shared vectors).
- DoS caps present on all untrusted length reads.
- No third-party crypto; stdlib/vetted only.
- Diffs reviewed by checker against SPEC.md; format changes went through RFC.md.

---

## 6. Worktrees & parallelism

- One task = one worktree/branch (`feature/…`, `bugfix/…`, `refactor/…`, `docs/…`).
- Parallel tasks MUST NOT edit the same files; if they would, serialize them.
- Commit atomically, Conventional Commits, no direct commits to main/master.
- Do not commit secrets, generated vectors' private keys used on real data, or temp files.

---

## 7. State file: docs/ROADMAP.md

The loop reads/writes docs/ROADMAP.md each iteration — it is the single source of work and
the shared memory that lets a loop resume. The "Active work" section is the live task queue;
Phases hold longer-range work. Conventions:

```
## Active work (do these first, top to bottom)
- [ ] <task> — Maker: <model> · Checker: <model>
- [~] <task in progress> — status
- [x] <done task> — (checker-confirmed <date>)
```

Legend: `[ ]` todo · `[~]` in progress · `[x]` done. After each task, tick its box and keep
its status line accurate. Never let ROADMAP.md drift from reality.

Keep it current; it is the memory that lets the loop resume without re-deriving context.

---

## 8. When to stop and ask a human

Autonomy has limits. Halt the loop and surface to a human when:

- A change would alter the **frozen format** (needs RFC.md + human sign-off).
- Vectors and SPEC.md disagree (spec ambiguity — do not "pick one" silently).
- A security-relevant decision is not covered by SECURITY.md.
- The checker and maker deadlock across 3 iterations on the same task.
- A new external dependency (esp. crypto) is proposed.

Everything else: keep looping toward the goal criteria.
