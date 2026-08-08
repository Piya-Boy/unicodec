# Codex Prompt — UBC central driver

Single entry point for the AI agent. Paste the prompt below; it tells the agent which
files to read and to work from the roadmap.

## Run

```powershell
codex exec -m gpt-5.6-terra --dangerously-bypass-approvals-and-sandbox (Get-Content prompt.md -Raw)
```

Run from the repo root. `--dangerously-bypass-approvals-and-sandbox` lets it run tests and
edit files without prompting. Work happens on a feature branch — never commit to main.

---

## PROMPT

You are building UBC (Universal Binary Container) autonomously.

FIRST, read these files in full before doing anything:
- AGENTS.md — the build loop, model split, stop-and-ask rules (authority after the spec)
- spec/SPEC.md — the NORMATIVE byte format; when in doubt about bytes/crypto/errors, it wins
- docs/ROADMAP.md — THE WORK LIST. The "Active work" section is your task queue
- docs/ALGORITHM.md, docs/SECURITY.md, docs/API.md, docs/TESTING.md, docs/SDK.md — reference

THEN work the roadmap:
- Do the FIRST unchecked task under "Active work" in docs/ROADMAP.md. If "Active work" is
  empty, do the first unchecked task in the current Phase.
- For EACH task run the full loop from AGENTS.md section 2, in this strict order:
  1. MAKE — implement, spec-normative.
  2. TEST — go test ./..., go vet, go test -race (and the Node suite if touched). Fix
     until green.
  3. CHECK — hostile self-review against SPEC.md and the relevant docs. Fix until clean.
  4. SECURITY — run: codex review --uncommitted "Security review: crypto correctness,
     fail-closed decoding, nonce/AAD handling, DoS bounds on untrusted lengths, injection,
     unsafe parsing. Flag anything exploitable." Fix any real finding, then re-run TEST +
     CHECK + SECURITY.
  5. RECORD — update docs/ROADMAP.md: tick the task [x] (or [~] if partway) and keep its
     status line accurate. The roadmap is the shared memory — always leave it current.
  6. COMMIT — only after TEST + CHECK + SECURITY all pass:
     git add -A && git commit -m "<type>: <task>" && git push
     Conventional Commits; feature branch only, never main; no secrets; no Co-Authored-By.
- Never commit a task that has not passed TEST, CHECK, and SECURITY.
- After committing + pushing a task, immediately start the next unchecked one. Do NOT stop
  to ask "should I continue?".

RULES:
- Never invent format or crypto. spec/SPEC.md is normative.
- Vectors in spec/vectors are the contract; never write bespoke expected values.
- Stdlib / vetted crypto only. Keep chunk_count/total_size as true 64-bit.
- Go and Node must expose equivalent public APIs (cross-language parity is a security
  property — SECURITY.md §6).
- Work on a feature branch; never commit to main. Conventional Commits. No secrets.

STOP AND ASK a human ONLY for AGENTS.md section 8 conditions: changing the frozen format,
a spec/vector contradiction, a new crypto dependency, or being stuck on one task after 3
fix attempts. Otherwise keep going until "Active work" is empty and the current Phase's
exit criteria are met, then summarize what changed and stop.

---

## Resume (new session after this one ends)

Same prompt — it is stateless. The agent re-reads docs/ROADMAP.md and continues from the
first unchecked task. Nothing else to pass.
