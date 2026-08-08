#!/usr/bin/env python3
"""UBC autonomous build-loop driver.

Runs distinct maker and checker `codex exec` passes with the central prompt (prompt.md).
Each pass works the first unfinished task in docs/ROADMAP.md; Codex tends to stop after a
task or when its session fills, so this loop re-launches it until no `- [ ]` or `- [~]` tasks remain under
"Active work" (or a safety cap / stall is hit).

The maker implements and tests. A distinct checker model independently reviews, reruns
relevant gates, performs security review, and only then records and commits a task.

Usage:
    python scripts/loop.py [--model gpt-5.6-terra] [--checker-model gpt-5.6-sol]
        [--max-iters 30] [--prompt prompt.md]

By default codex runs with its normal approval/sandbox. For unattended autonomous runs set
UBC_LOOP_BYPASS=1 to pass --dangerously-bypass-approvals-and-sandbox — do this ONLY inside a
disposable, isolated VM/container with no host mounts or credentials.

Stops when: no `- [ ]` or `- [~]` remain, --max-iters reached, or three maker/checker cycles
leave the same first task unfinished (stall guard — status-prose changes do not reset it).

Before starting, the driver requires a clean feature-style branch. It refuses main/master,
detached HEAD, and pre-existing worktree changes so checker commits cannot capture unrelated work.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROADMAP = REPO_ROOT / "docs" / "ROADMAP.md"

# Match an Active-work task line and preserve its state and description.
TASK_LINE = re.compile(r"^\s*-\s*\[([ ~x])\]\s+(.+)$", re.MULTILINE)
# The "Active work" section is everything from its heading to the next "## " heading.
ACTIVE_WORK = re.compile(r"##\s*Active work.*?(?=\n##\s)", re.DOTALL)

MAKER_INSTRUCTIONS = """

DRIVER ROLE: MAKER PASS. The checker runs separately on a different model after this pass.
Implement and test only the first unfinished Active work task. You may mark it [~] with a
concise current status, but you MUST NOT self-approve it: do not perform CHECK or SECURITY,
do not mark it [x], and do not commit or push. Leave the tested source diff for the checker.
"""

CHECKER_INSTRUCTIONS = """

DRIVER ROLE: INDEPENDENT CHECKER PASS. A different model already implemented and tested the
first unfinished Active work task. Review the uncommitted diff against the normative spec and
relevant docs, rerun relevant tests independently, and run the required security review.
Do not edit implementation source. If any finding or failed gate remains, keep the task [~],
do not commit or push, and report actionable findings for the next maker pass. Only when all
gates pass may you update docs/ROADMAP.md to [x], commit the task, and push the feature branch.
Review exactly one task. After a successful push, exit immediately; never begin or implement a
second task in this checker pass.
"""


def active_work(text: str) -> str:
    m = ACTIVE_WORK.search(text)
    return m.group(0) if m else text


def open_task_count(text: str) -> int:
    return sum(state != "x" for state, _ in active_tasks(text))


def active_tasks(text: str) -> list[tuple[str, str]]:
    tasks = []
    for state, description in TASK_LINE.findall(active_work(text)):
        tasks.append((state, description.split(" — ", 1)[0]))
    return tasks


def first_open_task_index(text: str) -> int:
    for index, (state, _) in enumerate(active_tasks(text)):
        if state != "x":
            return index
    return -1


def completed_exactly_one(before: str, after: str, task_index: int) -> bool:
    before_tasks = active_tasks(before)
    after_tasks = active_tasks(after)
    if len(before_tasks) != len(after_tasks):
        return False
    if task_index < 0 or task_index >= len(before_tasks):
        return False
    for index, ((before_state, before_task), (after_state, after_task)) in enumerate(zip(before_tasks, after_tasks)):
        if before_task != after_task:
            return False
        if index == task_index:
            if before_state == "x" or after_state != "x":
                return False
        elif before_state != after_state:
            return False
    return True


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def git_succeeds(*args: str) -> bool:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, check=False).returncode == 0


def workspace_error() -> str:
    try:
        branch = git_output("branch", "--show-current")
        status = git_output("status", "--porcelain", "--untracked-files=all")
    except RuntimeError as error:
        return f"git workspace check failed: {error}"
    if not branch:
        return "detached HEAD is not a dedicated feature branch"
    if branch in {"main", "master"}:
        return f"refusing protected branch {branch!r}"
    if not re.fullmatch(r"(?:feature|bugfix|hotfix|refactor|docs|chore)/[A-Za-z0-9._-]+", branch):
        return f"branch {branch!r} is not a dedicated feature-style branch"
    if status:
        return "worktree is not clean; commit, stash, or move unrelated changes before starting"
    return ""


def run_codex(
    model: str,
    prompt: str,
    role_instructions: str,
    bypass: bool,
    capture_last_message: bool = False,
) -> tuple[int, str]:
    cmd = ["codex", "exec", "-m", model]
    if bypass:
        # SECURITY: lets codex run shell commands with no approval prompt and no
        # sandbox. Opt-in only (UBC_LOOP_BYPASS=1). Intended for a throwaway VM /
        # container with no host mounts or credentials — never a trusted machine.
        cmd.append("--dangerously-bypass-approvals-and-sandbox")
    result_path = None
    if capture_last_message:
        with tempfile.NamedTemporaryFile(prefix="ubc-checker-", suffix=".txt", delete=False) as result_file:
            result_path = Path(result_file.name)
        cmd.extend(["--output-last-message", str(result_path)])
    cmd.append(prompt + role_instructions)
    try:
        # Stream output live; inherit stdio so the user sees progress.
        code = subprocess.run(cmd, cwd=REPO_ROOT).returncode
        feedback = result_path.read_text(encoding="utf-8") if result_path and result_path.exists() else ""
        return code, feedback
    finally:
        if result_path:
            result_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="UBC codex build-loop driver")
    parser.add_argument("--model", default="gpt-5.6-terra")
    parser.add_argument("--checker-model", default="gpt-5.6-sol")
    parser.add_argument("--max-iters", type=int, default=30)
    parser.add_argument("--prompt", default="prompt.md")
    args = parser.parse_args()
    if args.model == args.checker_model:
        print("maker and checker models must differ", file=sys.stderr)
        return 2

    # Bypass mode is off by default. Enable only with an explicit opt-in env var,
    # and only inside an isolated VM/container (per the security review on this file).
    bypass = os.environ.get("UBC_LOOP_BYPASS") == "1"
    if bypass:
        print("[loop] WARNING: UBC_LOOP_BYPASS=1 — codex runs shell commands with no "
              "approval prompt and no sandbox. Use only in a disposable, isolated "
              "environment.", file=sys.stderr)
    else:
        print("[loop] Running with codex default approval/sandbox. Set UBC_LOOP_BYPASS=1 "
              "(isolated VM only) for unattended autonomous runs.", file=sys.stderr)

    prompt_path = REPO_ROOT / args.prompt
    if not prompt_path.exists():
        print(f"prompt file not found: {prompt_path}", file=sys.stderr)
        return 2
    prompt = prompt_path.read_text(encoding="utf-8")

    if not ROADMAP.exists():
        print(f"roadmap not found: {ROADMAP}", file=sys.stderr)
        return 2

    workspace_problem = workspace_error()
    if workspace_problem:
        print(f"[loop] refusing to start: {workspace_problem}", file=sys.stderr)
        return 2

    unchanged_cycles = 0
    checker_feedback = ""
    for i in range(1, args.max_iters + 1):
        text = ROADMAP.read_text(encoding="utf-8")
        remaining = open_task_count(text)
        if remaining == 0:
            print(f"[loop] Active work is clear. Done after {i - 1} iteration(s).")
            return 0

        current_task_index = first_open_task_index(text)
        starting_branch = git_output("branch", "--show-current")
        starting_head = git_output("rev-parse", "HEAD")
        print(f"[loop] Iteration {i}/{args.max_iters} — {remaining} open task(s). "
              f"Launching maker ({args.model})...")
        maker_instructions = MAKER_INSTRUCTIONS
        if checker_feedback:
            maker_instructions += "\nCHECKER FINDINGS TO FIX:\n" + checker_feedback
        code, _ = run_codex(args.model, prompt, maker_instructions, bypass)
        if code != 0:
            print(f"[loop] maker exited {code}. Halting.", file=sys.stderr)
            return code
        if git_output("branch", "--show-current") != starting_branch:
            print("[loop] maker changed branches before independent review. Halting.", file=sys.stderr)
            return 1
        if git_output("rev-parse", "HEAD") != starting_head:
            print("[loop] maker committed before independent review. Halting.", file=sys.stderr)
            return 1
        if first_open_task_index(ROADMAP.read_text(encoding="utf-8")) != current_task_index:
            print("[loop] maker advanced the task before independent review. Halting.", file=sys.stderr)
            return 1

        print(f"[loop] Launching independent checker ({args.checker_model})...")
        code, checker_feedback = run_codex(
            args.checker_model,
            prompt,
            CHECKER_INSTRUCTIONS,
            bypass,
            capture_last_message=True,
        )
        if code != 0:
            print(f"[loop] checker exited {code}. Halting.", file=sys.stderr)
            return code

        after_text = ROADMAP.read_text(encoding="utf-8")
        after_task_index = first_open_task_index(after_text)
        checker_branch = git_output("branch", "--show-current")
        checker_head = git_output("rev-parse", "HEAD")
        checker_committed = checker_head != starting_head
        if checker_branch != starting_branch:
            print("[loop] checker changed branches. Halting.", file=sys.stderr)
            return 1
        if checker_committed:
            if not git_succeeds("merge-base", "--is-ancestor", starting_head, checker_head):
                print("[loop] checker rewrote history. Halting.", file=sys.stderr)
                return 1
            if git_output("rev-list", "--count", f"{starting_head}..{checker_head}") != "1":
                print("[loop] checker must create exactly one commit. Halting.", file=sys.stderr)
                return 1
            if not completed_exactly_one(text, after_text, current_task_index):
                print("[loop] checker committed without completing exactly one reviewed task. Halting.", file=sys.stderr)
                return 1
            if git_output("status", "--porcelain", "--untracked-files=all"):
                print("[loop] checker left a dirty worktree after commit. Halting.", file=sys.stderr)
                return 1
            try:
                upstream = git_output(
                    "for-each-ref",
                    "--format=%(upstream:short)",
                    f"refs/heads/{starting_branch}",
                )
                pushed_head = git_output("rev-parse", "@{upstream}")
            except RuntimeError:
                print("[loop] checker commit has no readable upstream. Halting.", file=sys.stderr)
                return 1
            if not upstream.endswith(f"/{starting_branch}") or pushed_head != checker_head:
                print("[loop] checker commit was not pushed to its matching upstream. Halting.", file=sys.stderr)
                return 1
        if not checker_committed and after_task_index != current_task_index:
            print("[loop] checker advanced a task without committing it. Halting.", file=sys.stderr)
            return 1

        if after_task_index == current_task_index:
            unchanged_cycles += 1
            if unchanged_cycles >= 3:
                print(
                    f"[loop] Roadmap unchanged across {unchanged_cycles} maker/checker cycles "
                    f"with {remaining} task(s) still open — halting for a human.",
                    file=sys.stderr,
                )
                return 1
        else:
            unchanged_cycles = 0
            checker_feedback = ""

    print(f"[loop] Hit --max-iters ({args.max_iters}). "
          f"{open_task_count(ROADMAP.read_text(encoding='utf-8'))} task(s) still open.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
