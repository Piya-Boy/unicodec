#requires -Version 7
<#
.SYNOPSIS
  UBC autonomous build loop. Drives Phase 1 tasks through maker -> checker with a strict
  maker != checker split, advancing task to task WITHOUT stopping (loop engineering).

.DESCRIPTION
  Repeats until the Phase-1 exit gate is green or -MaxTasks is reached:
    1. MAKER (implementer model) does the first unchecked Phase-1 task in docs/ROADMAP.md.
    2. CHECKER (different model) independently verifies the diff + re-runs tests/vectors.
       - PASS  -> checker marks the task Done (checker-confirmed); loop advances.
       - FAIL  -> maker fixes SAME task; retried up to -MaxFixRounds; then halts for a human.
  Maker and checker are always different models. The checker never edits implementation code.

  Human stays in the loop by design: the run is bounded (-MaxTasks, -MaxFixRounds) and
  stop-and-ask conditions in AGENTS.md section 8 still force a halt (format change,
  spec ambiguity, new crypto dep, deadlock).

.PARAMETER Maker
  Codex model for implementation. Default gpt-5.6-sol.
.PARAMETER Checker
  Codex model for verification. MUST differ from Maker. Default gpt-5.5.
.PARAMETER MaxTasks
  Max tasks to complete in one run before returning control. Default 20.
.PARAMETER MaxFixRounds
  Max maker fix attempts on a single failing task before halting. Default 3.

.EXAMPLE
  ./scripts/loop.ps1
.EXAMPLE
  ./scripts/loop.ps1 -Maker gpt-5.6-terra -Checker gpt-5.5 -MaxTasks 5
#>
param(
  [string]$Maker        = "gpt-5.6-sol",
  [string]$Checker      = "gpt-5.5",
  [int]   $MaxTasks     = 20,
  [int]   $MaxFixRounds = 3
)

$ErrorActionPreference = "Stop"

if ($Maker -eq $Checker) {
  throw "Maker and Checker must differ (maker != checker rule). Both were '$Maker'."
}
if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
  throw "codex CLI not found on PATH."
}

$StateFile  = "docs/ROADMAP.md"
$DoneMarker = "PHASE1_EXIT_GATE_GREEN"
$PassMarker = "CHECKER_VERDICT: PASS"
$FailMarker = "CHECKER_VERDICT: FAIL"

function Invoke-Codex {
  param([string]$Model, [string]$Prompt)
  # Non-interactive single-shot. Adjust the flag to your codex CLI if needed.
  codex -m $Model exec $Prompt 2>&1 | Tee-Object -Variable out | Write-Host
  return ($out -join "`n")
}

function Get-FirstOpenTask {
  if (-not (Test-Path $StateFile)) { return $null }
  $lines = Get-Content $StateFile
  # First unchecked "- [ ]" task in ROADMAP.md, scanning top to bottom.
  # "Active work" sits above the Phases, so this naturally drains it first.
  foreach ($l in $lines) {
    if ($l -match '^\s*-\s*\[\s\]\s*(.+)$') { return $Matches[1].Trim() }
  }
  return $null
}

$makerPromptTemplate = @"
Read AGENTS.md and docs/ROADMAP.md in full. Follow the build loop in AGENTS.md section 2.
TASK: {0}
Implement ONLY this task. spec/SPEC.md is normative; never invent format or crypto.
Run the task's tests and any conformance vectors locally (TEST stage).
Update docs/ROADMAP.md: move this task to 'In progress', note maker={1}.
Do NOT mark it Done and do NOT self-approve — a different checker model verifies next.
If you hit an AGENTS.md section 8 stop-and-ask condition, STOP and say so explicitly.
"@

$checkerPromptTemplate = @"
Read AGENTS.md sections 3-5 and docs/ROADMAP.md. You are the CHECKER (maker != checker).
TASK under review: {0}
Review the most recent diff against spec/SPEC.md and the relevant docs/ files.
Independently re-run the tests and conformance vectors. Do NOT edit implementation code.
Judge the task's goal criteria (AGENTS.md section 3).
On the LAST line of your output print exactly one of:
  $PassMarker
  $FailMarker
If PASS: update docs/ROADMAP.md to move the task to 'Done' with '(checker-confirmed)'.
If FAIL: list concrete, actionable findings for the maker (do not edit code).
"@

$fixPromptTemplate = @"
Read AGENTS.md and docs/ROADMAP.md. You are the MAKER (maker={1}) fixing a task the
checker REJECTED.
TASK: {0}
Checker findings:
{2}
Address every finding. Re-run tests/vectors locally. Keep the task 'In progress'.
Do NOT self-approve — the checker re-verifies.
"@

Write-Host "UBC loop: maker=$Maker checker=$Checker maxTasks=$MaxTasks maxFix=$MaxFixRounds" -ForegroundColor Green

for ($t = 1; $t -le $MaxTasks; $t++) {

  $task = Get-FirstOpenTask
  if (-not $task) {
    Write-Host "No open tasks remain in docs/ROADMAP.md. Done." -ForegroundColor Green
    break
  }

  Write-Host ""
  Write-Host "==================== TASK $t : $task ====================" -ForegroundColor Cyan

  # --- MAKER ---
  Write-Host "-- MAKER ($Maker) --" -ForegroundColor Cyan
  $makerOut = Invoke-Codex -Model $Maker -Prompt ($makerPromptTemplate -f $task, $Maker)
  if ($makerOut -match 'stop-and-ask|STOP AND ASK|section 8') {
    Write-Host "Maker hit a stop-and-ask condition. Halting for human review." -ForegroundColor Red
    break
  }

  # --- CHECKER (+ fix rounds) ---
  $passed = $false
  for ($f = 1; $f -le $MaxFixRounds; $f++) {
    Write-Host "-- CHECKER ($Checker) round $f --" -ForegroundColor Yellow
    $checkOut = Invoke-Codex -Model $Checker -Prompt ($checkerPromptTemplate -f $task)

    if ($checkOut -match [regex]::Escape($PassMarker)) {
      Write-Host "CHECKER PASS." -ForegroundColor Green
      $passed = $true
      break
    }

    Write-Host "CHECKER FAIL (round $f/$MaxFixRounds). Sending back to maker." -ForegroundColor Red
    if ($f -eq $MaxFixRounds) { break }

    Write-Host "-- MAKER FIX ($Maker) round $f --" -ForegroundColor Cyan
    [void](Invoke-Codex -Model $Maker -Prompt ($fixPromptTemplate -f $task, $Maker, $checkOut))
  }

  if (-not $passed) {
    Write-Host "Task did not pass within $MaxFixRounds fix rounds. Halting for human." -ForegroundColor Red
    break
  }
}

Write-Host ""
Write-Host "Loop run complete. Review docs/ROADMAP.md for status." -ForegroundColor Green
