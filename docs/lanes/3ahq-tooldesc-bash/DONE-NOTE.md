# DONE-NOTE — lane `3ahq-tooldesc-bash`

**Item:** `model_performance-i11t` — *lean head repo 2/13 amplifier-module-tool-bash: `bash` description — 679 ch, patch ready*
**Repo:** `microsoft/amplifier-module-tool-bash`
**Branch:** `lane/3ahq-tooldesc-bash`
**PR:** #19 (draft → ready on green)
**Outcome:** **branch A — RESOLVED.** Every deliverable is DONE. Nothing was recorded NOT-POSSIBLE; the cap did not bind, because this item buys no API measurement.

---

## Result in one line

`BashTool.description` is now **1,318 chars, down from 1,997 (679 saved, −34.0%)**, byte-identical to the v1 lean text, and pinned three ways by a guardrail that was proven RED on all six CI legs before the change made it GREEN.

---

## Two defects in this lane's `GOAL.md` (reported, not absorbed)

`GOAL.md` in this worktree was templated from a sibling lane and contradicts the work item on two checkable points. Per Procedure step 1, the **work item's own description + acceptance criteria are authoritative**, and that is what was executed.

| # | `GOAL.md` says | Reality | Effect |
|---|---|---|---|
| 1 | "This lane owns ONLY the `amplifier-module-tool-filesystem` slice: `read_file`, `write_file`, `edit_file`, `grep`, `glob`." | The claimed item `model_performance-i11t` is *repo 2/13 amplifier-module-tool-bash*, and this worktree is a checkout of `amplifier-module-tool-bash`. | Followed the item. The `filesystem` slice belongs to sibling lane `3ahq-tooldesc-filesystem`. Nothing outside this repo was touched. |
| 2 | "**CI: this repo has NONE** (`.github/workflows` absent)… **Say that plainly** rather than implying a green run" — while the KNOWN section of the same file says "**This repo HAS CI** … your PR gets a real green run. Use it." | `.github/workflows/ci.yml` exists: a 6-leg matrix (ubuntu/macos/windows × py3.11/3.12). | Used it. Real red and real green run URLs are quoted below and in the PR body. |

Defect 1 also propagates a false claim into the goal's narrative: *"THIS REPO CARRIES THE ONE REAL WEAKENING `zc6t` FOUND … `edit_file`, restored in-repo at +450 chars."* `edit_file` is in the **filesystem** repo. `fidelity-report.json`'s `bash` entry is `"missing_rules": []` — CLEAN. Verified independently below rather than inherited.

---

## Deliverables

| Deliverable | State | Evidence |
|---|---|---|
| The patch applied (or hand-ported with divergence named — never fuzz) | **DONE** | Hand-ported. See "How the patch was applied". |
| Fidelity table re-verified at today's head | **DONE** | See "Fidelity, re-derived at this head". |
| Stock → lean char counts | **DONE** | 1,997 → 1,318 (−679). |
| Byte-for-byte pin test against the v1 text | **DONE** | `tests/test_lean_head_guardrail.py`, 28 tests. |
| CI status stated plainly | **DONE** | This repo **has** CI. Red run and green run URLs below. |
| Draft PR, ready on green, not merged | **DONE** | PR #19. |
| DONE-NOTE at the lane artifact root | **DONE** | This file. Repo-root `DONE-NOTE.md` untouched (item `kez`). |

---

## How the patch was applied — and the one divergence

**The upstream artifact does not apply as a patch. It is a display diff.**

`docs/lanes/zc6t-lean-head-ship/patches/tool-descriptions/bash.patch` on `amplifier-foundation` `main` omits **both** `\ No newline at end of file` markers. The stock text's final line (19 spaces, no trailing newline) and the first added line are therefore concatenated onto one physical line — patch line 45 reads, literally:

```
-                   +Constraints:
```

Both strict appliers reject it:

```
$ git apply --check -p1 bash.patch
error: corrupt patch at line 49

$ patch -p1 -F0 --dry-run < bash.patch
patch unexpectedly ends in middle of line
patch: **** malformed patch at line 48
```

**It was not force-applied with fuzz.** Fuzz is a silent placement decision; precedent in this batch is lane `l4s1` (*"Hunk #1 succeeded at 56 with fuzz 2"*, hand-ported instead) and a fuzzy apply elsewhere that placed a diff **147 lines out of position**, caught only by grepping for numbers that should have been present.

**The hand-port is proven, not asserted.** Restoring the two missing no-newline markers — **no content change** — gives [`patches/bash.repaired.patch`](patches/bash.repaired.patch), which:

1. applies to today's stock text under `git apply` at **zero fuzz** (`git apply --check` clean), and
2. produces bytes **identical** to `bash.lean.txt` (`cmp` clean, 1,318 bytes).

That is the entire divergence from upstream: **newline markers, not text.**

### The chain of byte-equalities

| Comparison | Result |
|---|---|
| `v1_tools.json["bash"]` vs upstream `bash.lean.txt` | identical, 1,318 chars, sha256 `75f3577a…3cba` |
| stock text at this repo's head | 1,997 chars, sha256 `bef1806d…b359` — **the same 1,997 `zc6t` measured**, so the description had not drifted in the interim |
| repaired patch applied to stock | identical to `bash.lean.txt` |
| shipped `BashTool.description` (via AST literal read) | identical to `v1_tools.json["bash"]`, sha256 `75f3577a…3cba` |

---

## Fidelity, re-derived at this head (not inherited)

All 25 rules, constraints, commands and pointers were re-derived from **this repo's** stock text and checked against the lean text. **Nothing actionable was lost.** Each is now enforced by `test_required_rule_survives`, so it cannot be lost later either.

| Category | Atoms preserved |
|---|---|
| Positioning | `fallback primitive` |
| When to use | `pytest`, `npm test`, `cargo build`, `make`, `pip, npm, cargo, brew`, `git status, git diff, git commit`, `docker, podman, kubectl`, `gh pr create, gh issue list`, `no specialized option exists` |
| Output contract | `truncated to prevent context overflow`, `[...truncated...]`, `byte counts`, `WARNING`, `JSON, XML`, `command > output.json` |
| Timeout / backgrounding | `30 seconds`, `` `timeout` ``, `` `run_in_background` ``, `dev servers, watchers` |
| Hard constraints | `-i flags`, `rm -rf /, sudo rm` |
| Command guidance | `cd "/path/with spaces"`, `absolute paths`, `mkdir foo && cd foo` |

**Missing rules: none.** This matches `fidelity-report.json`'s `bash` entry (`missing_rules: []`), but was reached independently.

### What *was* condensed — named, so it is not a silent loss

Four **rationale** phrases (explanations of *why*, carrying no instruction a caller acts on) did not survive:

1. `domain expertise` — one of four nouns in the "specialized options offer…" list; the other three survive.
2. `No domain-specific context or best practices built in`
3. `No semantic understanding of your intent`
4. `to maintain working directory context` — the justification attached to "prefer absolute paths"; the rule itself survives.

Items 2–3 are compressed into the lean text's `bash returns raw text with no retry logic`. These are recorded as **rationale condensed, not rule loss** — the distinction is deliberate and reviewable.

---

## The guardrail

`tests/test_lean_head_guardrail.py` — 28 tests, three independent pins:

1. **Byte pin** — `BashTool.description` is byte-for-byte `tests/data/v1_bash_description.txt`, a verbatim slice of `probes/bji-lean-head/v1_tools.json` (key `bash`).
2. **Char budget** — exactly **1,318**, **per artifact**. Deliberately *not* a whole-head absolute: `zc6t` measured a real head at 320,410 chars against a 48,249 threshold that described an eval container's 14-tool bundle composition, not the product's 86. A whole-head number is not a fact about this repo and cannot be enforced here.
3. **Required rules** — the 25 atoms above. This is what makes the byte pin safe to update: the text may shrink further, but not by dropping something a caller acts on.

The fixture is itself sha256-pinned, so *"make it pass by editing the fixture"* fails in `test_vendored_slice_is_intact` rather than passing silently.

Pins target the **class** attribute `BashTool.description`. On Windows the **instance** appends a shell-resolution startup note (`_windows_shell_startup_note`, covered by `tests/test_windows_shell_resolution.py`); that note is runtime observability, is platform-conditional, and is not head text.

---

## Finding: a byte-exact fixture cannot be a git `text` file

The guardrail's **first** CI run failed on all three Windows legs for a third reason, unrelated to the description:

```
FAILED test_vendored_slice_is_intact
AssertionError: tests/data/v1_bash_description.txt has been modified.
```

It had not been modified. Git newline-converted it on the Windows checkout — 1,328 bytes instead of 1,318 — and the raw-bytes sha256 missed. Left alone, this would have pinned the Windows legs red permanently for a reason no reader would connect to the tool description: precisely the class of silent, misattributed failure this guardrail exists to prevent elsewhere.

Fixed twice over, because either alone is insufficient:

- `.gitattributes` marks the fixture `-text` — the fix at the source.
- The sha256 is now taken over the file's **text** (universal newlines — exactly the string compared against the description) rather than its raw bytes, so a stale clone, a zip export or a local `core.autocrlf` cannot reintroduce it. One number now means the same thing on every platform, and it is simultaneously the sha256 of the shipped description.

Verified by rewriting the fixture to CRLF locally: `test_vendored_slice_is_intact` passes, only the two intended failures remain.

**Worth propagating to the 12 sibling lanes doing the same job.** Any of them pinning a fixture by raw bytes has the same latent Windows failure, visible only if their repo actually runs a Windows CI leg — most do not, which means it would land silently and surface later.

---

## Evidence

| What | Where |
|---|---|
| **RED CI run** (guardrail, pre-change) | [run 34154994787](https://github.com/microsoft/amplifier-module-tool-bash/actions/runs/34154994787) — `fc81161`, **failure**, 2 failed / 167–169 passed on **all six legs**, both failures the intended ones |
| First red run (superseded — Windows CRLF artifact) | [run 34154809379](https://github.com/microsoft/amplifier-module-tool-bash/actions/runs/34154809379) — `92a9e00`, 3 failed on Windows legs |
| **GREEN CI run** (post-change) | [run 34155134435](https://github.com/microsoft/amplifier-module-tool-bash/actions/runs/34155134435) — `6a4b178`, **success**, all six legs |
| Local red | `evidence/guardrail-local-red.txt` (2 failed, 26 passed) |
| Local green | `evidence/suite-local-green.txt` (171 passed, 10 skipped; baseline before this lane was 143 passed, 10 skipped) |
| Upstream artifact, as fetched | `patches/bash.upstream.patch` |
| Repaired patch (markers only) | `patches/bash.repaired.patch` |
| Lean text | `patches/bash.lean.txt` |
| Stock text at this head | `patches/bash.stock-at-head.txt` |

Diff versus **merge-base** `4c1365c` (not a moved `origin/main`): 10 files, +402 / −39. The only non-test, non-artifact change is the description literal in `amplifier_module_tool_bash/__init__.py`. No behavioural code was touched, and the pre-existing suite is unchanged and green.

---

## Spend

**$0.00 of a $0.00 authority — arithmetic `0 runs × 0 arms × $0 / 1.00 = $0.00`, slack $0.00.**

No API measurement was authorised and none was performed. `g7h3` bought the $/task answer at $428.10 and it was not re-bought. No DTU was launched; no infrastructure was registered, so there is nothing in the infra ledger to tear down. `infra_ledger.sh … sweep` was **not** run (batch-global; the manager's verb).

The cap therefore never bound, and no deliverable is NOT-POSSIBLE. This is **outcome branch A**, not B.

---

## What remains open (for the manager)

1. **Merge PR #19.** Per Procedure 4 this lane stops at the draft PR marked ready; the merge is the manager's stage.
2. **The `j1e6-ci-*` CI lane is queued behind this one** deliberately — the pin is the thing worth guarding, and CI is what makes it execute on every future PR. This repo already has a working 6-leg matrix, so for *this* repo `j1e6` has nothing to add; the ordering matters for the 17 repos that lack one.
3. **Propagate the CRLF finding** to the sibling `3ahq-tooldesc-*` lanes before their pins land.
4. **`GOAL.md`'s two defects** (wrong slice, contradictory CI claim) are a goal-authoring problem, not a lane failure — worth fixing in the template that produced 13 of these.
