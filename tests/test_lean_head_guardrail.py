"""Lean-head guardrail for the `bash` tool description.

WHY THIS EXISTS
---------------
A tool description is not documentation. It is rendered into the tool-schema
block of *every request of every session*, whether or not the tool is ever
called, so its character count is a fixed per-request tax. Probe `g7h3`
measured the full lean head at -13.57% $/task, 95% CI [-22.27%, -4.86%], with
all three pre-registered estimators excluding zero. That saving is only real
while the text stays lean, and prose has exactly one direction of drift: it
grows back.

So this file pins the description three ways, each catching a different
regression:

1. BYTE PINS -- retain the historical v1 fixture and separately pin the shipped
   description with its supported-command guidance.
2. CHAR BUDGET -- a PER-ARTIFACT budget of 1,741 characters. Deliberately not
   a whole-head absolute: `zc6t` measured a real head at 320,410 chars against
   a 48,249 threshold that described an eval container's 14-tool bundle
   composition, not the product's 86. A whole-head number is not a fact about
   this repo and cannot be enforced here.
3. REQUIRED RULES -- every rule, constraint, command and pointer that exists in
   the pre-lean ("stock") text must still be findable in the lean text. This is
   the check that makes the byte pin safe to update: a future editor may
   shorten the text further, but not by dropping something a caller acts on.

The vendored fixture is itself sha256-pinned, so "make the test pass by editing
the fixture" is not a silent path -- it fails here first.

LINE ENDINGS
------------
The fixture is a byte-exact artifact, so `.gitattributes` marks it `-text`: git
must never newline-convert it on checkout. That alone is not enough to rely on
-- a stale clone, a zip export or a `core.autocrlf` setting can still hand us
CRLF -- so the sha256 below is taken over the file's TEXT (read with universal
newlines, which is exactly the string compared against the description), not
its raw bytes. One number then means the same thing on every platform, and it
is simultaneously the sha256 of the shipped description. The first CI run of
this guardrail failed on all three Windows legs for precisely this reason.

WINDOWS NOTE
------------
On Windows the *instance* appends a shell-resolution startup note to
`self.description` (see `BashTool._windows_shell_startup_note` and
`tests/test_windows_shell_resolution.py`). That note is runtime observability,
not head text, and it is platform-conditional -- so every pin below is on the
CLASS attribute `BashTool.description`, which is the text that ships.
"""

import hashlib
from pathlib import Path

import pytest

from amplifier_module_tool_bash import BashTool

# ---------------------------------------------------------------------------
# The vendored v1 slice.
# ---------------------------------------------------------------------------

VENDORED_PATH = Path(__file__).parent / "data" / "v1_bash_description.txt"

# sha256 of the vendored file's TEXT, utf-8 encoded (see LINE ENDINGS above).
# Pinned so the fixture cannot be quietly rewritten to match a description that
# has drifted. The shipped description has a separate pin below.
VENDORED_SHA256 = "75f3577ad0cb859918b8360b13c3ff3bfaa1270e0a604495a21a0da491083cba"

# V1 remains 1,318 chars. Supported-command guidance adds 423 chars.
SHIPPED_SHA256 = "c46fe9c65b4feef3818e836ed8863691b6f666ec73e82c59e538304c743b04e9"
CHAR_BUDGET = 1741

# Every rule, constraint, command and pointer present in the stock text. Each
# must survive verbatim in whatever the description says today. This list was
# re-derived from the stock text at this repo's head (not inherited from the
# upstream fidelity report) and verified present in BOTH stock and lean.
REQUIRED_RULES = [
    # Positioning: bash is the fallback, not the first reach.
    "fallback primitive",
    # When to use -- every named tool must still be named.
    "pytest",
    "npm test",
    "cargo build",
    "make",
    "pip, npm, cargo, brew",
    "git status, git diff, git commit",
    "docker, podman, kubectl",
    "gh pr create, gh issue list",
    "no specialized option exists",
    # Output limits -- the truncation contract and its workaround.
    "truncated to prevent context overflow",
    "[...truncated...]",
    "byte counts",
    "WARNING",
    "JSON, XML",
    "command > output.json",
    # Timeouts and backgrounding.
    "30 seconds",
    "`timeout`",
    "`run_in_background`",
    "dev servers, watchers",
    # Hard constraints.
    "-i flags",
    "rm -rf /, sudo rm",
    # Command-writing guidance.
    'cd "/path/with spaces"',
    "absolute paths",
    "mkdir foo && cd foo",
]


def _vendored_text() -> str:
    return VENDORED_PATH.read_text(encoding="utf-8")


def test_vendored_slice_is_intact():
    """The fixture itself is pinned, so it cannot absorb a drift."""
    assert VENDORED_PATH.exists(), f"vendored v1 slice missing at {VENDORED_PATH}"
    digest = hashlib.sha256(_vendored_text().encode("utf-8")).hexdigest()
    assert digest == VENDORED_SHA256, (
        "tests/data/v1_bash_description.txt has been modified.\n"
        f"  expected sha256: {VENDORED_SHA256}\n"
        f"  actual   sha256: {digest}\n"
        "This file is a verbatim slice of probes/bji-lean-head/v1_tools.json "
        "(key `bash`). If the description legitimately needs to change, change "
        "it upstream in v1_tools.json first, then re-vendor -- do not edit the "
        "fixture to match a drifted description."
    )
    assert len(_vendored_text()) == 1318


def test_shipped_description_preserves_v1_except_command_guidance():
    """Only the command-writing section differs from the historical fixture."""
    prefix = _vendored_text().rsplit("- Quote paths", 1)[0]
    actual = BashTool.description
    assert actual.startswith(prefix)
    assert hashlib.sha256(actual.encode("utf-8")).hexdigest() == SHIPPED_SHA256


def test_description_within_char_budget():
    """Per-artifact char budget -- the thing actually being bought."""
    actual = len(BashTool.description)
    assert actual == CHAR_BUDGET, (
        f"BashTool.description is {actual} chars; the pinned budget is "
        f"{CHAR_BUDGET}. Every character here is paid on every request of every "
        f"session, used or not."
    )


@pytest.mark.parametrize("rule", REQUIRED_RULES, ids=lambda r: r[:40])
def test_required_rule_survives(rule: str):
    """No rule, constraint, command or pointer was dropped to save bytes."""
    assert rule in BashTool.description, (
        f"Required text {rule!r} is absent from BashTool.description.\n"
        "Shortening the description is fine; dropping something a caller acts "
        "on is not. Restore it, or -- if it is genuinely obsolete -- remove it "
        "from REQUIRED_RULES in the same commit, with the reason."
    )
