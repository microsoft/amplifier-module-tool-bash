"""Regression test: binary command output must not be pushed into context.

## Why this test exists

Truncation bounds a *single* call at ``max_output_bytes``, but it does not
bound a *session*: a binary payload still costs tens of thousands of tokens of
noise per call after truncation, so a few dozen such calls exhaust even a
1M-token context. The guard withholds binary streams entirely, replacing them
with a short placeholder naming the byte count and pointing at a file-redirect
workflow.

## Why detection runs on raw bytes

An earlier revision keyed off the U+FFFD ratio of the *decoded* string. That
measure is inverted on both sides and was rejected on evidence:

* Real executables are full of ASCII string tables and NUL padding that decode
  cleanly -- ``/bin/cat`` scores 3.6% U+FFFD, ``python3`` 2.3% -- so genuine
  binaries slip past.
* Text in legacy 8-bit encodings is high-bit on nearly every character --
  cp1251 Russian 80.9%, shift_jis Japanese 64.8% -- so genuine text is
  destroyed.

Detection therefore runs on the raw bytes: strict-UTF-8-decodable is text;
otherwise the C0/C1 control-byte ratio separates binary from legacy-encoded
text. On that measure the populations separate cleanly -- every real binary
tested scored >= 6.0%, every text sample 0.0%. The tests below pin both sides.

## The NUL trap

The obvious binary marker -- a NUL byte -- is the wrong signal for a *shell*
tool. ``find -print0``, ``grep -z`` and ``xargs -0`` emit NUL as a legitimate
record delimiter. NUL is valid UTF-8, so those payloads pass stage 1 untouched.
Keying off NUL (as tool-web does, where it genuinely does mean binary) would
break the standard safe-filename idiom.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from amplifier_module_tool_bash import BashTool


def _tool(**config) -> BashTool:
    return BashTool(config)


def _synthetic_binary() -> bytes:
    """A payload shaped like real binary: dense control bytes, not valid UTF-8."""
    return bytes(range(256)) * 50


# --------------------------------------------------------------------------
# Binary output is withheld
# --------------------------------------------------------------------------


def test_binary_output_is_replaced_with_placeholder() -> None:
    """Binary is withheld and the payload never reaches context."""
    payload = _synthetic_binary()

    guarded, withheld = _tool()._guard_binary_output(payload, stream="stdout")

    assert withheld is True
    assert "binary output withheld" in guarded
    assert "stdout" in guarded
    # The placeholder must be tiny compared to the payload it replaces.
    assert len(guarded) < 300
    assert len(guarded) < len(payload) / 10


def test_placeholder_reports_byte_count_and_ratio() -> None:
    """The placeholder must tell the model what it lost, not just that it lost."""
    payload = _synthetic_binary()

    guarded, _ = _tool()._guard_binary_output(payload, stream="stdout")

    assert f"{len(payload)} bytes" in guarded
    assert "control bytes" in guarded
    # And it must point at a workflow that actually works.
    assert "file" in guarded or "xxd" in guarded


def test_stderr_placeholder_names_stderr() -> None:
    """Each stream is guarded independently and names itself."""
    guarded, withheld = _tool()._guard_binary_output(
        _synthetic_binary(), stream="stderr"
    )

    assert withheld is True
    assert "stderr" in guarded


@pytest.mark.parametrize("name", ["cat", "ls", "python3"])
def test_real_executables_are_withheld(name: str) -> None:
    """The case that broke the U+FFFD detector: actual compiled binaries.

    ``cat`` and ``python3`` decode with only 3.6% / 2.3% U+FFFD because they
    are dense with ASCII string tables, so a decoded-string measure lets them
    through. On raw control bytes they are unambiguous.
    """
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} not on PATH")

    payload = Path(path).read_bytes()[:200_000]

    _, withheld = _tool()._guard_binary_output(payload, stream="stdout")

    assert withheld is True, f"{name} was not detected as binary"


# --------------------------------------------------------------------------
# The NUL trap: legitimate NUL-delimited output must pass through untouched
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        # find . -print0
        ("find -print0", b"./a.txt\x00./b.txt\x00./c with spaces.txt\x00" * 10),
        # grep -z pattern file
        ("grep -z", b"match one\x00match two\x00match three\x00" * 10),
        # find -print0 | xargs -0 grep -l
        ("xargs -0", b"./src/main.py\x00./src/util.py\x00" * 20),
    ],
)
def test_nul_delimited_output_passes_through(label: str, payload: bytes) -> None:
    """NUL is a legitimate shell delimiter, not a binary marker.

    A NUL-keyed guard (as used by tool-web, where NUL genuinely does mean
    binary) would break the standard safe-filename idiom. NUL is valid UTF-8,
    so these payloads pass the strict-decode stage and never reach the ratio.
    """
    guarded, withheld = _tool()._guard_binary_output(payload, stream="stdout")

    assert withheld is False, f"{label} output was wrongly withheld"
    assert guarded == payload.decode("utf-8")


def test_nul_payload_is_valid_utf8() -> None:
    """Pins the premise stage 1 rests on: NUL-delimited output is valid UTF-8."""
    raw = b"./a.txt\x00./b.txt\x00"

    decoded = raw.decode("utf-8")  # must not raise

    assert "\x00" in decoded


# --------------------------------------------------------------------------
# Ordinary text must not be touched
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("plain ascii", b"hello world\n" * 100),
        ("utf-8 accents", "café résumé naïve\n".encode() * 100),
        ("cjk", "日本語のテキスト\n".encode() * 100),
        ("emoji", "shipped 🚀 done ✅\n".encode() * 100),
        ("json", b'{"key": "value", "n": 42}\n' * 100),
        ("ansi colours", b"\x1b[31mERROR\x1b[0m something failed\n" * 100),
        ("base64", b"aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=\n" * 100),
        ("tabs and crlf", b"col1\tcol2\r\nval1\tval2\r\n" * 100),
    ],
)
def test_utf8_text_passes_through(label: str, payload: bytes) -> None:
    """Anything that decodes as strict UTF-8 is text. The guard must not eat it."""
    guarded, withheld = _tool()._guard_binary_output(payload, stream="stdout")

    assert withheld is False, f"{label} was wrongly withheld"
    assert guarded == payload.decode("utf-8")


@pytest.mark.parametrize(
    ("label", "text", "encoding"),
    [
        ("cp1251 russian", "Привет мир, это текст\n" * 50, "cp1251"),
        ("iso-8859-7 greek", "Γειά σου κόσμε\n" * 50, "iso-8859-7"),
        ("shift_jis japanese", "日本語のテキストです\n" * 50, "shift_jis"),
        ("latin-1 accents", "café résumé naïve\n" * 50, "latin-1"),
    ],
)
def test_legacy_encoded_text_passes_through(
    label: str, text: str, encoding: str
) -> None:
    """The case that broke the U+FFFD detector in the other direction.

    Legacy 8-bit text is not valid UTF-8, so it reaches the ratio stage -- but
    it carries no control bytes, so it passes. A decoded-string measure would
    have scored these 64-81% "undecodable" and destroyed them.
    """
    payload = text.encode(encoding)

    guarded, withheld = _tool()._guard_binary_output(payload, stream="stdout")

    assert withheld is False, f"{label} was wrongly withheld"
    # Not valid UTF-8, so it is returned lossily -- but returned, not withheld.
    assert guarded == payload.decode("utf-8", errors="replace")


def test_short_output_is_never_withheld() -> None:
    """Below the sample floor the ratio is too noisy to act on."""
    tool = _tool()
    short = b"\xff\xfe\x00\x01"

    assert len(short) < tool.MIN_BINARY_SAMPLE_BYTES
    guarded, withheld = tool._guard_binary_output(short, stream="stdout")

    assert withheld is False
    assert guarded == short.decode("utf-8", errors="replace")


def test_empty_output_is_never_withheld() -> None:
    """Empty output must not divide by zero."""
    guarded, withheld = _tool()._guard_binary_output(b"", stream="stdout")

    assert withheld is False
    assert guarded == ""


def test_sparse_undecodable_bytes_pass_through() -> None:
    """A few bad bytes in mostly-text output is text, not binary."""
    payload = (b"normal log line here\n" * 100) + b"\xff\xfe"

    guarded, withheld = _tool()._guard_binary_output(payload, stream="stdout")

    assert withheld is False
    assert guarded == payload.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Threshold
# --------------------------------------------------------------------------


def test_threshold_is_documented_value() -> None:
    """The measured separation -- text 0.0%, binary >= 6.0% -- sets the bar."""
    assert _tool().BINARY_CONTROL_BYTE_RATIO == 0.05


def test_tab_lf_cr_are_not_control_bytes() -> None:
    """Whitespace control characters are legitimate in text output."""
    control = _tool()._BINARY_CONTROL_BYTES

    assert 0x09 not in control  # tab
    assert 0x0A not in control  # LF
    assert 0x0D not in control  # CR
    assert 0x00 in control
    assert 0x1B in control  # ESC -- dense in binary, sparse in ANSI text
