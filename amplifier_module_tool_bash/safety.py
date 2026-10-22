"""
Safety validation module for the Amplifier bash tool.

Provides a configurable, profile-based safety system with smart pattern matching
that avoids false positives while maintaining security for dangerous commands.

Key Features:
- Multiple safety profiles (strict, standard, permissive, unrestricted)
- Syntax-aware matching that inspects every effective Bash command
- Configurable allowlists that can override blocklists (profile-dependent)
- Clear error messages with hints for enabling blocked commands

Example:
    >>> from safety import SafetyValidator, SafetyConfig
    >>> validator = SafetyValidator(profile="strict")
    >>> result = validator.validate("cd ~/dev/project")
    >>> assert result.allowed  # Not blocked - /dev/ is in a path, not a redirect

    >>> result = validator.validate("sudo apt install vim")
    >>> assert not result.allowed  # Blocked in strict mode
    >>> print(result.hint)  # Suggests permissive/unrestricted profile
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Literal

import tree_sitter_bash
from tree_sitter import Language, Node, Parser

_BASH_LANGUAGE = Language(tree_sitter_bash.language())
_DYNAMIC_WORD_NODES = {
    "arithmetic_expansion",
    "brace_expression",
    "command_substitution",
    "expansion",
    "process_substitution",
    "simple_expansion",
}
_NON_ARGUMENT_NODES = {
    "comment",
    "file_redirect",
    "heredoc_redirect",
    "herestring_redirect",
    "variable_assignment",
}


@dataclass(frozen=True)
class _ShellWord:
    # None means the actual value is unknown, never a raw source fallback.
    value: str | None
    dynamic: bool = False
    opaque_quoting: bool = False


class _UnsafeShellSyntax(ValueError):
    """Raised when a restricted profile cannot safely inspect a command."""

    def __init__(
        self, reason: str, *, stage: str | None = None,
        scope: str = "top_level", depth: int = 0,
        line: int | None = None, byte_column: int | None = None,
        node_category: str | None = None,
    ):
        # Callers supply fixed labels and parser coordinates, never source text.
        if stage is not None:
            details = f"stage={stage}, scope={scope}, depth={depth}"
            if line is not None and byte_column is not None:
                details += (
                    f"; reported parser location: line {line}, byte column {byte_column}"
                )
                if scope == "shell_c":
                    details += "; coordinates within decoded nested script"
                elif scope == "eval":
                    details += "; coordinates within joined eval arguments"
            if node_category is not None:
                details += f"; node={node_category}"
            reason = f"{reason} ({details})"
        super().__init__(reason)


@dataclass
class BlockPattern:
    """A pattern to match against commands for blocking.

    Attributes:
        pattern: The pattern string to match
        reason: Human-readable explanation of why this is blocked
        check_type: How to match the pattern:
            - "command": Only match at command position (not in paths/strings)
            - "substring": Simple substring match (legacy behavior)
            - "regex": Full regex pattern matching
    """

    pattern: str
    reason: str
    check_type: Literal["command", "substring", "regex"] = "substring"


@dataclass
class SafetyProfile:
    """A safety profile defining blocked patterns and override behavior.

    Attributes:
        name: Profile identifier (strict, standard, permissive, unrestricted)
        blocked_patterns: List of patterns to block
        allow_overrides: Whether allowlist can override blocked patterns
    """

    name: str
    blocked_patterns: list[BlockPattern]
    allow_overrides: bool = False


@dataclass
class SafetyResult:
    """Result of a safety validation check.

    Attributes:
        allowed: Whether the command is allowed to execute
        reason: Explanation if blocked (None if allowed)
        matched_pattern: The pattern that matched (None if allowed)
        hint: Suggestion for enabling if blocked (None if allowed)
    """

    allowed: bool
    reason: str | None = None
    matched_pattern: str | None = None
    hint: str | None = None


@dataclass
class SafetyConfig:
    """Configuration for safety validation.

    Attributes:
        profile: Name of the safety profile to use
        allowed_commands: Whitelist of allowed command patterns (supports * wildcards)
        denied_commands: Additional custom patterns to block
        safety_overrides: Fine-grained override settings (for advanced use)
    """

    profile: str = "strict"
    allowed_commands: list[str] = field(default_factory=list)
    denied_commands: list[str] = field(default_factory=list)
    safety_overrides: dict | None = None


# =============================================================================
# Predefined Safety Profiles
# =============================================================================

STRICT_PROFILE = SafetyProfile(
    name="strict",
    blocked_patterns=[
        BlockPattern("rm -rf /", "Prevents root filesystem deletion", "command"),
        BlockPattern("rm -rf ~", "Prevents home directory deletion", "command"),
        BlockPattern("rm -fr /", "Prevents root filesystem deletion", "command"),
        BlockPattern("rm -fr ~", "Prevents home directory deletion", "command"),
        BlockPattern(
            "sudo", "Privilege escalation not allowed in strict mode", "command"
        ),
        BlockPattern("su -", "User switching not allowed", "command"),
        BlockPattern("dd if=/dev/zero", "Dangerous disk overwrite", "substring"),
        BlockPattern("dd if=/dev/random", "Dangerous disk overwrite", "substring"),
        BlockPattern("mkfs", "Filesystem creation not allowed", "command"),
        BlockPattern(r">\s*/dev/(?!null)", "Writing to devices not allowed", "regex"),
        BlockPattern("passwd", "Password changes not allowed", "command"),
        BlockPattern("chmod 777 /", "Dangerous root permissions", "substring"),
        BlockPattern(
            "chown -R /", "Recursive ownership of root not allowed", "substring"
        ),
        BlockPattern(":(){ :|:& };:", "Fork bomb", "substring"),
    ],
    allow_overrides=False,
)

STANDARD_PROFILE = SafetyProfile(
    name="standard",
    blocked_patterns=[
        BlockPattern("rm -rf /", "Prevents root filesystem deletion", "command"),
        BlockPattern("rm -rf ~", "Prevents home directory deletion", "command"),
        BlockPattern("rm -fr /", "Prevents root filesystem deletion", "command"),
        BlockPattern("rm -fr ~", "Prevents home directory deletion", "command"),
        BlockPattern(
            "sudo", "Privilege escalation not allowed in standard mode", "command"
        ),
        BlockPattern("su -", "User switching not allowed", "command"),
        BlockPattern("dd if=/dev/zero", "Dangerous disk overwrite", "substring"),
        BlockPattern("dd if=/dev/random", "Dangerous disk overwrite", "substring"),
        BlockPattern("mkfs", "Filesystem creation not allowed", "command"),
        BlockPattern(r">\s*/dev/(?!null)", "Writing to devices not allowed", "regex"),
        BlockPattern("passwd", "Password changes not allowed", "command"),
        BlockPattern("chmod 777 /", "Dangerous root permissions", "substring"),
        BlockPattern(
            "chown -R /", "Recursive ownership of root not allowed", "substring"
        ),
        BlockPattern(":(){ :|:& };:", "Fork bomb", "substring"),
    ],
    allow_overrides=True,  # Key difference: allowlist can override
)

PERMISSIVE_PROFILE = SafetyProfile(
    name="permissive",
    blocked_patterns=[
        BlockPattern("rm -rf /", "Prevents root filesystem deletion", "command"),
        BlockPattern("rm -fr /", "Prevents root filesystem deletion", "command"),
        BlockPattern(":(){ :|:& };:", "Fork bomb", "substring"),
    ],
    allow_overrides=True,
)

UNRESTRICTED_PROFILE = SafetyProfile(
    name="unrestricted",
    blocked_patterns=[],
    allow_overrides=True,
)

# Profile registry for lookup by name
PROFILES: dict[str, SafetyProfile] = {
    "strict": STRICT_PROFILE,
    "standard": STANDARD_PROFILE,
    "permissive": PERMISSIVE_PROFILE,
    "unrestricted": UNRESTRICTED_PROFILE,
}


class SafetyValidator:
    """Validates commands against safety rules based on configured profile.

    The validator uses a layered approach:
    1. Unrestricted profile bypasses all checks
    2. Allowlist checked first (if profile allows overrides)
    3. Blocked patterns checked with smart matching
    4. Custom denied_commands checked
    5. Default: allow

    Example:
        >>> validator = SafetyValidator(profile="strict")
        >>> result = validator.validate("git status")
        >>> assert result.allowed

        >>> result = validator.validate("sudo rm -rf /")
        >>> assert not result.allowed
        >>> print(result.reason)  # "Privilege escalation not allowed..."
    """

    def __init__(self, profile: str = "strict", config: SafetyConfig | None = None):
        """Initialize the safety validator.

        Args:
            profile: Name of the safety profile to use (strict, standard,
                     permissive, unrestricted)
            config: Optional SafetyConfig for additional customization

        Raises:
            ValueError: If profile name is not recognized
        """
        if profile not in PROFILES:
            valid_profiles = ", ".join(PROFILES.keys())
            raise ValueError(
                f"Unknown profile '{profile}'. Valid profiles: {valid_profiles}"
            )

        self.profile = PROFILES[profile]
        self.config = config or SafetyConfig(profile=profile)

        # Extract configuration
        self.allowed_commands = self.config.allowed_commands
        self.denied_commands = self.config.denied_commands

        # Handle safety_overrides for fine-grained control
        self._override_allows: list[str] = []
        self._override_blocks: list[str] = []
        if self.config.safety_overrides:
            self._override_allows = self.config.safety_overrides.get("allow", [])
            self._override_blocks = self.config.safety_overrides.get("block", [])

    def validate(self, command: str) -> SafetyResult:
        """Validate a command against safety rules.

        Args:
            command: The shell command to validate

        Returns:
            SafetyResult indicating whether command is allowed
        """
        # 1. Unrestricted profile = always allow
        if self.profile.name == "unrestricted":
            return SafetyResult(allowed=True)

        # 2. Check allowlist (if profile allows overrides)
        if self.profile.allow_overrides:
            if self._matches_allowlist(command):
                return SafetyResult(allowed=True)

        try:
            parsed_commands = self._parse_shell_commands(command)
            # Critical argument checks can also refuse unknown values here.
            for pattern in self.profile.blocked_patterns:
                if self._check_pattern(command, pattern, parsed_commands):
                    return SafetyResult(
                        allowed=False,
                        reason=pattern.reason,
                        matched_pattern=pattern.pattern,
                        hint="Use safety_profile: 'permissive' or 'unrestricted' for container/VM environments",
                    )
        except _UnsafeShellSyntax as exc:
            return SafetyResult(
                allowed=False,
                reason=f"Unable to safely analyze Bash syntax: {exc}",
                matched_pattern="<unsupported bash syntax>",
                hint=(
                    "Command was not executed. Safety analysis could not inspect this "
                    "syntax; report a minimal non-sensitive reproducer."
                ),
            )

        # 4. Check custom denied_commands (supports wildcards)
        for denied in self.denied_commands:
            if self._matches_wildcard(command, denied):
                return SafetyResult(
                    allowed=False,
                    reason=f"Matches custom denied pattern: {denied}",
                    matched_pattern=denied,
                    hint="Remove from denied_commands or add to allowed_commands (if profile allows overrides)",
                )

        # 5. Check override blocks (from safety_overrides.block)
        for block_pattern in self._override_blocks:
            if self._matches_wildcard(command, block_pattern):
                return SafetyResult(
                    allowed=False,
                    reason=f"Blocked by safety_overrides: {block_pattern}",
                    matched_pattern=block_pattern,
                    hint="Remove from safety_overrides.block",
                )

        # 6. Default: allow
        return SafetyResult(allowed=True)

    def _matches_allowlist(self, command: str) -> bool:
        """Check if command matches any allowlist pattern.

        Supports:
        - Exact matches: "git status"
        - Prefix wildcards: "git *" matches "git status", "git commit", etc.
        - Pattern wildcards: "npm run *" matches "npm run test", etc.
        """
        # Check override allows first (highest priority)
        # Note: substring_fallback=False for allowlist - require exact or wildcard match
        for pattern in self._override_allows:
            if self._matches_wildcard(command, pattern, substring_fallback=False):
                return True

        # Check standard allowed_commands
        for pattern in self.allowed_commands:
            if self._matches_wildcard(command, pattern, substring_fallback=False):
                return True

        return False

    def _matches_wildcard(
        self, command: str, pattern: str, substring_fallback: bool = True
    ) -> bool:
        """Check if command matches a wildcard pattern.

        Args:
            command: The command to check
            pattern: Pattern with optional * wildcards
            substring_fallback: If True and pattern has no wildcards, also try
                substring matching (for backward compatibility with denied_commands)

        Returns:
            True if pattern matches command
        """
        # Exact match (case-insensitive)
        if command.lower() == pattern.lower():
            return True

        # Wildcard matching
        if "*" in pattern:
            # Convert wildcard pattern to regex
            # Escape special regex chars except *
            regex_pattern = re.escape(pattern).replace(r"\*", ".*")
            regex_pattern = f"^{regex_pattern}$"
            if re.match(regex_pattern, command, re.IGNORECASE):
                return True
        elif substring_fallback:
            # No wildcards - try substring matching for backward compatibility
            if pattern.lower() in command.lower():
                return True

        return False

    def _parse_shell_commands(
        self, command: str, *, depth: int = 0, scope: str = "top_level"
    ) -> list[list[_ShellWord]]:
        """Parse every simple command, including substitutions and shell -c scripts."""
        if not command.strip():
            return []
        if depth > 10:
            raise _UnsafeShellSyntax(
                "nested shell command depth exceeds safety limit",
                stage="nesting_depth", scope=scope, depth=depth,
            )

        source = command.encode()
        root = Parser(_BASH_LANGUAGE).parse(source).root_node
        if root.has_error:
            failure = _UnsafeShellSyntax("invalid or unsupported Bash syntax")
            try:
                # Preorder over ALL children includes anonymous missing tokens.
                pending = [root]
                while pending:
                    node = pending.pop()
                    if node.type == "ERROR" or node.is_missing:
                        row, column = node.start_point
                        failure = _UnsafeShellSyntax(
                            "invalid or unsupported Bash syntax",
                            stage="tree_parse", scope=scope, depth=depth,
                            line=row + 1, byte_column=column + 1,
                            node_category="missing" if node.is_missing else "ERROR",
                        )
                        break
                    pending.extend(reversed(node.children))
            except Exception:
                # Diagnostics are best-effort; the refusal is unconditional.
                pass
            raise failure

        parsed_commands: list[list[_ShellWord]] = []
        self._collect_command_nodes(
            root, source, parsed_commands, scope=scope, depth=depth
        )

        nested_commands: list[list[_ShellWord]] = []
        for words in parsed_commands:
            effective = self._effective_command(words)
            if not effective:
                continue

            executable = self._command_basename(
                self._require_static(effective[0], "command name")
            )
            if executable in {"bash", "dash", "ksh", "sh", "zsh"}:
                script = self._shell_script_argument(effective)
                if script is not None:
                    script_value = self._require_static(script, "shell -c command")
                    nested_commands.extend(
                        self._parse_shell_commands(
                            script_value, depth=depth + 1, scope="shell_c"
                        )
                    )
            elif executable == "eval":
                arguments = effective[1:]
                values = [
                    self._require_static(argument, "eval argument")
                    for argument in arguments
                ]
                if arguments:
                    nested_commands.extend(
                        self._parse_shell_commands(
                            " ".join(values),
                            depth=depth + 1, scope="eval",
                        )
                    )

        return parsed_commands + nested_commands

    def _collect_command_nodes(
        self,
        node: Node,
        source: bytes,
        commands: list[list[_ShellWord]],
        *, scope: str = "top_level", depth: int = 0,
    ) -> None:
        if node.type == "command":
            words: list[_ShellWord] = []
            previous: Node | None = None
            for child in node.children:
                if child.type in _NON_ARGUMENT_NODES:
                    continue
                word = self._shell_word(child, source, scope=scope, depth=depth)
                # The grammar can split a word at a continuation, or expose a
                # literal $ as an anonymous sibling. Neither is an argv boundary.
                adjacent = previous is not None and not source[
                    previous.end_byte : child.start_byte
                ].replace(b"\\\n", b"")
                if adjacent:
                    locale = previous.type == "$" and child.type == "string"
                    words[-1] = self._combine_words(words[-1], word, opaque=locale)
                else:
                    words.append(word)
                previous = child
            if words:
                commands.append(words)

        for child in node.named_children:
            self._collect_command_nodes(
                child, source, commands, scope=scope, depth=depth
            )

    def _shell_word(
        self, node: Node, source: bytes, *, scope: str = "top_level", depth: int = 0
    ) -> _ShellWord:
        try:
            return self._decode_word_node(node, source)
        except ValueError:
            # Do not retain a source-bearing decoder exception as context.
            pass
        failure = _UnsafeShellSyntax(
            "cannot inspect shell word", stage="shell_word", scope=scope, depth=depth
        )
        try:
            row, column = node.start_point
            failure = _UnsafeShellSyntax(
                "cannot inspect shell word", stage="shell_word", scope=scope, depth=depth,
                line=row + 1, byte_column=column + 1,
            )
        except Exception:
            pass
        raise failure

    def _decode_word_node(self, node: Node, source: bytes) -> _ShellWord:
        """Decode only literal AST fragments; never interpret expansions."""
        kind = node.type
        if kind in _DYNAMIC_WORD_NODES:
            return _ShellWord(None, dynamic=True)
        if kind in {"ansi_c_string", "translated_string"}:
            return _ShellWord(None, opaque_quoting=True)
        text = source[node.start_byte : node.end_byte].decode()
        if kind == "raw_string":
            if not (text.startswith("'") and text.endswith("'")):
                raise ValueError("unsupported literal")
            return _ShellWord(text[1:-1])
        if kind == "string":
            if not (text.startswith('"') and text.endswith('"')):
                raise ValueError("unsupported literal")
            return self._decode_word_parts(
                node.children[1:-1], source, node.start_byte + 1,
                node.end_byte - 1, double_quoted=True,
            )
        if kind in {"command_name", "concatenation", "word", "number"}:
            # In particular a number can contain nested substitutions.
            if node.children:
                return self._decode_word_parts(
                    node.children, source, node.start_byte, node.end_byte
                )
            return self._decode_literal_fragment(text)
        if kind == "string_content":
            return self._decode_literal_fragment(text, double_quoted=True)
        if kind == "$" and text == "$":
            return _ShellWord("$")
        raise ValueError("unsupported word node")

    def _decode_word_parts(
        self, children: list[Node], source: bytes, start: int, end: int,
        *, double_quoted: bool = False,
    ) -> _ShellWord:
        result = _ShellWord("")
        previous: Node | None = None
        cursor = start
        for child in children:
            gap = source[cursor : child.start_byte].decode()
            result = self._combine_words(
                result,
                self._decode_literal_fragment(gap, double_quoted=double_quoted),
            )
            locale = (
                not double_quoted and previous is not None
                and previous.type == "$" and child.type == "string"
                and not gap.replace("\\\n", "")
            )
            result = self._combine_words(
                result, self._decode_word_node(child, source), opaque=locale
            )
            previous = child
            cursor = child.end_byte
        return self._combine_words(
            result,
            self._decode_literal_fragment(
                source[cursor:end].decode(), double_quoted=double_quoted
            ),
        )

    def _decode_literal_fragment(
        self, text: str, *, double_quoted: bool = False
    ) -> _ShellWord:
        """Remove backslashes at AST literal boundaries, not shell syntax."""
        decoded: list[str] = []
        unknown = False
        index = 0
        while index < len(text):
            char = text[index]
            if char == "\\":
                index += 1
                if index == len(text):
                    raise ValueError("incomplete escape")
                following = text[index]
                if following != "\n":
                    if double_quoted and following not in '$`"\\':
                        decoded.append("\\")
                    decoded.append(following)
            else:
                if char == '"' or (not double_quoted and char == "'"):
                    raise ValueError("unexpected quote in literal fragment")
                if not double_quoted and char in "*?[]{}~":
                    unknown = True
                decoded.append(char)
            index += 1
        return _ShellWord(None if unknown else "".join(decoded), dynamic=unknown)

    def _combine_words(
        self, left: _ShellWord, right: _ShellWord, *, opaque: bool = False
    ) -> _ShellWord:
        value = None
        if left.value is not None and right.value is not None and not opaque:
            value = left.value + right.value
        return _ShellWord(
            value,
            dynamic=left.dynamic or right.dynamic,
            opaque_quoting=opaque or left.opaque_quoting or right.opaque_quoting,
        )

    def _require_static(self, word: _ShellWord, context: str) -> str:
        # Context is always a fixed caller label, never source text.
        if word.value is None:
            raise _UnsafeShellSyntax(f"unknown {context} cannot be inspected")
        return word.value

    def _effective_command(
        self, words: list[_ShellWord]
    ) -> list[_ShellWord] | None:
        """Remove command-preserving prefixes and return the invoked command."""
        remaining = words
        while remaining:
            executable = self._command_basename(
                self._require_static(remaining[0], "command name")
            )
            if executable == "env":
                remaining = self._unwrap_env(remaining[1:])
            elif executable == "command":
                remaining = self._unwrap_command_builtin(remaining[1:])
            elif executable == "exec":
                remaining = self._unwrap_exec(remaining[1:])
            elif executable == "nohup":
                remaining = self._unwrap_simple_prefix(remaining[1:])
            elif executable == "time":
                remaining = self._unwrap_time(remaining[1:])
            elif executable in {"nice", "setsid", "stdbuf"}:
                remaining = self._unwrap_execution_wrapper(executable, remaining[1:])
            else:
                return remaining

        return None

    def _unwrap_execution_wrapper(
        self, executable: str, arguments: list[_ShellWord]
    ) -> list[_ShellWord]:
        """Inspect argv-preserving wrappers without guessing unknown options.

        Dynamic options could expand into multiple words or change where the
        invoked command starts, so restricted profiles reject that ambiguity.
        Literal data after the executable remains subject to its usual rules.
        """
        index = 0
        while index < len(arguments):
            value = self._require_static(arguments[index], "execution wrapper prefix")
            if value == "--":
                return arguments[index + 1 :]
            if value in {"--help", "--version"}:
                return []
            if not value.startswith("-") or value == "-":
                return arguments[index:]

            takes_value = False
            if executable == "nice":
                takes_value = value in {"-n", "--adjustment"}
                attached = (
                    value.startswith("--adjustment=")
                    or value.startswith("-n")
                    and len(value) > 2
                    or re.fullmatch(r"-\d+", value) is not None
                )
                known = takes_value or attached
            elif executable == "setsid":
                known = value in {"--ctty", "--fork", "--wait"} or (
                    value.startswith("-")
                    and not value.startswith("--")
                    and len(value) > 1
                    and set(value[1:]) <= set("cfw")
                )
            else:  # stdbuf: every short option consumes a buffering mode.
                takes_value = value in {
                    "-i",
                    "-o",
                    "-e",
                    "--input",
                    "--output",
                    "--error",
                }
                attached = value.startswith(("--input=", "--output=", "--error=")) or (
                    len(value) > 2 and value[:2] in {"-i", "-o", "-e"}
                )
                known = takes_value or attached
            if not known:
                raise _UnsafeShellSyntax(f"unsupported {executable} option")
            if takes_value:
                index += 1
                if index >= len(arguments):
                    raise _UnsafeShellSyntax(
                        f"{executable} option is missing its value"
                    )
                self._require_static(arguments[index], "execution wrapper option value")
            index += 1
        return []

    def _unwrap_env(self, arguments: list[_ShellWord]) -> list[_ShellWord]:
        index = 0
        options_ended = False
        while index < len(arguments):
            value = self._require_static(arguments[index], "env prefix")
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", value):
                index += 1
                continue
            if options_ended:
                break
            if value == "--":
                options_ended = True
                index += 1
                continue
            if value in {"-S", "--split-string"} or value.startswith(
                "--split-string="
            ):
                raise _UnsafeShellSyntax("env split-string command cannot be inspected")
            if value in {"-u", "--unset", "-C", "--chdir"}:
                if index + 1 >= len(arguments):
                    raise _UnsafeShellSyntax("env option is missing its value")
                self._require_static(arguments[index + 1], "env option value")
                index += 2
                continue
            if value.startswith(("--unset=", "--chdir=")):
                index += 1
                continue
            if value in {"--help", "--version"}:
                return []
            if value in {"-", "-i", "--ignore-environment", "-0", "--null", "-v", "--debug"}:
                index += 1
                continue
            if value.startswith("-"):
                raise _UnsafeShellSyntax("unsupported env option")
            break
        return arguments[index:]

    def _unwrap_command_builtin(
        self, arguments: list[_ShellWord]
    ) -> list[_ShellWord]:
        index = 0
        while index < len(arguments):
            value = self._require_static(arguments[index], "command prefix")
            if value == "--":
                index += 1
                break
            if value in {"-v", "-V"}:
                return []
            if value == "-p":
                index += 1
                continue
            if value.startswith("-"):
                raise _UnsafeShellSyntax("unsupported command option")
            break
        return arguments[index:]

    def _unwrap_exec(self, arguments: list[_ShellWord]) -> list[_ShellWord]:
        index = 0
        while index < len(arguments):
            value = self._require_static(arguments[index], "exec prefix")
            if value == "--":
                index += 1
                break
            if value == "-a":
                if index + 1 >= len(arguments):
                    raise _UnsafeShellSyntax("exec option is missing its value")
                self._require_static(arguments[index + 1], "exec option value")
                index += 2
                continue
            if value in {"-c", "-l", "-cl", "-lc"}:
                index += 1
                continue
            if value.startswith("-"):
                raise _UnsafeShellSyntax("unsupported exec option")
            break
        return arguments[index:]

    def _unwrap_simple_prefix(
        self, arguments: list[_ShellWord]
    ) -> list[_ShellWord]:
        if not arguments:
            return []
        value = self._require_static(arguments[0], "nohup prefix")
        if value == "--":
            return arguments[1:]
        if value in {"--help", "--version"}:
            return []
        if value.startswith("-"):
            raise _UnsafeShellSyntax("unsupported nohup option")
        return arguments

    def _unwrap_time(self, arguments: list[_ShellWord]) -> list[_ShellWord]:
        index = 0
        while index < len(arguments):
            value = self._require_static(arguments[index], "time prefix")
            if value == "--":
                index += 1
                break
            if value in {"-f", "--format", "-o", "--output"}:
                if index + 1 >= len(arguments):
                    raise _UnsafeShellSyntax("time option is missing its value")
                self._require_static(arguments[index + 1], "time option value")
                index += 2
                continue
            if value.startswith(("--format=", "--output=")) or (
                len(value) > 2 and value[:2] in {"-f", "-o"}
            ):
                index += 1
                continue
            if value in {"--help", "--version"}:
                return []
            if value in {"--portability", "--verbose", "--append", "--quiet"} or (
                value.startswith("-") and not value.startswith("--")
                and len(value) > 1 and set(value[1:]) <= set("pvaq")
            ):
                index += 1
                continue
            if value.startswith("-"):
                raise _UnsafeShellSyntax("unsupported time option")
            break
        return arguments[index:]

    def _shell_script_argument(
        self, words: list[_ShellWord]
    ) -> _ShellWord | None:
        index = 1
        while index < len(words):
            value = self._require_static(words[index], "shell option or script path")
            if value == "--":
                return None
            if value in {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}:
                if index + 1 >= len(words):
                    raise _UnsafeShellSyntax("shell option is missing its value")
                self._require_static(words[index + 1], "shell option value")
                index += 2
                continue
            if (
                value.startswith(("-", "+"))
                and not value.startswith("--")
                and any(flag in value[1:] for flag in ("o", "O"))
            ):
                raise _UnsafeShellSyntax(
                    "combined shell option with a value cannot be inspected"
                )
            if value.startswith("--"):
                if value not in {
                    "--debugger", "--dump-po-strings", "--dump-strings", "--help",
                    "--login", "--noediting", "--noprofile", "--norc", "--posix",
                    "--pretty-print", "--restricted", "--verbose", "--version",
                }:
                    raise _UnsafeShellSyntax("unsupported shell option")
            elif value.startswith(("-", "+")) and (
                len(value) < 2 or not set(value[1:]) <= set("abBceCDEfhHiklmnpPrstTuvx")
            ):
                raise _UnsafeShellSyntax("unsupported shell option")
            if value == "-c" or (
                value.startswith("-")
                and not value.startswith("--")
                and "c" in value[1:]
            ):
                if index + 1 >= len(words):
                    raise _UnsafeShellSyntax("shell -c is missing its command string")
                return words[index + 1]
            if not value.startswith(("-", "+")):
                return None
            index += 1
        return None

    def _check_pattern(
        self,
        command: str,
        pattern: BlockPattern,
        parsed_commands: list[list[_ShellWord]],
    ) -> bool:
        """Check if a pattern matches the command using appropriate strategy.

        Args:
            command: The command to check
            pattern: The BlockPattern to match against

        Returns:
            True if pattern matches (command should be blocked)
        """
        if pattern.check_type == "substring":
            return self._check_substring(command, pattern.pattern)
        elif pattern.check_type == "command":
            return self._check_command_position(parsed_commands, pattern.pattern)
        elif pattern.check_type == "regex":
            return self._check_regex(command, pattern.pattern)
        else:
            # Unknown check type, fall back to substring
            return self._check_substring(command, pattern.pattern)

    def _check_substring(self, command: str, pattern: str) -> bool:
        """Simple case-insensitive substring match.

        Args:
            command: The command to check
            pattern: The substring to find

        Returns:
            True if pattern is found in command
        """
        return pattern.lower() in command.lower()

    def _check_command_position(
        self, commands: list[list[_ShellWord]], pattern: str
    ) -> bool:
        """Match a blocked command against syntax-aware effective commands."""
        pattern_words = shlex.split(pattern)
        if not pattern_words:
            return False

        for words in commands:
            effective = self._effective_command(words)
            if not effective:
                continue

            if pattern_words[0] == "rm" and len(pattern_words) == 3:
                if self._matches_dangerous_rm(effective, pattern_words[2]):
                    return True
                continue

            actual_executable = self._command_basename(
                self._require_static(effective[0], "command name")
            )
            expected_executable = self._command_basename(pattern_words[0])
            executable_matches = actual_executable == expected_executable
            if expected_executable == "mkfs":
                executable_matches = executable_matches or actual_executable.startswith(
                    "mkfs."
                )
            if not executable_matches:
                continue

            actual_arguments = [
                self._require_static(word, "blocked command argument").lower()
                for word in effective[1 : len(pattern_words)]
            ]
            # An unknown expansion could change argv length, so require known
            # compared arguments before ruling out a longer blocked pattern.
            if len(effective) < len(pattern_words):
                continue
            expected_arguments = [word.lower() for word in pattern_words[1:]]
            if actual_arguments == expected_arguments:
                return True

        return False

    def _matches_dangerous_rm(
        self, words: list[_ShellWord], blocked_target: str
    ) -> bool:
        if self._command_basename(self._require_static(words[0], "command name")) != "rm":
            return False

        recursive = False
        force = False
        operands: list[str] = []
        options_ended = False
        for word in words[1:]:
            # Every rm argument is critical, including flags and words after --.
            value = self._require_static(word, "rm argument")
            if not options_ended and value == "--":
                options_ended = True
                continue
            if not options_ended and value.startswith("--"):
                option = value.split("=", 1)[0]
                recursive = recursive or option == "--recursive"
                force = force or option == "--force"
                continue
            if not options_ended and value.startswith("-") and value != "-":
                flags = value[1:]
                recursive = recursive or "r" in flags or "R" in flags
                force = force or "f" in flags
                continue
            operands.append(value)

        if not (recursive and force):
            return False
        if blocked_target == "/":
            return any(self._is_root_path(operand) for operand in operands)
        if blocked_target == "~":
            return any(self._is_home_path(operand) for operand in operands)
        return False

    def _is_root_path(self, value: str) -> bool:
        if not value.startswith("/"):
            return False
        return posixpath.normpath("/" + value.lstrip("/")) == "/"

    def _is_home_path(self, value: str) -> bool:
        for prefix in ("~", "$HOME", "${HOME}"):
            if value == prefix:
                return True
            if value.startswith(prefix + "/"):
                suffix = value[len(prefix) + 1 :]
                return posixpath.normpath(suffix or ".") == "."
        return False

    def _command_basename(self, value: str) -> str:
        return value.rsplit("/", 1)[-1].lower()

    def _check_regex(self, command: str, pattern: str) -> bool:
        """Check if regex pattern matches the command.

        The regex is searched anywhere in the command, but patterns
        can be written to be position-aware (e.g., using ^ for start).

        Args:
            command: The command to check
            pattern: The regex pattern to match

        Returns:
            True if pattern matches
        """
        try:
            # Use search, not match, to find pattern anywhere
            return bool(re.search(pattern, command))
        except re.error:
            # Invalid regex, treat as no match
            return False
