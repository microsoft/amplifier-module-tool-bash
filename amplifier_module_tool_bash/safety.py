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
    "command_substitution",
    "expansion",
    "process_substitution",
    "simple_expansion",
}
_NON_ARGUMENT_NODES = {
    "comment",
    "file_redirect",
    "heredoc_redirect",
    "variable_assignment",
}


@dataclass(frozen=True)
class _ShellWord:
    value: str
    dynamic: bool = False


class _UnsafeShellSyntax(ValueError):
    """Raised when a restricted profile cannot safely inspect a command."""


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
        except _UnsafeShellSyntax as exc:
            return SafetyResult(
                allowed=False,
                reason=f"Unable to safely analyze Bash syntax: {exc}",
                matched_pattern="<unsupported bash syntax>",
                hint="Use safety_profile: 'unrestricted' only in a trusted container/VM environment",
            )

        # 3. Check blocked patterns with smart matching
        for pattern in self.profile.blocked_patterns:
            if self._check_pattern(command, pattern, parsed_commands):
                return SafetyResult(
                    allowed=False,
                    reason=pattern.reason,
                    matched_pattern=pattern.pattern,
                    hint="Use safety_profile: 'permissive' or 'unrestricted' for container/VM environments",
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
        self, command: str, *, depth: int = 0
    ) -> list[list[_ShellWord]]:
        """Parse every simple command, including substitutions and shell -c scripts."""
        if not command.strip():
            return []
        if depth > 10:
            raise _UnsafeShellSyntax("nested shell command depth exceeds safety limit")

        source = command.encode()
        root = Parser(_BASH_LANGUAGE).parse(source).root_node
        if root.has_error:
            raise _UnsafeShellSyntax("invalid or unsupported Bash syntax")

        parsed_commands: list[list[_ShellWord]] = []
        self._collect_command_nodes(root, source, parsed_commands)

        nested_commands: list[list[_ShellWord]] = []
        for words in parsed_commands:
            effective = self._effective_command(words)
            if not effective:
                continue

            executable = self._command_basename(effective[0].value)
            if executable in {"bash", "dash", "ksh", "sh", "zsh"}:
                script = self._shell_script_argument(effective)
                if script is not None:
                    if script.dynamic:
                        raise _UnsafeShellSyntax(
                            "dynamic shell -c command cannot be inspected"
                        )
                    nested_commands.extend(
                        self._parse_shell_commands(script.value, depth=depth + 1)
                    )
            elif executable == "eval":
                arguments = effective[1:]
                if any(argument.dynamic for argument in arguments):
                    raise _UnsafeShellSyntax(
                        "dynamic eval command cannot be inspected"
                    )
                if arguments:
                    nested_commands.extend(
                        self._parse_shell_commands(
                            " ".join(argument.value for argument in arguments),
                            depth=depth + 1,
                        )
                    )

        return parsed_commands + nested_commands

    def _collect_command_nodes(
        self,
        node: Node,
        source: bytes,
        commands: list[list[_ShellWord]],
    ) -> None:
        if node.type == "command":
            words: list[_ShellWord] = []
            for child in node.named_children:
                if child.type in _NON_ARGUMENT_NODES:
                    continue
                words.append(self._shell_word(child, source))
            if words:
                commands.append(words)

        for child in node.named_children:
            self._collect_command_nodes(child, source, commands)

    def _shell_word(self, node: Node, source: bytes) -> _ShellWord:
        text = source[node.start_byte : node.end_byte].decode()
        try:
            parsed = shlex.split(text)
        except ValueError as exc:
            raise _UnsafeShellSyntax(f"cannot inspect shell word: {exc}") from exc

        value = parsed[0] if len(parsed) == 1 else text
        dynamic = node.type in _DYNAMIC_WORD_NODES or any(
            descendant.type in _DYNAMIC_WORD_NODES
            for descendant in self._descendants(node)
        )
        return _ShellWord(value=value, dynamic=dynamic)

    def _descendants(self, node: Node) -> list[Node]:
        descendants: list[Node] = []
        pending = list(node.named_children)
        while pending:
            child = pending.pop()
            descendants.append(child)
            pending.extend(child.named_children)
        return descendants

    def _effective_command(
        self, words: list[_ShellWord]
    ) -> list[_ShellWord] | None:
        """Remove command-preserving prefixes and return the invoked command."""
        remaining = words
        while remaining:
            if remaining[0].dynamic:
                raise _UnsafeShellSyntax("dynamic command name cannot be inspected")

            executable = self._command_basename(remaining[0].value)
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
            else:
                return remaining

        return None

    def _unwrap_env(self, arguments: list[_ShellWord]) -> list[_ShellWord]:
        index = 0
        while index < len(arguments):
            value = arguments[index].value
            if value == "--":
                index += 1
                break
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", value):
                index += 1
                continue
            if value in {"-S", "--split-string"} or value.startswith(
                "--split-string="
            ):
                raise _UnsafeShellSyntax("env split-string command cannot be inspected")
            if value in {"-u", "--unset", "-C", "--chdir"}:
                index += 2
                continue
            if value.startswith(("--unset=", "--chdir=")):
                index += 1
                continue
            if value.startswith("-") and value != "-":
                index += 1
                continue
            break
        return arguments[index:]

    def _unwrap_command_builtin(
        self, arguments: list[_ShellWord]
    ) -> list[_ShellWord]:
        index = 0
        while index < len(arguments):
            value = arguments[index].value
            if value == "--":
                index += 1
                break
            if value in {"-v", "-V"}:
                return []
            if value == "-p":
                index += 1
                continue
            break
        return arguments[index:]

    def _unwrap_exec(self, arguments: list[_ShellWord]) -> list[_ShellWord]:
        index = 0
        while index < len(arguments):
            value = arguments[index].value
            if value == "--":
                index += 1
                break
            if value == "-a":
                index += 2
                continue
            if value.startswith("-") and value != "-":
                index += 1
                continue
            break
        return arguments[index:]

    def _unwrap_simple_prefix(
        self, arguments: list[_ShellWord]
    ) -> list[_ShellWord]:
        if arguments and arguments[0].value == "--":
            return arguments[1:]
        if arguments and arguments[0].value in {"--help", "--version"}:
            return []
        return arguments

    def _unwrap_time(self, arguments: list[_ShellWord]) -> list[_ShellWord]:
        index = 0
        while index < len(arguments):
            value = arguments[index].value
            if value == "--":
                index += 1
                break
            if value in {"-f", "--format", "-o", "--output"}:
                index += 2
                continue
            if value.startswith(("--format=", "--output=")):
                index += 1
                continue
            if value.startswith("-") and value != "-":
                index += 1
                continue
            break
        return arguments[index:]

    def _shell_script_argument(
        self, words: list[_ShellWord]
    ) -> _ShellWord | None:
        for index, argument in enumerate(words[1:], start=1):
            value = argument.value
            if value == "--":
                continue
            if value == "-c" or (
                value.startswith("-")
                and not value.startswith("--")
                and "c" in value[1:]
            ):
                if index + 1 >= len(words):
                    raise _UnsafeShellSyntax("shell -c is missing its command string")
                return words[index + 1]
            if not value.startswith("-"):
                return None
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

            if len(effective) < len(pattern_words):
                continue

            actual_executable = self._command_basename(effective[0].value)
            expected_executable = self._command_basename(pattern_words[0])
            executable_matches = actual_executable == expected_executable
            if expected_executable == "mkfs":
                executable_matches = executable_matches or actual_executable.startswith(
                    "mkfs."
                )
            if not executable_matches:
                continue

            actual_arguments = [
                word.value.lower() for word in effective[1 : len(pattern_words)]
            ]
            expected_arguments = [word.lower() for word in pattern_words[1:]]
            if actual_arguments == expected_arguments:
                return True

        return False

    def _matches_dangerous_rm(
        self, words: list[_ShellWord], blocked_target: str
    ) -> bool:
        if self._command_basename(words[0].value) != "rm":
            return False

        recursive = False
        force = False
        operands: list[str] = []
        options_ended = False
        for word in words[1:]:
            value = word.value
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
