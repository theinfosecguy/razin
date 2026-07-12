"""Bounded whole-package analysis for agent skills.

This module never imports or executes package code. It hashes files, parses Python
with the standard-library AST, and applies conservative lexical correlations to
JavaScript, TypeScript, and shell helpers.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import warnings
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from razin.config import RazinConfig
from razin.constants.package_analysis import (
    ANALYZED_SCRIPT_SUFFIXES,
    ARCHIVE_SUFFIXES,
    IGNORED_PACKAGE_DIRECTORIES,
    MANIFEST_FILENAMES,
    PACKAGE_COVERAGE_DIGEST_VERSION,
    SUSPICIOUS_COLLECTION_DOMAINS,
    TEXT_SUFFIXES,
    UNSUPPORTED_EXECUTABLE_SUFFIXES,
    UNSUPPORTED_SOURCE_SUFFIXES,
)
from razin.model import Evidence, FindingCandidate

_URL_RE = re.compile(r"https?://[^\s<>()\[\]{}'\"`]+", re.IGNORECASE)
_REMOTE_PIPE_RE = re.compile(
    r"\b(?:curl\b[^|\n]*|wget\b[^|\n]*)\|\s*(?:sudo\s+)?(?:ba)?sh\b",
    re.IGNORECASE,
)
_CREDENTIAL_ENV_KEY_RE = re.compile(
    r"(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_?KEY|AUTH)(?:_|$)",
    re.IGNORECASE,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|[/\\'\"])(?:\.env(?:\.[^/\\'\"]+)?|\.netrc|id_(?:rsa|dsa|ecdsa|ed25519)|credentials|"
    r"\.aws[/\\]credentials|\.ssh[/\\]|kubeconfig|\.docker[/\\]config\.json)(?:$|[/\\'\"])",
    re.IGNORECASE,
)
_REMOTE_SOURCE_RE = re.compile(
    r"(?:\bfetch\s*\(|\baxios\.(?:get|request)\s*\(|\brequests?\.get\s*\(|\bhttpx\.get\s*\(|\bcurl\b|\bwget\b)",
    re.IGNORECASE,
)
_NETWORK_SINK_RE = re.compile(
    r"(?:\bfetch\s*\(|\baxios\.(?:post|put|patch|request)\s*\(|\brequests?\.(?:post|put|patch|request)\s*\(|\bhttpx\.(?:post|put|patch|request)\s*\(|\bhttps?\.request\s*\(|\b(?:curl|wget|nc|netcat)\b)",
    re.IGNORECASE,
)
_EXECUTION_SINK_RE = re.compile(
    r"(?:(?<!\.)\b(?:eval|exec)\s*\(|\bchild_process\.(?:exec|spawn)\s*\(|\b(?:exec|spawn)Sync\s*\(|\bsubprocess\.(?:run|Popen|call|check_output)\s*\(|\bos\.system\s*\(|\beval\s+|\b(?:ba)?sh\s+-c\b)",
    re.IGNORECASE,
)
_ASSIGNMENT_RE = re.compile(r"^\s*(?:(?:const|let|var|export)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+)$")
_SHELL_ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
_SHELL_SENSITIVE_RE = re.compile(
    r"(?:\$\{?[A-Za-z_]*(?:TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL)[A-Za-z_]*\}?|\b(?:cat|source|\.)\s+[^\n]*(?:\.env|\.ssh/|\.aws/|credentials))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PackageManifestEntry:
    """Hashed package member used to produce the package digest."""

    path: str
    size: int
    sha256: str | None
    mode: int | None


@dataclass(frozen=True)
class PackageAnalysisResult:
    """Candidates and deterministic provenance for one skill package."""

    candidates: tuple[FindingCandidate, ...]
    package_sha256: str
    manifest: tuple[PackageManifestEntry, ...]
    analyzed_helpers: int
    coverage_complete: bool
    coverage_markers: tuple[str, ...]


@dataclass(frozen=True)
class _TextFile:
    path: Path
    relative_path: str
    text: str
    sha256: str


@dataclass(frozen=True)
class _FlowSignal:
    variable: str
    line: int
    snippet: str
    destination: str | None = None
    scope: str = "module"


def analyze_skill_package(
    *,
    skill_path: Path,
    skill_text: str,
    config: RazinConfig,
    active_rule_ids: frozenset[str] | None = None,
    excluded_paths: tuple[Path, ...] = (),
) -> PackageAnalysisResult:
    """Analyze a skill directory without executing package content."""
    package_root = skill_path.resolve().parent
    analysis = config.package_analysis
    if not analysis.enabled:
        return PackageAnalysisResult(
            candidates=(),
            package_sha256="",
            manifest=(),
            analyzed_helpers=0,
            coverage_complete=False,
            coverage_markers=("package-analysis-disabled",),
        )

    allowed = active_rule_ids
    candidates: list[FindingCandidate] = []
    manifest: list[PackageManifestEntry] = []
    text_files: list[_TextFile] = []
    total_bytes = 0
    truncated_files = False
    truncated_bytes = False
    truncated_directories = False
    dynamic_members: set[str] = set()
    max_total_bytes = analysis.max_total_mb * 1024 * 1024
    max_file_bytes = analysis.max_file_mb * 1024 * 1024

    paths, enumeration_truncated, truncated_directories, ignored_directories = _bounded_package_paths(
        package_root,
        analysis.max_files,
        analysis.max_directories,
        excluded_paths,
    )
    if enumeration_truncated:
        truncated_files = True

    for path in paths:
        relative = path.relative_to(package_root).as_posix()
        if path.is_symlink():
            try:
                mode = path.lstat().st_mode & 0o7777
            except OSError:
                mode = None
            manifest.append(PackageManifestEntry(relative, 0, None, mode))
            _append_candidate(
                candidates,
                _gap_candidate(skill_path, relative, "Symbolic link target was not followed."),
                allowed,
                analysis.max_findings_per_rule,
            )
            continue
        try:
            stat = path.stat()
        except OSError as exc:
            manifest.append(PackageManifestEntry(relative, 0, None, None))
            _append_candidate(
                candidates,
                _gap_candidate(skill_path, relative, f"File metadata could not be read: {exc}"),
                allowed,
                analysis.max_findings_per_rule,
            )
            continue

        size = stat.st_size
        if total_bytes + size > max_total_bytes:
            truncated_bytes = True
            break
        total_bytes += size
        if size > max_file_bytes:
            manifest.append(PackageManifestEntry(relative, size, None, stat.st_mode & 0o7777))
            _append_candidate(
                candidates,
                _gap_candidate(
                    skill_path,
                    relative,
                    f"File size {size} bytes exceeds package_analysis.max_file_mb={analysis.max_file_mb}.",
                ),
                allowed,
                analysis.max_findings_per_rule,
            )
            continue

        try:
            data = path.read_bytes()
        except OSError as exc:
            manifest.append(PackageManifestEntry(relative, size, None, stat.st_mode & 0o7777))
            _append_candidate(
                candidates,
                _gap_candidate(skill_path, relative, f"File could not be read: {exc}"),
                allowed,
                analysis.max_findings_per_rule,
            )
            continue

        digest = hashlib.sha256(data).hexdigest()
        manifest.append(PackageManifestEntry(relative, size, digest, stat.st_mode & 0o7777))
        _match_bad_hash(candidates, path, relative, digest, config, allowed)

        lower_name = relative.lower()
        if lower_name.endswith(ARCHIVE_SUFFIXES):
            dynamic_members.add(relative)
            _append_candidate(
                candidates,
                _dynamic_candidate(path, relative, "Archive contents are not unpacked or analyzed."),
                allowed,
                analysis.max_findings_per_rule,
            )
            continue

        suffix = path.suffix.lower()
        if suffix in UNSUPPORTED_EXECUTABLE_SUFFIXES:
            dynamic_members.add(relative)
            _append_candidate(
                candidates,
                _dynamic_candidate(path, relative, "Compiled executable content requires isolated dynamic analysis."),
                allowed,
                analysis.max_findings_per_rule,
            )
            continue

        text = _decode_text(data)
        if text is None:
            if suffix not in _known_media_suffixes():
                dynamic_members.add(relative)
                _append_candidate(
                    candidates,
                    _dynamic_candidate(
                        path, relative, "Binary content is not supported by the static helper analyzers."
                    ),
                    allowed,
                    analysis.max_findings_per_rule,
                )
            continue
        if suffix == "" and stat.st_mode & 0o111:
            dynamic_members.add(relative)
            _append_candidate(
                candidates,
                _dynamic_candidate(
                    path,
                    relative,
                    "Extensionless executable text requires explicit language analysis or isolated execution.",
                ),
                allowed,
                analysis.max_findings_per_rule,
            )
        elif suffix in UNSUPPORTED_SOURCE_SUFFIXES or (suffix not in TEXT_SUFFIXES and stat.st_mode & 0o111):
            dynamic_members.add(relative)
            _append_candidate(
                candidates,
                _dynamic_candidate(path, relative, "Executable text uses an unsupported language or file type."),
                allowed,
                analysis.max_findings_per_rule,
            )
        text_files.append(_TextFile(path, relative, text, digest))

    if truncated_files:
        _append_candidate(
            candidates,
            _gap_candidate(
                skill_path,
                skill_path.name,
                f"Package enumeration stopped at package_analysis.max_files={analysis.max_files}.",
            ),
            allowed,
            analysis.max_findings_per_rule,
        )
    if truncated_bytes:
        _append_candidate(
            candidates,
            _gap_candidate(
                skill_path,
                skill_path.name,
                f"Package reading stopped at package_analysis.max_total_mb={analysis.max_total_mb}.",
            ),
            allowed,
            analysis.max_findings_per_rule,
        )
    if truncated_directories:
        _append_candidate(
            candidates,
            _gap_candidate(
                skill_path,
                skill_path.name,
                f"Package traversal stopped at package_analysis.max_directories={analysis.max_directories}.",
            ),
            allowed,
            analysis.max_findings_per_rule,
        )

    ignored_references = tuple(
        sorted(
            {
                *_ignored_package_references(skill_text),
                *(reference for text_file in text_files for reference in _ignored_package_references(text_file.text)),
            }
        )
    )
    dynamic_members.update(
        text_file.relative_path
        for text_file in text_files
        if text_file.path.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
        and any(len(line) > 2000 for line in text_file.text.splitlines())
    )
    for ignored_reference in ignored_references:
        _append_candidate(
            candidates,
            _gap_candidate(
                skill_path,
                ignored_reference,
                "Instructions or analyzed helpers reference executable content under an excluded dependency "
                "or environment directory.",
            ),
            allowed,
            analysis.max_findings_per_rule,
        )

    referenced = _referenced_helper_lines(skill_text, text_files)
    analyzed_helpers = 0
    helper_coverage_markers: list[str] = []
    for text_file in text_files:
        _match_known_text_iocs(candidates, text_file, config, allowed)
        _match_mutable_references(candidates, text_file, config, allowed)
        if text_file.path.suffix.lower() not in ANALYZED_SCRIPT_SUFFIXES:
            continue
        analyzed_helpers += 1
        declaration_line = referenced.get(text_file.relative_path) or referenced.get(text_file.path.name)
        helper_coverage_markers.extend(_analyze_helper(candidates, text_file, declaration_line, config, allowed))

    coverage_markers = tuple(
        marker
        for marker, present in (
            ("file-limit", truncated_files),
            ("byte-limit", truncated_bytes),
            ("directory-limit", truncated_directories),
        )
        if present
    ) + tuple(f"ignored-reference:{reference}" for reference in ignored_references)
    coverage_markers += tuple(f"ignored-directory:{path}" for path in ignored_directories)
    coverage_markers += tuple(f"dynamic-analysis:{path}" for path in sorted(dynamic_members))
    coverage_markers += tuple(sorted(helper_coverage_markers))
    coverage_markers += tuple(f"unhashed-member:{entry.path}" for entry in manifest if entry.sha256 is None)
    coverage_markers = tuple(sorted(set(coverage_markers)))
    coverage_complete = not coverage_markers
    package_sha256 = _manifest_digest(manifest, coverage_complete, coverage_markers)
    if analysis.emit_inventory and _is_allowed("PACKAGE_INVENTORY", allowed):
        manifests = sorted(entry.path for entry in manifest if Path(entry.path).name.lower() in MANIFEST_FILENAMES)
        candidates.append(
            FindingCandidate(
                rule_id="PACKAGE_INVENTORY",
                score=0,
                confidence="high",
                title="Package provenance inventory",
                description=(
                    f"Coverage digest v{PACKAGE_COVERAGE_DIGEST_VERSION} for {len(manifest)} package files is "
                    f"SHA-256 {package_sha256} (complete={str(coverage_complete).lower()}); "
                    f"statically analyzed {analyzed_helpers} helper scripts. "
                    f"Dependency manifests: {', '.join(manifests) if manifests else 'none'}."
                ),
                evidence=Evidence(path=str(skill_path), line=1, snippet=skill_path.name),
                recommendation=(
                    "Store this digest with the reviewed package and compare it before installation or execution."
                ),
                classification="informational",
            )
        )

    return PackageAnalysisResult(
        candidates=tuple(candidates),
        package_sha256=package_sha256,
        manifest=tuple(manifest),
        analyzed_helpers=analyzed_helpers,
        coverage_complete=coverage_complete,
        coverage_markers=coverage_markers,
    )


def incomplete_skill_candidate(path: Path, reason: str) -> FindingCandidate:
    """Create a first-class analysis-gap candidate for an unreadable SKILL.md."""
    return FindingCandidate(
        rule_id="INCOMPLETE_SCAN",
        score=0,
        confidence="high",
        title="Skill analysis incomplete",
        description=reason,
        evidence=Evidence(path=str(path), line=None, snippet=path.name),
        recommendation=(
            "Treat the package as unassessed until every SKILL.md can be parsed and all limits are resolved."
        ),
        classification="informational",
    )


def _bounded_package_paths(
    root: Path,
    max_files: int,
    max_directories: int,
    excluded_paths: tuple[Path, ...],
) -> tuple[list[Path], bool, bool, tuple[str, ...]]:
    paths: list[Path] = []
    truncated = False
    directory_count = 0
    ignored_directories: set[str] = set()
    excluded = tuple(
        path.resolve() for path in excluded_paths if path.resolve() != root.resolve() and _is_within(path, root)
    )
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if any(_is_within(current_path, excluded_path) for excluded_path in excluded):
            dirnames[:] = []
            continue
        directory_count += 1
        if directory_count > max_directories:
            return paths, truncated, True, tuple(sorted(ignored_directories))
        symlinked_dirs = sorted(name for name in dirnames if (current_path / name).is_symlink())
        paths.extend(current_path / name for name in symlinked_dirs)
        if len(paths) > max_files:
            return paths[:max_files], True, False, tuple(sorted(ignored_directories))
        ignored_directories.update(
            (current_path / name).relative_to(root).as_posix()
            for name in dirnames
            if name in IGNORED_PACKAGE_DIRECTORIES
        )
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in IGNORED_PACKAGE_DIRECTORIES
            and name not in symlinked_dirs
            and not any(_is_within(current_path / name, excluded_path) for excluded_path in excluded)
        )
        filenames.sort()
        if current_path != root and "SKILL.md" in filenames:
            dirnames[:] = []
            continue
        for filename in filenames:
            file_path = current_path / filename
            if any(_is_within(file_path, excluded_path) for excluded_path in excluded):
                continue
            paths.append(file_path)
            if len(paths) > max_files:
                truncated = True
                return paths[:max_files], truncated, False, tuple(sorted(ignored_directories))
    return paths, truncated, False, tuple(sorted(ignored_directories))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent)
    except ValueError:
        return False
    return True


def _decode_text(data: bytes) -> str | None:
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _known_media_suffixes() -> frozenset[str]:
    return frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".mp3", ".mp4", ".mov"})


def _manifest_digest(
    entries: list[PackageManifestEntry],
    coverage_complete: bool,
    coverage_markers: tuple[str, ...],
) -> str:
    hasher = hashlib.sha256()
    hasher.update(f"razin-package-coverage-v{PACKAGE_COVERAGE_DIGEST_VERSION}\n".encode("ascii"))
    hasher.update(f"complete={str(coverage_complete).lower()}\n".encode("ascii"))
    for marker in sorted(coverage_markers):
        hasher.update(f"marker={marker}\n".encode())
    for entry in sorted(entries, key=lambda item: item.path):
        hasher.update(entry.path.encode("utf-8", errors="surrogateescape"))
        hasher.update(b"\0")
        hasher.update(str(entry.size).encode("ascii"))
        hasher.update(b"\0")
        hasher.update((entry.sha256 or "UNREAD").encode("ascii"))
        hasher.update(b"\0")
        hasher.update(str(entry.mode if entry.mode is not None else "UNKNOWN").encode("ascii"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def _ignored_package_references(skill_text: str) -> tuple[str, ...]:
    ignored = "|".join(re.escape(name) for name in sorted(IGNORED_PACKAGE_DIRECTORIES))
    pattern = re.compile(rf"(?<![\w.-])((?:{ignored})/[A-Za-z0-9_./-]+)")
    return tuple(sorted({match.group(1).rstrip(".,;:") for match in pattern.finditer(skill_text)}))


def _referenced_helper_lines(skill_text: str, files: list[_TextFile]) -> dict[str, int]:
    references: dict[str, int] = {}
    helper_names = {
        item.relative_path: item.path.name for item in files if item.path.suffix.lower() in ANALYZED_SCRIPT_SUFFIXES
    }
    for number, line in enumerate(skill_text.splitlines(), start=1):
        for relative, basename in helper_names.items():
            if relative in line or re.search(rf"(?<![\w.-]){re.escape(basename)}(?![\w.-])", line):
                references.setdefault(relative, number)
                references.setdefault(basename, number)
    return references


def _analyze_helper(
    candidates: list[FindingCandidate],
    text_file: _TextFile,
    declaration_line: int | None,
    config: RazinConfig,
    allowed: frozenset[str] | None,
) -> tuple[str, ...]:
    suffix = text_file.path.suffix.lower()
    if suffix == ".py":
        try:
            sensitive, remote, network, execution = _python_signals(text_file.text)
        except SyntaxError as exc:
            _append_candidate(
                candidates,
                FindingCandidate(
                    rule_id="INCOMPLETE_SCAN",
                    score=0,
                    confidence="high",
                    title="Helper analysis incomplete",
                    description=f"Python AST parsing failed for {text_file.relative_path}: {exc.msg}.",
                    evidence=Evidence(
                        path=str(text_file.path), line=exc.lineno, snippet=exc.text.strip() if exc.text else ""
                    ),
                    recommendation="Fix or separately inspect the helper before trusting the package.",
                    classification="informational",
                ),
                allowed,
                config.package_analysis.max_findings_per_rule,
            )
            return (f"python-parse:{text_file.relative_path}",)
    elif suffix in {".sh", ".bash", ".zsh"}:
        sensitive, remote, network, execution = _lexical_signals(text_file.text, shell=True)
    else:
        if any(len(line) > 2000 for line in text_file.text.splitlines()):
            _append_candidate(
                candidates,
                _dynamic_candidate(
                    text_file.path,
                    text_file.relative_path,
                    "Minified or packed script lines exceed the static correlation bound.",
                ),
                allowed,
                config.package_analysis.max_findings_per_rule,
            )
            return (f"dynamic-analysis:{text_file.relative_path}",)
        sensitive, remote, network, execution = _lexical_signals(text_file.text, shell=False)

    _emit_flow_correlations(
        candidates,
        text_file,
        declaration_line,
        sensitive,
        remote,
        network,
        execution,
        config,
        allowed,
    )
    _match_remote_pipe(candidates, text_file, declaration_line, config, allowed)
    if suffix in {".sh", ".bash", ".zsh"}:
        _match_shell_download_then_execute(candidates, text_file, declaration_line, config, allowed)
    return ()


def _python_signals(
    text: str,
) -> tuple[list[_FlowSignal], list[_FlowSignal], list[_FlowSignal], list[_FlowSignal]]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(text)
    sensitive: list[_FlowSignal] = []
    remote: list[_FlowSignal] = []
    network: list[_FlowSignal] = []
    execution: list[_FlowSignal] = []
    lines = text.splitlines()
    aliases = _python_aliases(tree)
    wrappers = _python_wrapper_summaries(tree, aliases)
    function_ranges = [
        (node.lineno, node.end_lineno or node.lineno, f"{node.name}@{node.lineno}")
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    assignments = sorted(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and node.value is not None
        ),
        key=lambda item: (item.lineno, item.col_offset),
    )
    sensitive_names_by_scope: dict[str, set[str]] = {}
    remote_names_by_scope: dict[str, set[str]] = {}
    taint_history_by_scope: dict[str, dict[str, list[tuple[int, int, bool, bool]]]] = {}
    for node in assignments:
        value = node.value
        if value is None:
            continue
        variables = _assigned_names(node)
        used_names = {child.id for child in ast.walk(value) if isinstance(child, ast.Name)}
        scope = _python_scope_for_line(node.lineno, function_ranges)
        sensitive_names = sensitive_names_by_scope.setdefault(scope, set())
        remote_names = remote_names_by_scope.setdefault(scope, set())
        for variable in variables:
            signal = _FlowSignal(variable, node.lineno, _line(lines, node.lineno), scope=scope)
            if _python_sensitive_source(value, aliases) or sensitive_names.intersection(used_names):
                sensitive.append(signal)
                sensitive_names.add(variable)
            else:
                sensitive_names.discard(variable)
            if _python_remote_source(value, aliases) or remote_names.intersection(used_names):
                remote.append(signal)
                remote_names.add(variable)
            else:
                remote_names.discard(variable)
            taint_history_by_scope.setdefault(scope, {}).setdefault(variable, []).append(
                (node.lineno, node.col_offset, variable in sensitive_names, variable in remote_names)
            )

    remote_written_paths_by_scope: dict[str, dict[str, _FlowSignal]] = {}
    calls = sorted(
        (node for node in ast.walk(tree) if isinstance(node, ast.Call)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for call_node in calls:
        scope = _python_scope_for_line(call_node.lineno, function_ranges)
        sensitive_names, remote_names = _python_taint_at_point(
            taint_history_by_scope.get(scope, {}), call_node.lineno, call_node.col_offset
        )
        remote_written_paths = remote_written_paths_by_scope.setdefault(scope, {})
        canonical = _python_canonical_name(call_node.func, aliases)
        payloads, destination = _python_network_payloads(call_node, canonical)
        if payloads:
            payload_names = {
                child.id for payload in payloads for child in ast.walk(payload) if isinstance(child, ast.Name)
            }
            for variable in sorted(payload_names & sensitive_names):
                network.append(
                    _FlowSignal(variable, call_node.lineno, _line(lines, call_node.lineno), destination, scope)
                )
            if not payload_names.intersection(sensitive_names) and any(
                _python_sensitive_source(payload, aliases) for payload in payloads
            ):
                direct = _FlowSignal("*DIRECT*", call_node.lineno, _line(lines, call_node.lineno), destination, scope)
                sensitive.append(direct)
                network.append(direct)

        wrapper = wrappers.get(canonical)
        if wrapper is not None:
            for index, sink_kind, wrapper_destination in wrapper:
                if index >= len(call_node.args):
                    continue
                argument_names = {child.id for child in ast.walk(call_node.args[index]) if isinstance(child, ast.Name)}
                for variable in sorted(argument_names):
                    if sink_kind == "network" and variable in sensitive_names:
                        network.append(
                            _FlowSignal(
                                variable,
                                call_node.lineno,
                                _line(lines, call_node.lineno),
                                wrapper_destination,
                                scope,
                            )
                        )
                    if sink_kind == "execution" and variable in remote_names:
                        execution.append(
                            _FlowSignal(variable, call_node.lineno, _line(lines, call_node.lineno), scope=scope)
                        )

        written_path = _python_written_path(call_node, canonical, remote_names)
        if written_path is not None:
            remote_written_paths[written_path] = _FlowSignal(
                f"@path:{written_path}", call_node.lineno, _line(lines, call_node.lineno), scope=scope
            )

        for variable in _python_execution_variables(call_node, canonical, remote_names):
            execution.append(_FlowSignal(variable, call_node.lineno, _line(lines, call_node.lineno), scope=scope))
        command_expression = call_node.args[0] if call_node.args else None
        if (
            canonical
            in {
                "eval",
                "exec",
                "os.system",
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.call",
                "subprocess.check_call",
            }
            and command_expression is not None
            and _python_remote_source(command_expression, aliases)
            and _python_direct_remote_execution(call_node, canonical, command_expression)
        ):
            direct = _FlowSignal("*DIRECT*", call_node.lineno, _line(lines, call_node.lineno), scope=scope)
            remote.append(direct)
            execution.append(direct)
        for written_path, source in remote_written_paths.items():
            if _python_executes_path(call_node, canonical, written_path):
                remote.append(source)
                execution.append(
                    _FlowSignal(source.variable, call_node.lineno, _line(lines, call_node.lineno), scope=scope)
                )
    return sensitive, remote, network, execution


def _python_scope_for_line(line: int, ranges: list[tuple[int, int, str]]) -> str:
    containing = [(start, name) for start, end, name in ranges if start <= line <= end]
    return max(containing, default=(0, "module"))[1]


def _python_taint_at_point(
    history: dict[str, list[tuple[int, int, bool, bool]]], line: int, column: int
) -> tuple[set[str], set[str]]:
    sensitive: set[str] = set()
    remote: set[str] = set()
    for variable, states in history.items():
        prior = [state for state in states if (state[0], state[1]) <= (line, column)]
        if not prior:
            continue
        _, _, is_sensitive, is_remote = prior[-1]
        if is_sensitive:
            sensitive.add(variable)
        if is_remote:
            remote.add(variable)
    return sensitive, remote


def _python_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for name in node.names:
                aliases[name.asname or name.name.split(".")[0]] = name.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for name in node.names:
                aliases[name.asname or name.name] = f"{node.module}.{name.name}"
    return aliases


def _python_canonical_name(node: ast.expr, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _python_canonical_name(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _python_sensitive_source(node: ast.AST, aliases: dict[str, str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Subscript) and _python_canonical_name(child.value, aliases) == "os.environ":
            key = _literal_string(child.slice)
            if key and _CREDENTIAL_ENV_KEY_RE.search(key):
                return True
        if not isinstance(child, ast.Call):
            continue
        canonical = _python_canonical_name(child.func, aliases)
        if canonical in {"os.getenv", "os.environ.get"}:
            key = _literal_string(child.args[0]) if child.args else None
            if key and _CREDENTIAL_ENV_KEY_RE.search(key):
                return True
        if canonical == "open" or canonical.endswith((".read_text", ".read_bytes", ".open")):
            rendered = ast.unparse(child)
            if _SENSITIVE_PATH_RE.search(rendered):
                return True
    return False


def _python_remote_source(node: ast.AST, aliases: dict[str, str]) -> bool:
    remote_calls = {
        "requests.get",
        "httpx.get",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
    }
    return any(
        isinstance(child, ast.Call) and _python_canonical_name(child.func, aliases) in remote_calls
        for child in ast.walk(node)
    )


def _python_network_payloads(call: ast.Call, canonical: str) -> tuple[list[ast.expr], str | None]:
    request_calls = {
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.request",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.request",
    }
    if canonical not in request_calls:
        return [], None
    url_index = 1 if canonical.endswith(".request") else 0
    destination = _literal_string(call.args[url_index]) if len(call.args) > url_index else None
    payloads = [
        keyword.value
        for keyword in call.keywords
        if keyword.arg in {"data", "json", "body", "content", "files", "payload"}
    ]
    positional_index = url_index + 1
    if len(call.args) > positional_index:
        payloads.append(call.args[positional_index])
    return payloads, destination


def _python_execution_variables(call: ast.Call, canonical: str, remote_names: set[str]) -> set[str]:
    if canonical in {"eval", "exec", "os.system"}:
        expression = call.args[0] if call.args else None
        return _names_in(expression) & remote_names
    if canonical not in {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }:
        return set()
    command = call.args[0] if call.args else next((kw.value for kw in call.keywords if kw.arg == "args"), None)
    if command is None:
        return set()
    shell = any(
        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in call.keywords
    )
    if shell or isinstance(command, ast.Name):
        return _names_in(command) & remote_names
    if isinstance(command, (ast.List, ast.Tuple)) and command.elts:
        first = command.elts[0]
        controlled = _names_in(first) & remote_names
        interpreter = (_literal_string(first) or "").rsplit("/", 1)[-1]
        if interpreter in {"python", "python3", "node", "bash", "sh", "zsh"}:
            controlled |= {
                name for argument in command.elts[1:] for name in _names_in(argument) if name in remote_names
            }
        return controlled
    return set()


def _python_direct_remote_execution(call: ast.Call, canonical: str, command: ast.expr) -> bool:
    if canonical in {"eval", "exec", "os.system"}:
        return True
    shell = any(
        keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        for keyword in call.keywords
    )
    if shell:
        return True
    if not isinstance(command, (ast.List, ast.Tuple)) or not command.elts:
        return False
    interpreter = (_literal_string(command.elts[0]) or "").rsplit("/", 1)[-1]
    return interpreter in {"python", "python3", "node", "bash", "sh", "zsh"}


def _names_in(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _python_written_path(call: ast.Call, canonical: str, remote_names: set[str]) -> str | None:
    if canonical not in {"write_text", "write_bytes", "write"} and not canonical.endswith(
        (".write_text", ".write_bytes", ".write")
    ):
        return None
    if not call.args or not (_names_in(call.args[0]) & remote_names):
        return None
    rendered = ast.unparse(call.func)
    match = re.search(r"['\"]([^'\"]+)['\"]", rendered)
    return match.group(1) if match else None


def _python_executes_path(call: ast.Call, canonical: str, path: str) -> bool:
    if canonical not in {
        "exec",
        "os.system",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
    }:
        return False
    command = call.args[0] if call.args else None
    return command is not None and path in ast.unparse(command)


def _python_wrapper_summaries(
    tree: ast.Module,
    aliases: dict[str, str],
) -> dict[str, list[tuple[int, str, str | None]]]:
    summaries: dict[str, list[tuple[int, str, str | None]]] = {}
    for function in (node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        params = [arg.arg for arg in function.args.args]
        entries: list[tuple[int, str, str | None]] = []
        for child in ast.walk(function):
            if not isinstance(child, ast.Call):
                continue
            canonical = _python_canonical_name(child.func, aliases)
            payloads, destination = _python_network_payloads(child, canonical)
            for index, param in enumerate(params):
                if any(param in _names_in(payload) for payload in payloads):
                    entries.append((index, "network", destination))
                if param in _python_execution_variables(child, canonical, set(params)):
                    entries.append((index, "execution", None))
        if entries:
            summaries[function.name] = entries[:16]
    return summaries


def _assigned_names(node: ast.Assign | ast.AnnAssign | ast.NamedExpr) -> set[str]:
    targets: list[ast.expr] = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
    return {child.id for target in targets for child in ast.walk(target) if isinstance(child, ast.Name)}


def _lexical_signals(
    text: str,
    *,
    shell: bool,
) -> tuple[list[_FlowSignal], list[_FlowSignal], list[_FlowSignal], list[_FlowSignal]]:
    if not shell:
        text = _split_javascript_statements(text)
    sensitive: list[_FlowSignal] = []
    remote: list[_FlowSignal] = []
    network: list[_FlowSignal] = []
    execution: list[_FlowSignal] = []
    assignments: dict[str, tuple[int, str]] = {}
    sensitive_names: set[str] = set()
    remote_names: set[str] = set()
    assignment_re = _SHELL_ASSIGNMENT_RE if shell else _ASSIGNMENT_RE
    lines = text.splitlines()
    wrappers = {} if shell else _lexical_wrapper_summaries(text)

    for number, line in enumerate(lines, start=1):
        assignment = assignment_re.match(line)
        if assignment:
            variable, value = assignment.groups()
            if shell:
                value_window = value
            else:
                assignment_window = _assignment_value_window(lines, number - 1)
                value_window = assignment_window.split("=", 1)[1] if "=" in assignment_window else value
            assignments[variable] = (number, line.strip())
            used_in_value = (
                set()
                if not shell and ("=> {" in value_window or re.search(r"\bfunction\b", value_window))
                else {name for name in assignments if _uses_variable(value_window, name, shell=shell)}
            )
            if _lexical_sensitive_source(value_window, shell=shell) or sensitive_names.intersection(used_in_value):
                sensitive.append(_FlowSignal(variable, number, line.strip()))
                sensitive_names.add(variable)
            else:
                sensitive_names.discard(variable)
            if _REMOTE_SOURCE_RE.search(value_window) or remote_names.intersection(used_in_value):
                remote.append(_FlowSignal(variable, number, line.strip()))
                remote_names.add(variable)
            else:
                remote_names.discard(variable)

        if shell and line.lstrip().startswith(("#", "echo ", "echo\t", "printf ", "printf\t")):
            continue

        window = " ".join(lines[number - 1 : min(len(lines), number + 6)])
        used = {name for name in assignments if _uses_variable(window, name, shell=shell)}
        if _NETWORK_SINK_RE.search(line):
            destination = _first_url(window)
            for name in sorted(used):
                if name in sensitive_names and _lexical_payload_use(window, name, shell=shell):
                    network.append(_FlowSignal(name, number, line.strip(), destination))
            if _lexical_direct_sensitive_payload(window, shell=shell):
                direct = _FlowSignal("*DIRECT*", number, line.strip(), destination)
                if not any(item.line == number and item.variable != "*DIRECT*" for item in network):
                    network.append(direct)
                    sensitive.append(direct)
        if _EXECUTION_SINK_RE.search(line):
            for name in sorted(used):
                if name in remote_names and _lexical_execution_use(window, name, shell=shell):
                    execution.append(_FlowSignal(name, number, line.strip()))
            if _REMOTE_SOURCE_RE.search(line):
                execution.append(_FlowSignal("*DIRECT*", number, line.strip()))
                remote.append(_FlowSignal("*DIRECT*", number, line.strip()))
        for wrapper_name, (params, sink_kind, destination) in wrappers.items():
            call = re.search(rf"\b{re.escape(wrapper_name)}\s*\(([^)]*)\)", line)
            if call is None:
                continue
            arguments = [part.strip() for part in call.group(1).split(",")]
            for index in params:
                if index >= len(arguments):
                    continue
                for name in assignments:
                    if not _uses_variable(arguments[index], name, shell=False):
                        continue
                    if sink_kind == "network" and name in sensitive_names:
                        network.append(_FlowSignal(name, number, line.strip(), destination))
                    if sink_kind == "execution" and name in remote_names:
                        execution.append(_FlowSignal(name, number, line.strip()))
    return sensitive, remote, network, execution


def _split_javascript_statements(text: str) -> str:
    """Put semicolon-delimited JS statements on separate analysis lines."""
    rendered: list[str] = []
    quote: str | None = None
    escaped = False
    for char in text:
        rendered.append(char)
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote is not None:
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == ";":
            rendered.append("\n")
    return "".join(rendered)


def _lexical_sensitive_source(text: str, *, shell: bool) -> bool:
    if _SENSITIVE_PATH_RE.search(text) and re.search(r"\b(?:readFile\w*|cat|source)\b", text, re.IGNORECASE):
        return True
    if shell:
        for match in re.finditer(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", text):
            if _CREDENTIAL_ENV_KEY_RE.search(match.group(1)):
                return True
        return False
    for match in re.finditer(
        r"(?:process\.env\.?|Deno\.env\.get\s*\(|Bun\.env\.?)['\"]?([A-Za-z_][A-Za-z0-9_]*)",
        text,
    ):
        if _CREDENTIAL_ENV_KEY_RE.search(match.group(1)):
            return True
    return False


def _first_url(text: str) -> str | None:
    match = _URL_RE.search(text)
    return match.group(0).rstrip(".,;:") if match else None


def _lexical_execution_use(text: str, variable: str, *, shell: bool) -> bool:
    if not _uses_variable(text, variable, shell=shell):
        return False
    if re.search(r"\b(?:eval|exec)\b", text):
        return True
    if re.search(r"\b(?:echo|printf)\b", text) and not re.search(r"\b(?:ba)?sh\s+-c\b", text):
        return False
    return re.search(r"\b(?:child_process\.)?(?:exec|spawn)(?:Sync)?\s*\(", text) is not None


def _lexical_wrapper_summaries(text: str) -> dict[str, tuple[tuple[int, ...], str, str | None]]:
    summaries: dict[str, tuple[tuple[int, ...], str, str | None]] = {}
    pattern = re.compile(
        r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{(.{0,2000}?)\}",
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        name, raw_params, body = match.groups()
        params = [part.strip() for part in raw_params.split(",") if part.strip()]
        if _NETWORK_SINK_RE.search(body):
            used = tuple(index for index, param in enumerate(params) if _lexical_payload_use(body, param, shell=False))
            if used:
                summaries[name] = (used, "network", _first_url(body))
        elif _EXECUTION_SINK_RE.search(body):
            used = tuple(
                index for index, param in enumerate(params) if _lexical_execution_use(body, param, shell=False)
            )
            if used:
                summaries[name] = (used, "execution", None)
        if len(summaries) >= 32:
            break
    return summaries


def _assignment_value_window(lines: list[str], zero_based_index: int) -> str:
    """Capture one bounded JS/TS assignment expression without tainting later statements."""
    captured: list[str] = []
    for line in lines[zero_based_index : zero_based_index + 7]:
        captured.append(line)
        if ";" in line:
            break
    return " ".join(captured)


def _lexical_payload_use(text: str, variable: str, *, shell: bool) -> bool:
    escaped = re.escape(variable)
    if shell:
        return (
            re.search(
                rf"(?:--data(?:-binary)?|-d\b|--form\b|-F\b|--upload-file\b)[^\n|;]*"
                rf"\$(?:\{{{escaped}\}}|{escaped}\b)",
                text,
            )
            is not None
        )
    return (
        re.search(
            rf"\b(?:body|data|payload|content|files)\s*:[^,}}]*" rf"(?<![\w$]){escaped}(?![\w$])",
            text,
            re.IGNORECASE,
        )
        is not None
    )


def _lexical_direct_sensitive_payload(text: str, *, shell: bool) -> bool:
    if shell:
        match = re.search(
            r"(?:--data(?:-binary)?|-d\b|--form\b|-F\b|--upload-file\b)([^\n|;]*)",
            text,
            re.IGNORECASE,
        )
        return match is not None and _lexical_sensitive_source(match.group(1), shell=True)
    return any(
        _lexical_sensitive_source(match.group(1), shell=False)
        for match in re.finditer(
            r"\b(?:body|data|payload|content|files)\s*:([^,}]*)",
            text,
            re.IGNORECASE,
        )
    )


def _uses_variable(line: str, variable: str, *, shell: bool) -> bool:
    if shell:
        return re.search(rf"\$(?:\{{{re.escape(variable)}\}}|{re.escape(variable)}\b)", line) is not None
    return re.search(rf"(?<![\w$]){re.escape(variable)}(?![\w$])", line) is not None


def _emit_flow_correlations(
    candidates: list[FindingCandidate],
    text_file: _TextFile,
    declaration_line: int | None,
    sensitive: list[_FlowSignal],
    remote: list[_FlowSignal],
    network: list[_FlowSignal],
    execution: list[_FlowSignal],
    config: RazinConfig,
    allowed: frozenset[str] | None,
) -> None:
    for source, sink in _correlate(sensitive, network):
        declaration = (
            f" SKILL.md references this helper on line {declaration_line}." if declaration_line is not None else ""
        )
        _append_candidate(
            candidates,
            FindingCandidate(
                rule_id="PACKAGE_SENSITIVE_NETWORK_FLOW",
                score=65,
                confidence="high" if declaration_line is not None else "medium",
                title="Sensitive data reaches a network payload",
                description=(
                    f"{text_file.relative_path} assigns sensitive data to '{source.variable}' on line {source.line} "
                    f"and passes it to a network sink on line {sink.line}.{declaration}"
                ),
                evidence=Evidence(path=str(text_file.path), line=sink.line, snippet=sink.snippet[:240]),
                recommendation=(
                    "Verify the destination, user consent, data minimization, and redaction before enabling this flow."
                ),
            ),
            allowed,
            config.package_analysis.max_findings_per_rule,
        )
        if _suspicious_exfil_destination(sink.destination, config):
            _append_candidate(
                candidates,
                FindingCandidate(
                    rule_id="PACKAGE_DATA_EXFILTRATION",
                    score=94,
                    confidence="high",
                    title="Sensitive data flows to a suspicious collection endpoint",
                    description=(
                        f"{text_file.relative_path} sends sensitive data from line {source.line} to "
                        f"suspicious destination {sink.destination!r} on line {sink.line}.{declaration}"
                    ),
                    evidence=Evidence(path=str(text_file.path), line=sink.line, snippet=sink.snippet[:240]),
                    recommendation=(
                        "Quarantine the package and validate the destination and data flow before execution."
                    ),
                ),
                allowed,
                config.package_analysis.max_findings_per_rule,
            )
    for source, sink in _correlate(remote, execution):
        declaration = (
            f" SKILL.md references this helper on line {declaration_line}." if declaration_line is not None else ""
        )
        _append_candidate(
            candidates,
            FindingCandidate(
                rule_id="PACKAGE_REMOTE_CODE_EXECUTION",
                score=96,
                confidence="high" if declaration_line is not None else "medium",
                title="Remote content flows to code execution",
                description=(
                    f"{text_file.relative_path} obtains remote content in '{source.variable}' on line {source.line} "
                    f"and passes it to an execution sink on line {sink.line}.{declaration}"
                ),
                evidence=Evidence(path=str(text_file.path), line=sink.line, snippet=sink.snippet[:240]),
                recommendation="Remove download-and-execute behavior; vendor and verify an immutable artifact instead.",
            ),
            allowed,
            config.package_analysis.max_findings_per_rule,
        )


def _correlate(sources: list[_FlowSignal], sinks: list[_FlowSignal]) -> list[tuple[_FlowSignal, _FlowSignal]]:
    pairs: list[tuple[_FlowSignal, _FlowSignal]] = []
    seen: set[tuple[str, str, int, int]] = set()
    for source in sources:
        for sink in sinks:
            if source.scope != sink.scope or source.variable != sink.variable or sink.line < source.line:
                continue
            key = (source.scope, source.variable, source.line, sink.line)
            if key not in seen:
                seen.add(key)
                pairs.append((source, sink))
    return pairs


def _suspicious_exfil_destination(destination: str | None, config: RazinConfig) -> bool:
    if destination is None:
        return False
    try:
        host = (urlparse(destination).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    suspicious = (*config.package_analysis.known_bad.domains, *SUSPICIOUS_COLLECTION_DOMAINS)
    return any(host == domain or host.endswith(f".{domain}") for domain in suspicious)


def _match_remote_pipe(
    candidates: list[FindingCandidate],
    text_file: _TextFile,
    referenced_line: int | None,
    config: RazinConfig,
    allowed: frozenset[str] | None,
) -> None:
    logical_text = re.sub(r"\\\s*\n\s*", " ", text_file.text)
    heredoc_end: str | None = None
    for number, line in enumerate(logical_text.splitlines(), start=1):
        if heredoc_end is not None:
            if line.strip() == heredoc_end:
                heredoc_end = None
            continue
        if text_file.path.suffix.lower() in {".sh", ".bash", ".zsh"}:
            heredoc = re.search(
                r"<<-?\s*(?:'([^']+)'|\"([^\"]+)\"|([^\s;&|<>]+))",
                line,
            )
            if heredoc is not None:
                heredoc_end = next(group for group in heredoc.groups() if group is not None)
                continue
        if not _REMOTE_PIPE_RE.search(line):
            continue
        stripped = line.lstrip()
        if stripped.startswith(("#", "echo ", "echo\t", "printf ", "printf\t")):
            continue
        if text_file.path.suffix.lower() not in {".sh", ".bash", ".zsh"} and any(
            quote in line for quote in ("'", '"', "`")
        ):
            continue
        declaration = f" SKILL.md references this helper on line {referenced_line}." if referenced_line else ""
        _append_candidate(
            candidates,
            FindingCandidate(
                rule_id="PACKAGE_REMOTE_CODE_EXECUTION",
                score=98,
                confidence="high" if referenced_line else "medium",
                title="Remote content is piped to a shell",
                description=(
                    f"{text_file.relative_path} downloads content and pipes it directly to a shell.{declaration}"
                ),
                evidence=Evidence(path=str(text_file.path), line=number, snippet=line.strip()[:240]),
                recommendation=(
                    "Download an immutable version, verify its digest, inspect it, and execute only after approval."
                ),
            ),
            allowed,
            config.package_analysis.max_findings_per_rule,
        )


def _match_shell_download_then_execute(
    candidates: list[FindingCandidate],
    text_file: _TextFile,
    referenced_line: int | None,
    config: RazinConfig,
    allowed: frozenset[str] | None,
) -> None:
    downloads: dict[str, int] = {}
    lines = re.sub(r"\\\s*\n\s*", " ", text_file.text).splitlines()
    for number, line in enumerate(lines, start=1):
        curl = re.search(r"\bcurl\b[^\n]*(?:-o|--output)\s+['\"]?([^\s'\"]+)", line)
        wget = re.search(r"\bwget\b[^\n]*(?:-O|--output-document)\s+['\"]?([^\s'\"]+)", line)
        match = curl or wget
        if match:
            downloads[match.group(1)] = number
            continue
        for path, source_line in downloads.items():
            if not re.search(
                rf"(?:(?:\b(?:ba)?sh\b|\bzsh\b|\bpython3?\b|\bnode\b)\s+{re.escape(path)}|"
                rf"\./{re.escape(path.lstrip('./'))})(?:\s|$)",
                line,
            ):
                continue
            declaration = f" SKILL.md references this helper on line {referenced_line}." if referenced_line else ""
            _append_candidate(
                candidates,
                FindingCandidate(
                    rule_id="PACKAGE_REMOTE_CODE_EXECUTION",
                    score=96,
                    confidence="high" if referenced_line else "medium",
                    title="Downloaded file is executed",
                    description=(
                        f"{text_file.relative_path} downloads {path!r} on line {source_line} "
                        f"and executes it on line {number}.{declaration}"
                    ),
                    evidence=Evidence(path=str(text_file.path), line=number, snippet=line.strip()[:240]),
                    recommendation="Vendor and verify an immutable artifact instead of executing downloaded content.",
                ),
                allowed,
                config.package_analysis.max_findings_per_rule,
            )


def _match_bad_hash(
    candidates: list[FindingCandidate],
    path: Path,
    relative: str,
    digest: str,
    config: RazinConfig,
    allowed: frozenset[str] | None,
) -> None:
    if digest not in config.package_analysis.known_bad.sha256:
        return
    _append_candidate(
        candidates,
        FindingCandidate(
            rule_id="KNOWN_BAD_FILE_HASH",
            score=100,
            confidence="high",
            title="Known-bad file hash matched",
            description=f"{relative} matches configured SHA-256 indicator {digest}.",
            evidence=Evidence(path=str(path), line=None, snippet=digest),
            recommendation="Quarantine the package and investigate its origin before any execution.",
        ),
        allowed,
        config.package_analysis.max_findings_per_rule,
    )


def _match_known_text_iocs(
    candidates: list[FindingCandidate],
    text_file: _TextFile,
    config: RazinConfig,
    allowed: frozenset[str] | None,
) -> None:
    known = config.package_analysis.known_bad
    for number, line in enumerate(text_file.text.splitlines(), start=1):
        line_lower = line.lower()
        for domain in known.domains:
            if _domain_in_line(line_lower, domain):
                _append_candidate(
                    candidates,
                    FindingCandidate(
                        rule_id="KNOWN_BAD_DOMAIN",
                        score=98,
                        confidence="high",
                        title="Known-bad domain matched",
                        description=f"{text_file.relative_path} references configured known-bad domain '{domain}'.",
                        evidence=Evidence(path=str(text_file.path), line=number, snippet=line.strip()[:240]),
                        recommendation="Remove the reference, quarantine the package, and investigate the destination.",
                    ),
                    allowed,
                    config.package_analysis.max_findings_per_rule,
                )
        for indicator in known.indicators:
            if indicator.lower() in line_lower:
                _append_candidate(
                    candidates,
                    FindingCandidate(
                        rule_id="KNOWN_BAD_INDICATOR",
                        score=98,
                        confidence="high",
                        title="Known-bad indicator matched",
                        description=f"{text_file.relative_path} contains configured indicator '{indicator}'.",
                        evidence=Evidence(path=str(text_file.path), line=number, snippet=line.strip()[:240]),
                        recommendation=(
                            "Quarantine the package and validate the indicator against trusted threat intelligence."
                        ),
                    ),
                    allowed,
                    config.package_analysis.max_findings_per_rule,
                )


def _domain_in_line(line: str, domain: str) -> bool:
    for match in _URL_RE.finditer(line):
        try:
            host = (urlparse(match.group(0).rstrip(".,;:")).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host == domain or host.endswith(f".{domain}"):
            return True
    return re.search(rf"(?<![a-z0-9.-])(?:[a-z0-9-]+\.)*{re.escape(domain)}(?![a-z0-9.-])", line) is not None


def _match_mutable_references(
    candidates: list[FindingCandidate],
    text_file: _TextFile,
    config: RazinConfig,
    allowed: frozenset[str] | None,
) -> None:
    lines = text_file.text.splitlines()
    for number, line in enumerate(lines, start=1):
        clone = re.search(r"\bgit\s+clone\b", line, re.IGNORECASE) is not None
        pinned_checkout = False
        if clone:
            followup = "\n".join(lines[number : number + 8])
            pinned_checkout = (
                re.search(
                    r"\bgit(?:\s+-C\s+\S+)?\s+(?:checkout|switch\s+--detach|reset\s+--hard)\s+[0-9a-fA-F]{40}\b",
                    followup,
                )
                is not None
            )
        mutable = clone and not pinned_checkout
        matched_ref = "git clone without a subsequent full-SHA checkout" if mutable else None
        for url_match in _URL_RE.finditer(line):
            url = url_match.group(0).rstrip(".,;:")
            if _is_mutable_remote_url(url):
                mutable = True
                matched_ref = url
                break
        if not mutable or matched_ref is None:
            continue
        _append_candidate(
            candidates,
            FindingCandidate(
                rule_id="MUTABLE_REMOTE_REFERENCE",
                score=55,
                confidence="high",
                title="Mutable remote reference",
                description=(
                    f"{text_file.relative_path} relies on {matched_ref!r}, "
                    "whose content can change without package changes."
                ),
                evidence=Evidence(path=str(text_file.path), line=number, snippet=line.strip()[:240]),
                recommendation="Pin the remote content to an immutable commit or digest and verify it before use.",
            ),
            allowed,
            config.package_analysis.max_findings_per_rule,
        )


def _is_mutable_remote_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if host in {"raw.githubusercontent.com", "github.com"}:
        return any(token in path for token in ("/main/", "/master/", "/refs/heads/", "/heads/"))
    if host == "gitlab.com" or host.endswith(".gitlab.com"):
        return "/-/raw/main/" in path or "/-/raw/master/" in path
    return False


def _gap_candidate(skill_path: Path, relative: str, reason: str) -> FindingCandidate:
    return FindingCandidate(
        rule_id="INCOMPLETE_SCAN",
        score=0,
        confidence="high",
        title="Package analysis incomplete",
        description=f"{relative}: {reason}",
        evidence=Evidence(path=str(skill_path.parent / relative), line=None, snippet=relative),
        recommendation="Resolve the analysis gap or inspect the omitted content in an isolated environment.",
        classification="informational",
    )


def _dynamic_candidate(path: Path, relative: str, reason: str) -> FindingCandidate:
    return FindingCandidate(
        rule_id="DYNAMIC_ANALYSIS_REQUIRED",
        score=0,
        confidence="high",
        title="Dynamic analysis required",
        description=f"{relative}: {reason}",
        evidence=Evidence(path=str(path), line=None, snippet=relative),
        recommendation=(
            "Inspect this artifact in a sandbox with network and filesystem monitoring before trust decisions."
        ),
        classification="informational",
    )


def _append_candidate(
    candidates: list[FindingCandidate],
    candidate: FindingCandidate,
    allowed: frozenset[str] | None,
    per_rule_limit: int,
) -> None:
    if not _is_allowed(candidate.rule_id, allowed):
        return
    if any(
        existing.rule_id == candidate.rule_id
        and existing.evidence.path == candidate.evidence.path
        and existing.evidence.line == candidate.evidence.line
        for existing in candidates
    ):
        return
    if sum(existing.rule_id == candidate.rule_id for existing in candidates) >= per_rule_limit:
        return
    candidates.append(candidate)


def _is_allowed(rule_id: str, allowed: frozenset[str] | None) -> bool:
    return allowed is None or rule_id in allowed


def _line(lines: list[str], number: int) -> str:
    if 1 <= number <= len(lines):
        return lines[number - 1].strip()[:240]
    return ""


def package_signature(result: PackageAnalysisResult) -> str:
    """Return the package digest used by cache validation."""
    return result.package_sha256


def manifest_to_json(result: PackageAnalysisResult) -> str:
    """Serialize provenance deterministically for callers that persist inventories."""
    payload = {
        "coverage_digest_version": PACKAGE_COVERAGE_DIGEST_VERSION,
        "coverage_sha256": result.package_sha256,
        "coverage_complete": result.coverage_complete,
        "coverage_markers": list(result.coverage_markers),
        "analyzed_helpers": result.analyzed_helpers,
        "files": [
            {"path": entry.path, "size": entry.size, "sha256": entry.sha256, "mode": entry.mode}
            for entry in result.manifest
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
