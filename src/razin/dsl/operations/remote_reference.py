"""Metadata-only remote reference risk detection operation for DSL rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from razin.constants.detectors import (
    LOCAL_DEV_HOSTS,
    LOCAL_DEV_TLDS,
    REMOTE_REF_ANY_URI_RE,
    REMOTE_REF_FETCH_APPLY_HINTS,
    REMOTE_REF_FETCH_APPLY_SCORE,
    REMOTE_REF_HTTP_URL_RE,
    REMOTE_REF_INSECURE_SCHEME_BOOST,
    REMOTE_REF_SHORTENER_DOMAINS,
    REMOTE_REF_SHORTENER_SCORE,
    REMOTE_REF_UNSAFE_SCHEME_SCORE,
    RESERVED_EXAMPLE_DOMAINS,
    TRAILING_PUNCT_RE,
)
from razin.model import Evidence, FindingCandidate
from razin.types.dsl import EvalContext


def run_remote_reference_scan(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan skill content for risky remote reference patterns without fetching remote content."""
    raw = ctx.parsed.raw_text
    signals: list[_RemoteRefSignal] = []
    seen_urls: set[str] = set()

    _scan_unsafe_schemes(raw, signals, seen_urls)
    _scan_insecure_http(raw, signals, seen_urls, base_score)
    _scan_url_shorteners(raw, signals, seen_urls)
    _scan_fetch_apply_language(raw, signals)

    min_signals: int = match_config.get("min_signals", 1)
    if len(signals) < min_signals:
        return []

    first = signals[0]
    summary = "; ".join(s.label for s in signals[:5])
    if len(signals) > 5:
        summary += f" (+{len(signals) - 5} more)"

    description = metadata.get("description", "")
    description = f"{description} Detected: {summary}."

    score = max(s.score for s in signals)

    return [
        FindingCandidate(
            rule_id="",
            score=score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=description,
            evidence=Evidence(
                path=str(ctx.parsed.file_path),
                line=first.line,
                snippet=first.snippet[:200],
            ),
            recommendation=metadata["recommendation"],
        )
    ]


@dataclass(frozen=True, slots=True)
class _RemoteRefSignal:
    """Internal container for a remote reference risk signal."""

    category: str
    label: str
    line: int
    snippet: str
    score: int


def _scan_unsafe_schemes(
    raw_text: str,
    signals: list[_RemoteRefSignal],
    seen_urls: set[str],
) -> None:
    """Detect non-standard/unsafe URI schemes (data:, javascript:, ftp:, etc.)."""
    for match in REMOTE_REF_ANY_URI_RE.finditer(raw_text):
        url = TRAILING_PUNCT_RE.sub("", match.group(0))
        if url in seen_urls:
            continue
        seen_urls.add(url)
        scheme = url.split(":")[0].lower()
        line = raw_text[: match.start()].count("\n") + 1
        signals.append(
            _RemoteRefSignal(
                category="unsafe_scheme",
                label=f"unsafe scheme '{scheme}:' at line {line}",
                line=line,
                snippet=url,
                score=REMOTE_REF_UNSAFE_SCHEME_SCORE,
            )
        )


def _scan_insecure_http(
    raw_text: str,
    signals: list[_RemoteRefSignal],
    seen_urls: set[str],
    base_score: int,
) -> None:
    """Detect http:// URLs outside local/dev exceptions."""
    for match in REMOTE_REF_HTTP_URL_RE.finditer(raw_text):
        url = TRAILING_PUNCT_RE.sub("", match.group(0))
        if url in seen_urls:
            continue
        if not url.lower().startswith("http://"):
            continue
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            continue
        if _is_local_or_reserved(host):
            continue
        seen_urls.add(url)
        line = raw_text[: match.start()].count("\n") + 1
        signals.append(
            _RemoteRefSignal(
                category="insecure_http",
                label=f"insecure http:// to '{host}' at line {line}",
                line=line,
                snippet=url,
                score=base_score + REMOTE_REF_INSECURE_SCHEME_BOOST,
            )
        )


def _scan_url_shorteners(
    raw_text: str,
    signals: list[_RemoteRefSignal],
    seen_urls: set[str],
) -> None:
    """Detect URL shortener domains that obscure final destination."""
    for match in REMOTE_REF_HTTP_URL_RE.finditer(raw_text):
        url = TRAILING_PUNCT_RE.sub("", match.group(0))
        if url in seen_urls:
            continue
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            continue
        if host.lower() in REMOTE_REF_SHORTENER_DOMAINS:
            seen_urls.add(url)
            line = raw_text[: match.start()].count("\n") + 1
            signals.append(
                _RemoteRefSignal(
                    category="url_shortener",
                    label=f"URL shortener '{host}' at line {line}",
                    line=line,
                    snippet=url,
                    score=REMOTE_REF_SHORTENER_SCORE,
                )
            )


def _scan_fetch_apply_language(
    raw_text: str,
    signals: list[_RemoteRefSignal],
) -> None:
    """Detect language patterns indicating remote instruction fetch-and-apply behavior."""
    lowered = raw_text.lower()
    seen_hints: set[str] = set()
    for hint in REMOTE_REF_FETCH_APPLY_HINTS:
        idx = lowered.find(hint)
        if idx == -1 or hint in seen_hints:
            continue
        seen_hints.add(hint)
        line = raw_text[:idx].count("\n") + 1
        snippet = raw_text.splitlines()[line - 1] if line <= len(raw_text.splitlines()) else hint
        signals.append(
            _RemoteRefSignal(
                category="fetch_apply",
                label=f"fetch-and-apply language '{hint}' at line {line}",
                line=line,
                snippet=snippet.strip(),
                score=REMOTE_REF_FETCH_APPLY_SCORE,
            )
        )


def _is_local_or_reserved(host: str) -> bool:
    """Return True for localhost, reserved example domains, and local TLDs."""
    host_lower = host.lower()
    if host_lower in LOCAL_DEV_HOSTS:
        return True
    if host_lower in RESERVED_EXAMPLE_DOMAINS:
        return True
    return any(host_lower.endswith(tld) for tld in LOCAL_DEV_TLDS)
