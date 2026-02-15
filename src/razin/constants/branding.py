"""Branding constants for docs and terminal output."""

from __future__ import annotations

BRAND_NAME: str = "RAZIN"
ASCII_LOGO_LINES: tuple[str, ...] = (
    ">_ RAZIN",
    "     // static analysis for LLM skills",
)
SCAN_SUMMARY_TITLE: str = "Scan summary"
CLI_DESCRIPTION: str = "\n".join((*ASCII_LOGO_LINES, "", f"{BRAND_NAME} skill scanner"))
