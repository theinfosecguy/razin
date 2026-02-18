"""Cross-module type aliases."""

from __future__ import annotations

from typing import Literal

type Severity = Literal["low", "medium", "high"]
type Confidence = Literal["low", "medium", "high"]
type Classification = Literal["security", "informational"]

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]
