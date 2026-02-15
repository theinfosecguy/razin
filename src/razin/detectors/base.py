"""Detector interfaces for scanner rules."""

from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from typing import ClassVar

from razin.config import RazinConfig
from razin.constants.detectors import RULE_ID_PATTERN
from razin.model import FindingCandidate, ParsedSkillDocument


class Detector(ABC):
    """Abstract base class for detector implementations."""

    rule_id: ClassVar[str]

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Validate detector subclasses define a valid UPPER_SNAKE_CASE `rule_id`."""
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls):
            return

        rule_id = getattr(cls, "rule_id", None)
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise TypeError(f"{cls.__name__} must define a non-empty class attribute `rule_id`")
        if not rule_id.startswith("_") and not RULE_ID_PATTERN.match(rule_id):
            raise TypeError(f"{cls.__name__}.rule_id must be UPPER_SNAKE_CASE (got {rule_id!r})")

    @abstractmethod
    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        """Run detector on a parsed skill document."""
