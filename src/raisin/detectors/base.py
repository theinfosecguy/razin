"""Detector interfaces for scanner rules."""

from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from typing import ClassVar

from raisin.config import RaisinConfig
from raisin.model import FindingCandidate, ParsedSkillDocument


class Detector(ABC):
    """Abstract base class for detector implementations."""

    rule_id: ClassVar[str]

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Validate detector subclasses define a non-empty `rule_id`."""
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls):
            return

        rule_id = getattr(cls, "rule_id", None)
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise TypeError(f"{cls.__name__} must define a non-empty class attribute `rule_id`")

    @abstractmethod
    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RaisinConfig,
    ) -> list[FindingCandidate]:
        """Run detector on a parsed skill document."""
