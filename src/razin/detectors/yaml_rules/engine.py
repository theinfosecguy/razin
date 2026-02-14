"""YamlDetector: adapter that wraps a YAML rule definition as a Detector.

The engine reads the parsed YAML dict, extracts strategy name and parameters,
and delegates to the matching strategy function in the strategies module.
"""

from __future__ import annotations

from typing import Any, ClassVar

from razin.config import RazinConfig
from razin.detectors.base import Detector
from razin.detectors.yaml_rules.strategies import STRATEGY_REGISTRY
from razin.model import FindingCandidate, ParsedSkillDocument


class YamlDetector(Detector):
    """Detector backed by a YAML rule definition.

    Constructed from a validated YAML dict. Delegates matching to a
    strategy function looked up from the strategies registry.
    """

    rule_id: ClassVar[str] = "_yaml_rule_template"

    def __init__(self, rule_def: dict[str, Any]) -> None:
        self._rule_def = rule_def
        self._detector_id: str = rule_def["rule_id"]
        self._strategy_name: str = rule_def["match"]["strategy"]
        self._match_config: dict[str, Any] = rule_def["match"]
        self._metadata: dict[str, Any] = rule_def["metadata"]
        self._base_score: int = rule_def["scoring"]["base_score"]
        self._dedupe: bool = rule_def.get("dedupe", True)
        self._version: int = rule_def["version"]

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        """Run the YAML-defined detector via strategy delegation."""
        strategy_fn = STRATEGY_REGISTRY.get(self._strategy_name)
        if strategy_fn is None:
            raise ValueError(f"YamlDetector '{self._detector_id}': unknown strategy '{self._strategy_name}'")

        candidates = strategy_fn(
            parsed=parsed,
            config=config,
            match_config=self._match_config,
            metadata=self._metadata,
            base_score=self._base_score,
            do_dedupe=self._dedupe,
        )

        # Stamp rule_id onto each candidate (strategies leave it empty).
        stamped: list[FindingCandidate] = []
        for candidate in candidates:
            stamped.append(
                FindingCandidate(
                    rule_id=self._detector_id,
                    score=candidate.score,
                    confidence=candidate.confidence,
                    title=candidate.title,
                    description=candidate.description,
                    evidence=candidate.evidence,
                    recommendation=candidate.recommendation,
                )
            )
        return stamped

    @property
    def version(self) -> int:
        """Rule definition version from YAML."""
        return self._version

    @property
    def detector_id(self) -> str:
        """Rule ID defined by this YAML detector instance."""
        return self._detector_id

    @property
    def source_yaml(self) -> dict[str, Any]:
        """Raw YAML definition for auditability."""
        return dict(self._rule_def)
