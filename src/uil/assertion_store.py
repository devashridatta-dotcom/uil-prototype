"""
uil/assertion_store.py — Stage 4: Assertion Store.

The Assertion Store is the durable, queryable artifact that anchors the
audit trail. It is independently queryable — its reproducibility property
is what makes audit defensible.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from .models import Assertion, Claim, Dimension


class AssertionStore:
    """
    In-memory Assertion Store with JSON serialization for audit trail output.

    The store is independently queryable: given the same input artifacts
    and policy version, it produces the same assertion set (determinism
    property, §4.1).
    """

    def __init__(self, pipeline_version: str = "UIL-v0.1-SCORED26"):
        self._assertions: List[Assertion] = []
        self.pipeline_version = pipeline_version
        self.created_at = datetime.now(timezone.utc)

    # ── Write ─────────────────────────────────────────────────────────────────

    def add(self, assertion: Assertion) -> None:
        self._assertions.append(assertion)

    def add_many(self, assertions: List[Assertion]) -> None:
        self._assertions.extend(assertions)

    # ── Query ─────────────────────────────────────────────────────────────────

    @property
    def all(self) -> List[Assertion]:
        return list(self._assertions)

    def by_claim(self, claim: Claim) -> List[Assertion]:
        return [a for a in self._assertions if a.claim == claim]

    def by_dimension(self, dimension: Dimension) -> List[Assertion]:
        return [a for a in self._assertions if a.dimension == dimension]

    def by_component(self, canonical_id: str) -> List[Assertion]:
        return [
            a for a in self._assertions
            if a.component.lower() == canonical_id.lower()
        ]

    def above_confidence(self, threshold: float) -> List[Assertion]:
        return [a for a in self._assertions if a.confidence.overall >= threshold]

    def below_confidence(self, threshold: float) -> List[Assertion]:
        return [a for a in self._assertions if a.confidence.overall < threshold]

    @property
    def count(self) -> int:
        return len(self._assertions)

    # ── Serialization (audit trail) ───────────────────────────────────────────

    def to_dict(self, policy_result=None, policy_version: str = "unknown") -> dict:
        return {
            "pipeline_version": self.pipeline_version,
            "policy_version":   policy_version,
            "generated_at":     self.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "decision":         policy_result.decision if policy_result else None,
            "decision_reason":  policy_result.reason   if policy_result else None,
            "assertions":       [a.to_dict() for a in self._assertions],
            "audit": {
                "assertion_count":  self.count,
                "block_count":      len(self.by_claim(Claim.REMEDIATION_REQUIRED)),
                "risk_accept_count": len(self.by_claim(Claim.ELEVATED_THREAT)),
                "reproducible":     True,
            },
        }

    def to_json(self, policy_result=None, policy_version: str = "unknown",
                indent: int = 2) -> str:
        return json.dumps(
            self.to_dict(policy_result, policy_version),
            indent=indent,
            default=str,
        )

    def save(self, path: str | Path, policy_result=None,
             policy_version: str = "unknown") -> None:
        Path(path).write_text(self.to_json(policy_result, policy_version))
