"""
uil/models.py — Core data models for the Unified Intelligence Layer prototype.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any


# ── Claim vocabulary (§5.2) ──────────────────────────────────────────────────

class Claim(str, Enum):
    NON_EXPLOITABLE               = "NON_EXPLOITABLE"
    REMEDIATION_REQUIRED          = "REMEDIATION_REQUIRED"
    LICENSE_COMPLIANT             = "LICENSE_COMPLIANT"
    LICENSE_REVIEW_REQUIRED       = "LICENSE_REVIEW_REQUIRED"
    ELEVATED_THREAT               = "ELEVATED_THREAT"
    AI_BEHAVIOR_RISK              = "AI_BEHAVIOR_RISK"
    PROMPT_INJECTION_RISK_BOUNDED = "PROMPT_INJECTION_RISK_BOUNDED"


class Dimension(str, Enum):
    SECURITY     = "security"
    LICENSING    = "licensing"
    ARCHITECTURE = "architecture"
    AI           = "ai"


class IdentityStrategy(str, Enum):
    DIGEST             = "DIGEST"
    EXACT_PURL         = "EXACT_PURL"
    NORMALIZED_COORDS  = "NORMALIZED_COORDS"
    FUZZY_VERSION      = "FUZZY_VERSION"
    NONE               = "NONE"


# Q_identity values per resolution strategy (Algorithm 1, §4.3)
Q_IDENTITY: Dict[IdentityStrategy, float] = {
    IdentityStrategy.DIGEST:            1.00,
    IdentityStrategy.EXACT_PURL:        0.90,
    IdentityStrategy.NORMALIZED_COORDS: 0.75,
    IdentityStrategy.FUZZY_VERSION:     0.50,
    IdentityStrategy.NONE:              0.00,
}


# ── Confidence model (§5.1) ──────────────────────────────────────────────────

@dataclass
class Confidence:
    """
    Conf(A) = Q_artifact · Q_identity · Q_correlation

    Multiplicative composition ensures any one weak factor dominates the score.
    """
    q_artifact:    float  # completeness/provenance quality of source artifact
    q_identity:    float  # cross-artifact identity resolution strength
    q_correlation: float  # inferential strength of the correlation step

    @property
    def overall(self) -> float:
        return round(self.q_artifact * self.q_identity * self.q_correlation, 3)

    @property
    def label(self) -> str:
        v = self.overall
        if v >= 0.70:
            return "high"
        if v >= 0.45:
            return "medium"
        return "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "q_artifact":    self.q_artifact,
            "q_identity":    self.q_identity,
            "q_correlation": self.q_correlation,
            "overall":       self.overall,
            "label":         self.label,
        }


# ── Assertion (§5.1) ─────────────────────────────────────────────────────────

@dataclass
class Assertion:
    """
    An assertion is a tuple:
      (component, context, claim, evidence, confidence, timestamp)

    This is the central abstraction of UIL — the unit on which release
    policy operates.
    """
    component:  str                    # canonical identity (PURL, digest, etc.)
    context:    str                    # deployment/distribution/release scope
    claim:      Claim                  # typed safety-relevance claim
    dimension:  Dimension              # which σ function produced this claim
    evidence:   List[str]              # referential pointers to source artifacts
    confidence: Confidence             # Conf(A) = Q_art · Q_id · Q_corr
    detail:     str                    # human-readable justification
    timestamp:  datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component":  self.component,
            "context":    self.context,
            "claim":      self.claim.value,
            "dimension":  self.dimension.value,
            "evidence":   self.evidence,
            "confidence": self.confidence.to_dict(),
            "detail":     self.detail,
            "timestamp":  self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


# ── Normalized artifact representations ──────────────────────────────────────

@dataclass
class NormalizedComponent:
    """Internal representation of a component after Stage 1 normalization."""
    canonical_id:   str            # canonical PURL
    name:           str
    version:        str
    ecosystem:      str            # npm, maven, pypi, etc.
    digest:         Optional[str] = None
    licenses:       List[str] = field(default_factory=list)
    raw_format:     str = "unknown"  # cyclonedx-1.5, spdx-3.0, etc.

    @property
    def coords(self):
        """Normalized coordinate triple (ecosystem, name, version)."""
        return (self.ecosystem.lower(), self.name.lower(), self.version)


@dataclass
class NormalizedVulnerability:
    """Internal representation of a VEX statement after normalization."""
    cve_id:       str
    component_id: str             # canonical PURL reference
    status:       str             # not_affected, affected, fixed, under_investigation
    justification: Optional[str] = None
    evidence_ref:  Optional[str] = None
    source_format: str = "unknown"  # csaf, cyclonedx-vex, openvex


@dataclass
class NormalizedTPN:
    """Internal representation of a Third-Party Notice clause."""
    component_id:  str
    license_spdx:  str            # SPDX identifier
    obligations:   List[str] = field(default_factory=list)
    attribution:   Optional[str] = None


@dataclass
class NormalizedTMBOM:
    """Internal representation of a TMBOM trust boundary."""
    boundary_id:   str
    description:   str
    component_ids: List[str] = field(default_factory=list)  # components behind this boundary
    exposure_ids:  List[str] = field(default_factory=list)  # components exposed at boundary
    mitigations:   List[str] = field(default_factory=list)


@dataclass
class NormalizedAIVEX:
    """Internal representation of an AIVEX AI risk assertion."""
    component_id:   str
    risk_type:      str           # prompt_injection, behavior_risk, training_risk, etc.
    cwe_id:         Optional[str] = None   # e.g. CWE-1427 for prompt injection
    mitre_atlas_id: Optional[str] = None
    mitigation_ref: Optional[str] = None  # TMBOM boundary or control reference
    evidence_ref:   Optional[str] = None


# ── Policy result ─────────────────────────────────────────────────────────────

@dataclass
class PolicyResult:
    """Output of Stage 5 — Policy Engine."""
    decision:        str           # APPROVE, BLOCK, RISK_ACCEPT_REQUIRED, HUMAN_REVIEW
    reason:          str
    policy_version:  str
    assertions_used: List[Assertion] = field(default_factory=list)
    blocking:        List[Assertion] = field(default_factory=list)
    risk_accept:     List[Assertion] = field(default_factory=list)
    low_confidence:  List[Assertion] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision":       self.decision,
            "reason":         self.reason,
            "policy_version": self.policy_version,
            "blocking":       [a.to_dict() for a in self.blocking],
            "risk_accept":    [a.to_dict() for a in self.risk_accept],
            "low_confidence": [a.to_dict() for a in self.low_confidence],
        }
