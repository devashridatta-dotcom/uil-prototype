"""
uil/correlator.py — Stage 3: Correlation Engine.

Implements the four signal-extraction functions:
  σ_S — security signal  (SBOM + VEX)
  σ_L — licensing signal (TPN)
  σ_A — architectural signal (TMBOM)
  σ_AI — AI behavioral signal (AIVEX)

Each function maps a (component, context) pair to one or more typed claims
from the closed vocabulary of §5.2, with associated confidence.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional

from .models import (
    Assertion, Claim, Confidence, Dimension,
    NormalizedComponent, NormalizedVulnerability,
    NormalizedTPN, NormalizedTMBOM, NormalizedAIVEX,
    Q_IDENTITY, IdentityStrategy,
)


def sigma_S(
    component: NormalizedComponent,
    context: str,
    vulnerabilities: List[NormalizedVulnerability],
    tmbom_boundaries: List[NormalizedTMBOM],
    q_identity: float,
    q_artifact_sbom: float = 0.85,
    min_confidence: float = 0.40,
) -> List[Assertion]:
    """
    σ_S: Security signal extractor.

    Correlates SBOM component presence with VEX exploitability status and
    TMBOM architectural isolation to produce security dimension assertions.

    For each vulnerability affecting the component:
      - VEX not_affected + TMBOM isolation  → NON_EXPLOITABLE (high confidence)
      - VEX not_affected (no TMBOM)         → NON_EXPLOITABLE (medium confidence)
      - VEX affected / no VEX              → REMEDIATION_REQUIRED
      - VEX fixed                          → NON_EXPLOITABLE
    """
    ts = datetime.now(timezone.utc)
    assertions = []

    # Find boundaries that isolate this component
    isolating_boundaries = [
        b for b in tmbom_boundaries
        if component.canonical_id in b.component_ids
    ]

    component_vulns = [
        v for v in vulnerabilities
        if v.component_id.lower() == component.canonical_id.lower()
        or v.component_id.lower() == component.name.lower()
    ]

    if not component_vulns:
        return assertions

    for vuln in component_vulns:
        claim: Claim
        q_corr: float
        evidence: List[str] = []
        detail: str

        if vuln.evidence_ref:
            evidence.append(vuln.evidence_ref)

        if vuln.status == "not_affected":
            claim = Claim.NON_EXPLOITABLE
            if isolating_boundaries:
                q_corr = 0.95
                for b in isolating_boundaries:
                    evidence.append(b.boundary_id)
                detail = (
                    f"{vuln.cve_id}: VEX asserts not_affected; "
                    f"corroborated by TMBOM isolation at "
                    f"{', '.join(b.boundary_id for b in isolating_boundaries)}."
                )
            else:
                q_corr = 0.80
                detail = (
                    f"{vuln.cve_id}: VEX asserts not_affected in this "
                    f"deployment context. No TMBOM corroboration."
                )

        elif vuln.status == "fixed":
            claim = Claim.NON_EXPLOITABLE
            q_corr = 0.90
            detail = f"{vuln.cve_id}: Fixed in {component.version} per VEX."

        elif vuln.status == "affected":
            claim = Claim.REMEDIATION_REQUIRED
            q_corr = 0.95
            detail = (
                f"{vuln.cve_id}: VEX confirms exploitable in this deployment. "
                f"Patch or mitigation required before release."
            )

        else:
            # No VEX or under_investigation — conservative treatment
            claim = Claim.REMEDIATION_REQUIRED
            q_corr = 0.55
            detail = (
                f"{vuln.cve_id}: No VEX statement available or status under "
                f"investigation. Conservative policy treats as requiring remediation."
            )

        conf = Confidence(
            q_artifact=q_artifact_sbom,
            q_identity=q_identity,
            q_correlation=q_corr,
        )
        if conf.overall >= min_confidence:
            assertions.append(Assertion(
                component=component.canonical_id,
                context=context,
                claim=claim,
                dimension=Dimension.SECURITY,
                evidence=evidence,
                confidence=conf,
                detail=detail,
                timestamp=ts,
            ))

    return assertions


def sigma_L(
    component: NormalizedComponent,
    context: str,
    tpn: Optional[NormalizedTPN],
    distribution_type: str,
    q_identity: float,
    q_artifact_tpn: float = 0.88,
    min_confidence: float = 0.40,
) -> List[Assertion]:
    """
    σ_L: Licensing signal extractor.

    Evaluates component license obligations against the distribution context
    to produce licensing dimension assertions.

    distribution_type: one of 'internal', 'binary_external', 'saas', 'oss'
    """
    ts = datetime.now(timezone.utc)
    assertions = []

    license_spdx = (tpn.license_spdx if tpn else "").upper()
    evidence = ["TPN:clause-auto"] if tpn else []

    STRONG_COPYLEFT = {"GPL-2.0", "GPL-3.0", "GPL-2.0-ONLY", "GPL-3.0-ONLY", "AGPL-3.0", "AGPL-3.0-ONLY"}
    WEAK_COPYLEFT   = {"LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EUPL-1.2"}
    PERMISSIVE      = {"MIT", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC", "0BSD"}

    if not license_spdx or license_spdx == "UNKNOWN" or license_spdx == "NOASSERTION":
        claim = Claim.LICENSE_REVIEW_REQUIRED
        q_corr = 0.60
        detail = (
            "License not specified in SBOM or TPN. "
            "Legal review required before any distribution."
        )
    elif license_spdx in STRONG_COPYLEFT and distribution_type in ("binary_external", "oss"):
        claim = Claim.LICENSE_REVIEW_REQUIRED
        q_corr = 0.90
        detail = (
            f"Strong copyleft ({license_spdx}) under {distribution_type}: "
            f"legal review required. Copyleft obligations may require source disclosure."
        )
    elif license_spdx in WEAK_COPYLEFT and distribution_type == "binary_external":
        claim = Claim.LICENSE_REVIEW_REQUIRED
        q_corr = 0.80
        detail = (
            f"Weak copyleft ({license_spdx}) under binary external distribution: "
            f"attribution and linking obligations require review."
        )
    elif license_spdx in PERMISSIVE:
        claim = Claim.LICENSE_COMPLIANT
        q_corr = 0.95
        detail = (
            f"Permissive license ({license_spdx}); compliant under "
            f"{distribution_type} distribution context."
        )
    else:
        # Commercial or unrecognized — treat as compliant for internal, review for external
        if distribution_type == "internal":
            claim = Claim.LICENSE_COMPLIANT
            q_corr = 0.80
            detail = f"{license_spdx}: assessed as compliant for internal distribution."
        else:
            claim = Claim.LICENSE_REVIEW_REQUIRED
            q_corr = 0.70
            detail = (
                f"{license_spdx}: obligations for {distribution_type} distribution "
                f"require legal review."
            )

    conf = Confidence(
        q_artifact=q_artifact_tpn,
        q_identity=q_identity,
        q_correlation=q_corr,
    )
    if conf.overall >= min_confidence:
        assertions.append(Assertion(
            component=component.canonical_id,
            context=context,
            claim=claim,
            dimension=Dimension.LICENSING,
            evidence=evidence,
            confidence=conf,
            detail=detail,
            timestamp=ts,
        ))

    return assertions


def sigma_A(
    component: NormalizedComponent,
    context: str,
    tmbom_boundaries: List[NormalizedTMBOM],
    q_identity: float,
    q_artifact_tmbom: float = 0.85,
    min_confidence: float = 0.40,
) -> List[Assertion]:
    """
    σ_A: Architectural signal extractor.

    Evaluates TMBOM trust boundaries to identify components with elevated
    architectural exposure in the deployment context.

    A component receives ELEVATED_THREAT when it is listed in a boundary's
    exposure_ids (i.e., it sits on a sensitive trust boundary, not behind it).
    """
    ts = datetime.now(timezone.utc)
    assertions = []

    exposed_boundaries = [
        b for b in tmbom_boundaries
        if component.canonical_id in b.exposure_ids
    ]

    if not exposed_boundaries:
        return assertions

    evidence = [b.boundary_id for b in exposed_boundaries]
    detail = (
        f"Component sits on trust "
        f"{'boundary' if len(exposed_boundaries) == 1 else 'boundaries'} "
        f"adjacent to a sensitive data path or privileged zone: "
        f"{', '.join(b.boundary_id + ' (' + b.description + ')' for b in exposed_boundaries)}. "
        f"Exposure is deployment-specific."
    )

    conf = Confidence(
        q_artifact=q_artifact_tmbom,
        q_identity=q_identity,
        q_correlation=0.90,
    )
    if conf.overall >= min_confidence:
        assertions.append(Assertion(
            component=component.canonical_id,
            context=context,
            claim=Claim.ELEVATED_THREAT,
            dimension=Dimension.ARCHITECTURE,
            evidence=evidence,
            confidence=conf,
            detail=detail,
            timestamp=ts,
        ))

    return assertions


def sigma_AI(
    component: NormalizedComponent,
    context: str,
    aivex_entries: List[NormalizedAIVEX],
    tmbom_boundaries: List[NormalizedTMBOM],
    q_identity: float,
    q_artifact_aivex: float = 0.82,
    min_confidence: float = 0.40,
) -> List[Assertion]:
    """
    σ_AI: AI behavioral signal extractor.

    Evaluates AIVEX entries against TMBOM mitigations to produce AI
    dimension assertions. Implements the double-evidence requirement for
    PROMPT_INJECTION_RISK_BOUNDED (§5.2): both AIVEX susceptibility
    documentation AND a TMBOM mitigation node are required for the
    bounded claim; without TMBOM corroboration, AI_BEHAVIOR_RISK is emitted.

    CWE-1427 is the weakness anchor for prompt injection (per CycloneDX #956).
    """
    ts = datetime.now(timezone.utc)
    assertions = []

    component_entries = [
        e for e in aivex_entries
        if e.component_id.lower() == component.canonical_id.lower()
        or e.component_id.lower() == component.name.lower()
    ]

    if not component_entries:
        return assertions

    # Find TMBOM mitigations available for this component
    mitigating_boundaries = [
        b for b in tmbom_boundaries
        if b.mitigations and component.canonical_id in b.component_ids
    ]

    for entry in component_entries:
        evidence: List[str] = []
        if entry.evidence_ref:
            evidence.append(entry.evidence_ref)

        claim: Claim
        q_corr: float
        detail: str

        if entry.risk_type in ("prompt_injection", "indirect_injection"):
            cwe = entry.cwe_id or "CWE-1427"
            if mitigating_boundaries:
                # Double-evidence: AIVEX + TMBOM mitigation → BOUNDED claim
                for b in mitigating_boundaries:
                    if b.mitigations:
                        evidence.extend(b.mitigations[:1])  # first mitigation reference
                claim = Claim.PROMPT_INJECTION_RISK_BOUNDED
                q_corr = 0.88
                detail = (
                    f"Prompt-injection susceptibility ({cwe}) mitigated by "
                    f"TMBOM-defined input controls at "
                    f"{', '.join(b.boundary_id for b in mitigating_boundaries)}. "
                    f"Double evidence (AIVEX + TMBOM) verified."
                )
            else:
                # Single evidence only → AI_BEHAVIOR_RISK
                claim = Claim.AI_BEHAVIOR_RISK
                q_corr = 0.85
                detail = (
                    f"Prompt-injection susceptibility ({cwe}) documented in AIVEX. "
                    f"No TMBOM input-control mitigation confirmed. "
                    f"Governance action required before deployment in this context."
                )

        elif entry.risk_type == "behavior_risk":
            claim = Claim.AI_BEHAVIOR_RISK
            q_corr = 0.80
            atlas = f" (MITRE ATLAS: {entry.mitre_atlas_id})" if entry.mitre_atlas_id else ""
            detail = (
                f"Adversarial-input behavioral risk{atlas} documented in AIVEX "
                f"for this deployment context."
            )

        elif entry.risk_type == "training_risk":
            claim = Claim.AI_BEHAVIOR_RISK
            q_corr = 0.70
            detail = (
                "Training-data provenance concern documented. "
                "Deployment risk requires formal assessment before release."
            )

        else:
            claim = Claim.AI_BEHAVIOR_RISK
            q_corr = 0.65
            detail = f"AI/ML risk ({entry.risk_type}) documented in AIVEX."

        conf = Confidence(
            q_artifact=q_artifact_aivex,
            q_identity=q_identity,
            q_correlation=q_corr,
        )
        if conf.overall >= min_confidence:
            assertions.append(Assertion(
                component=component.canonical_id,
                context=context,
                claim=claim,
                dimension=Dimension.AI,
                evidence=evidence,
                confidence=conf,
                detail=detail,
                timestamp=ts,
            ))

    return assertions
