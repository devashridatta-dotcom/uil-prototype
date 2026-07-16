"""
uil/policy_engine.py — Stage 5: Policy Engine.

Evaluates the Φ_P aggregation over the Assertion Store to produce a
release decision. Ships in two parallel forms:

  1. OPA/Rego evaluator — calls the OPA REST API with policy/release.rego
  2. Python fallback    — implements the same strict-veto logic natively,
                          enabling the prototype to run without OPA installed.

The Python fallback is the default. Set USE_OPA=true in environment or
pass use_opa=True to use the OPA evaluator.
"""
from __future__ import annotations
import json
import os
import subprocess
from typing import List
from .models import Assertion, Claim, PolicyResult


# ── Claim routing tables (strict-veto Φ_P) ────────────────────────────────────

BLOCK_CLAIMS = {
    Claim.REMEDIATION_REQUIRED,
    Claim.AI_BEHAVIOR_RISK,
    Claim.LICENSE_REVIEW_REQUIRED,
}

RISK_ACCEPT_CLAIMS = {
    Claim.ELEVATED_THREAT,
    Claim.PROMPT_INJECTION_RISK_BOUNDED,
}


class PolicyEngine:
    """
    Stage 5: Policy Engine.

    Evaluates policy rules over the Assertion Store to produce a release
    decision. Supports strict-veto and weighted-threshold aggregation
    strategies (§6).
    """

    def __init__(
        self,
        policy_version: str = "strict-veto-v1.0",
        min_confidence: float = 0.40,
        use_opa: bool = False,
        opa_url: str = "http://localhost:8181",
        policy_path: str = "policy/release.rego",
    ):
        self.policy_version = policy_version
        self.min_confidence = min_confidence
        self.use_opa = use_opa or os.environ.get("USE_OPA", "").lower() == "true"
        self.opa_url = opa_url
        self.policy_path = policy_path

    # ── Main entry point ──────────────────────────────────────────────────────

    def evaluate(self, assertions: List[Assertion]) -> PolicyResult:
        if self.use_opa:
            return self._evaluate_opa(assertions)
        return self._evaluate_python(assertions)

    # ── Python fallback (strict-veto Φ_P) ────────────────────────────────────

    def _evaluate_python(self, assertions: List[Assertion]) -> PolicyResult:
        """
        Python-native implementation of the strict-veto Φ_P policy.
        Equivalent to policy/release.rego (Listing 1 in paper).

        Decision logic:
          BLOCK              — any assertion with a block-class claim
                               above the confidence threshold
          RISK_ACCEPT_REQ    — any risk-class claim above threshold,
                               no block-class claims
          HUMAN_REVIEW       — any assertion below confidence threshold,
                               no blocking or risk claims above threshold
          APPROVE            — all assertions clear all thresholds
        """
        above = [a for a in assertions if a.confidence.overall >= self.min_confidence]
        below = [a for a in assertions if a.confidence.overall <  self.min_confidence]

        blocking   = [a for a in above if a.claim in BLOCK_CLAIMS]
        risk_items = [a for a in above if a.claim in RISK_ACCEPT_CLAIMS]

        if blocking:
            claims_str = ", ".join(a.claim.value for a in blocking)
            return PolicyResult(
                decision="BLOCK",
                reason=f"{len(blocking)} blocking assertion(s): {claims_str}",
                policy_version=self.policy_version,
                assertions_used=assertions,
                blocking=blocking,
                risk_accept=risk_items,
                low_confidence=below,
            )

        if risk_items:
            claims_str = ", ".join(a.claim.value for a in risk_items)
            return PolicyResult(
                decision="RISK_ACCEPT_REQUIRED",
                reason=(
                    f"{len(risk_items)} assertion(s) require formal risk acceptance: "
                    f"{claims_str}"
                ),
                policy_version=self.policy_version,
                assertions_used=assertions,
                blocking=[],
                risk_accept=risk_items,
                low_confidence=below,
            )

        if below:
            return PolicyResult(
                decision="HUMAN_REVIEW",
                reason=(
                    f"{len(below)} assertion(s) below confidence threshold "
                    f"({self.min_confidence}) — routed to human review"
                ),
                policy_version=self.policy_version,
                assertions_used=assertions,
                blocking=[],
                risk_accept=[],
                low_confidence=below,
            )

        return PolicyResult(
            decision="APPROVE",
            reason=(
                f"All {len(assertions)} assertion(s) clear policy thresholds. "
                f"Release approved."
            ),
            policy_version=self.policy_version,
            assertions_used=assertions,
            blocking=[],
            risk_accept=[],
            low_confidence=[],
        )

    # ── OPA/Rego evaluator ────────────────────────────────────────────────────

    def _evaluate_opa(self, assertions: List[Assertion]) -> PolicyResult:
        """
        Evaluate policy using OPA REST API.

        Requires OPA running at self.opa_url.
        Falls back to Python evaluator if OPA is unreachable.
        """
        try:
            import urllib.request
            import urllib.error

            input_data = {
                "input": {
                    "assertions": [a.to_dict() for a in assertions],
                    "min_confidence": self.min_confidence,
                }
            }
            body = json.dumps(input_data).encode()
            req = urllib.request.Request(
                f"{self.opa_url}/v1/data/uil/release",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read())

            opa_result = result.get("result", {})
            decision = opa_result.get("decision", "HUMAN_REVIEW")
            reason   = opa_result.get("reason", "OPA policy evaluation")

            blocking   = [a for a in assertions if a.claim in BLOCK_CLAIMS
                          and a.confidence.overall >= self.min_confidence]
            risk_items = [a for a in assertions if a.claim in RISK_ACCEPT_CLAIMS
                          and a.confidence.overall >= self.min_confidence]
            below      = [a for a in assertions if a.confidence.overall < self.min_confidence]

            return PolicyResult(
                decision=decision,
                reason=reason,
                policy_version=f"rego:{self.policy_version}",
                assertions_used=assertions,
                blocking=blocking,
                risk_accept=risk_items,
                low_confidence=below,
            )

        except Exception as e:
            # OPA unreachable — fall back to Python evaluator
            result = self._evaluate_python(assertions)
            result.reason += f" [OPA unavailable: {e}; used Python fallback]"
            return result
