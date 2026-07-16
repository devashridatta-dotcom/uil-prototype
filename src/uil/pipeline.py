"""
uil/pipeline.py — Main five-stage pipeline orchestrator.

Composes all five UIL stages into a single end-to-end pipeline:

  Stage 1 — Normalization
  Stage 2 — Identity Resolution
  Stage 3 — Correlation Engine (σ_S, σ_L, σ_A, σ_AI)
  Stage 4 — Assertion Store
  Stage 5 — Policy Engine (Φ_P)
"""
from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    NormalizedComponent, NormalizedVulnerability, NormalizedTPN,
    NormalizedTMBOM, NormalizedAIVEX, IdentityStrategy, Q_IDENTITY,
)
from .identity import hierarchical_resolve
from .correlator import sigma_S, sigma_L, sigma_A, sigma_AI
from .assertion_store import AssertionStore
from .policy_engine import PolicyEngine


class UILPipeline:
    """
    End-to-end UIL governance pipeline.

    Takes normalized artifact inputs and produces an Assertion Store,
    a policy decision, and a JSON audit trail.
    """

    def __init__(
        self,
        pipeline_version: str = "UIL-v0.1-SCORED26",
        policy_version: str = "strict-veto-v1.0",
        min_confidence: float = 0.40,
        use_opa: bool = False,
        distribution_type: str = "binary_external",
    ):
        self.pipeline_version = pipeline_version
        self.policy_version   = policy_version
        self.min_confidence   = min_confidence
        self.distribution_type = distribution_type
        self.policy_engine = PolicyEngine(
            policy_version=policy_version,
            min_confidence=min_confidence,
            use_opa=use_opa,
        )

    def run(
        self,
        components:    List[NormalizedComponent],
        vulnerabilities: List[NormalizedVulnerability],
        tpn_clauses:   List[NormalizedTPN],
        tmbom_boundaries: List[NormalizedTMBOM],
        aivex_entries: List[NormalizedAIVEX],
        context: str = "unspecified deployment context",
        sbom_quality: float = 0.85,
    ) -> Dict[str, Any]:
        """
        Execute all five pipeline stages and return the full audit package.

        Returns a dict containing:
          - assertion_store: AssertionStore object
          - policy_result:   PolicyResult object
          - audit_json:      str (JSON audit trail)
          - runtime_seconds: float
        """
        t0 = time.perf_counter()
        store = AssertionStore(pipeline_version=self.pipeline_version)

        for component in components:
            # ── Stage 2: Identity resolution ─────────────────────────────────
            # Self-resolution: resolve component against the full set
            _, strategy, q_id = hierarchical_resolve(
                component.canonical_id, components, component.digest
            )

            # ── Stage 3: Correlation Engine ───────────────────────────────────

            # σ_S — security
            store.add_many(sigma_S(
                component=component,
                context=context,
                vulnerabilities=vulnerabilities,
                tmbom_boundaries=tmbom_boundaries,
                q_identity=q_id,
                q_artifact_sbom=sbom_quality,
                min_confidence=self.min_confidence,
            ))

            # σ_L — licensing
            tpn = next(
                (t for t in tpn_clauses
                 if t.component_id.lower() == component.canonical_id.lower()),
                None,
            )
            store.add_many(sigma_L(
                component=component,
                context=context,
                tpn=tpn,
                distribution_type=self.distribution_type,
                q_identity=q_id,
                min_confidence=self.min_confidence,
            ))

            # σ_A — architecture
            store.add_many(sigma_A(
                component=component,
                context=context,
                tmbom_boundaries=tmbom_boundaries,
                q_identity=q_id,
                min_confidence=self.min_confidence,
            ))

            # σ_AI — AI behavioral
            store.add_many(sigma_AI(
                component=component,
                context=context,
                aivex_entries=aivex_entries,
                tmbom_boundaries=tmbom_boundaries,
                q_identity=q_id,
                min_confidence=self.min_confidence,
            ))

        # ── Stage 5: Policy Engine ────────────────────────────────────────────
        policy_result = self.policy_engine.evaluate(store.all)

        runtime = time.perf_counter() - t0
        audit_json = store.to_json(policy_result, self.policy_version)

        return {
            "assertion_store": store,
            "policy_result":   policy_result,
            "audit_json":      audit_json,
            "runtime_seconds": round(runtime, 4),
        }


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="UIL Pipeline — Unified Intelligence Layer prototype v0.1"
    )
    parser.add_argument("--input",   help="Path to JSON scenario file")
    parser.add_argument("--sbom",    help="Path to CycloneDX SBOM JSON")
    parser.add_argument("--vex",     help="Path to VEX JSON overlay")
    parser.add_argument("--tmbom",   help="Path to TMBOM JSON")
    parser.add_argument("--aivex",   help="Path to AIVEX JSON")
    parser.add_argument("--policy",  help="Path to Rego policy file", default="policy/release.rego")
    parser.add_argument("--output",  help="Path for assertion store JSON output", default="assertion_store.json")
    parser.add_argument("--context", help="Deployment context string", default="enterprise deployment")
    parser.add_argument("--min-conf",type=float, default=0.40, help="Minimum confidence threshold")
    parser.add_argument("--no-opa",  action="store_true", help="Use Python fallback (no OPA required)")
    args = parser.parse_args()

    # Load scenario from JSON file if provided
    if args.input:
        scenario = json.loads(Path(args.input).read_text())
        _run_scenario(scenario, args)
    else:
        # Load individual artifact files
        print("UIL Pipeline prototype — provide --input <scenario.json> or individual artifact flags.")
        print("Run: python -m uil.pipeline --input examples/openssl_scenario.json")


def _run_scenario(scenario: dict, args):
    from .models import (
        NormalizedComponent, NormalizedVulnerability,
        NormalizedTPN, NormalizedTMBOM, NormalizedAIVEX,
    )

    components = [NormalizedComponent(**c) for c in scenario.get("components", [])]
    vulns      = [NormalizedVulnerability(**v) for v in scenario.get("vulnerabilities", [])]
    tpn        = [NormalizedTPN(**t) for t in scenario.get("tpn", [])]
    tmbom      = [NormalizedTMBOM(**b) for b in scenario.get("tmbom", [])]
    aivex      = [NormalizedAIVEX(**a) for a in scenario.get("aivex", [])]
    context    = scenario.get("context", args.context)

    pipeline = UILPipeline(
        min_confidence=args.min_conf,
        use_opa=not args.no_opa,
        distribution_type=scenario.get("distribution_type", "binary_external"),
    )
    result = pipeline.run(
        components=components,
        vulnerabilities=vulns,
        tpn_clauses=tpn,
        tmbom_boundaries=tmbom,
        aivex_entries=aivex,
        context=context,
        sbom_quality=scenario.get("sbom_quality", 0.85),
    )

    print(f"\nUIL Pipeline complete in {result['runtime_seconds']}s")
    print(f"Assertions: {result['assertion_store'].count}")
    print(f"Decision:   {result['policy_result'].decision}")
    print(f"Reason:     {result['policy_result'].reason}\n")

    output_path = args.output if hasattr(args, 'output') else "assertion_store.json"
    Path(output_path).write_text(result["audit_json"])
    print(f"Audit trail written to: {output_path}")


if __name__ == "__main__":
    main()
