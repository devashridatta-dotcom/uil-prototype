# policy/release.rego — UIL strict-veto release policy (Φ_P)
#
# This is the canonical Rego policy specification (Listing 1 in the SCORED '26 paper).
# The Python fallback in uil/policy_engine.py implements identical logic.
#
# Evaluated by OPA against the Assertion Store output of Stage 4.
# Input schema: { assertions: [...], min_confidence: float }

package uil.release

default decision := "APPROVE"
default reason   := "All assertions clear policy thresholds."

min_confidence := input.min_confidence

# ── Block claims: any of these blocks release ─────────────────────────────────

block_claims := {
    "REMEDIATION_REQUIRED",
    "AI_BEHAVIOR_RISK",
    "LICENSE_REVIEW_REQUIRED",
}

block_reasons[reason] {
    some a in input.assertions
    a.claim in block_claims
    a.confidence.overall >= min_confidence
    reason := sprintf("BLOCK — %s on %s (conf=%.3f)", [
        a.claim, a.component, a.confidence.overall
    ])
}

# ── Risk-acceptance claims: require formal approval ───────────────────────────

risk_claims := {
    "ELEVATED_THREAT",
    "PROMPT_INJECTION_RISK_BOUNDED",
}

risk_acceptance_reasons[reason] {
    some a in input.assertions
    a.claim in risk_claims
    a.confidence.overall >= min_confidence
    reason := sprintf("RISK_ACCEPT — %s on %s (conf=%.3f)", [
        a.claim, a.component, a.confidence.overall
    ])
}

# ── Low confidence: route to human review ────────────────────────────────────

low_confidence_reasons[reason] {
    some a in input.assertions
    a.confidence.overall < min_confidence
    reason := sprintf("LOW_CONF — %s on %s (conf=%.3f < threshold=%.2f)", [
        a.claim, a.component, a.confidence.overall, min_confidence
    ])
}

# ── Decision logic ────────────────────────────────────────────────────────────

decision := "BLOCK" if {
    count(block_reasons) > 0
}

decision := "RISK_ACCEPT_REQUIRED" if {
    count(block_reasons) == 0
    count(risk_acceptance_reasons) > 0
}

decision := "HUMAN_REVIEW" if {
    count(block_reasons) == 0
    count(risk_acceptance_reasons) == 0
    count(low_confidence_reasons) > 0
}

reason := concat("; ", block_reasons) if {
    count(block_reasons) > 0
}

reason := concat("; ", risk_acceptance_reasons) if {
    count(block_reasons) == 0
    count(risk_acceptance_reasons) > 0
}

# ── Output package ────────────────────────────────────────────────────────────

output := {
    "decision":               decision,
    "reason":                 reason,
    "block_assertions":       [a | some a in input.assertions; a.claim in block_claims; a.confidence.overall >= min_confidence],
    "risk_accept_assertions": [a | some a in input.assertions; a.claim in risk_claims;  a.confidence.overall >= min_confidence],
    "low_confidence":         [a | some a in input.assertions; a.confidence.overall < min_confidence],
    "assertion_count":        count(input.assertions),
    "reproducible":           true,
}
