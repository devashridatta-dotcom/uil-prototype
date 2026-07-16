# Unified Intelligence Layer (UIL) — Prototype v0.1

Proof-of-concept implementation of the Unified Intelligence Layer for software supply chain governance,
submitted to ACM SCORED '26.

UIL transforms heterogeneous supply chain artifacts (SBOM, VEX, TPN, TMBOM, AIVEX) into structured,
machine-interpretable safety-relevance assertions over which policy-as-code can be evaluated.

## Architecture

```
Artifacts (SBOM · VEX · TPN · TMBOM · AIVEX)
        │
        ▼
┌─────────────────────────────────────────────────┐
│  Stage 1 — Normalization                        │
│  SPDX / CycloneDX / CSAF / OpenVEX → internal  │
├─────────────────────────────────────────────────┤
│  Stage 2 — Identity Resolution                  │
│  PURL / CPE / SWID / digest → canonical id     │
├─────────────────────────────────────────────────┤
│  Stage 3 — Correlation Engine                   │
│  σ_S (security) · σ_L (license)                │
│  σ_A (architecture) · σ_AI (AI/AIVEX)          │
├─────────────────────────────────────────────────┤
│  Stage 4 — Assertion Store                      │
│  (component, context, claim, evidence,          │
│   confidence, timestamp)                        │
├─────────────────────────────────────────────────┤
│  Stage 5 — Policy Engine (OPA / Rego)           │
│  Φ_P aggregation → release decision             │
└─────────────────────────────────────────────────┘
        │
        ▼
Release Decision  ·  Assertion Store JSON  ·  Audit Trail
```

## Installation

```bash
git clone https://github.com/[AUTHOR]/uil-prototype.git
cd uil-prototype
pip install -r requirements.txt
```

OPA is required for Rego policy evaluation. A Python-native fallback evaluator is included
and runs without OPA:

```bash
# With OPA (https://www.openpolicyagent.org/docs/latest/#running-opa)
opa run --server &

# Without OPA (Python fallback)
# Set USE_OPA=false in config or pass --no-opa flag
```

## Quick Start

```bash
# Run the worked example from the SCORED '26 paper (§8 scenario)
python -m uil.pipeline --input examples/openssl_scenario.json

# Run on a real CycloneDX SBOM with synthetic VEX overlay
python -m uil.pipeline \
  --sbom examples/dropwizard_1.3.15.json \
  --vex  examples/synthetic_vex_4pct.json \
  --tmbom examples/minimal_tmbom.json \
  --policy policy/release.rego \
  --output assertion_store.json

# Run scalability benchmark (10 to 50,000 components)
python -m uil.benchmark --sizes 10,100,1000,10000,50000
```

## Interactive Prototype

A browser-based interactive prototype is available at:

**[UIL Interactive Prototype](https://[AUTHOR].github.io/uil-prototype/)**

The prototype runs the full five-stage pipeline in the browser, allowing you to:
- Configure all five artifact signal inputs (σ_S, σ_L, σ_A, σ_AI)
- Select identity resolution strategy and confidence threshold
- Watch the pipeline animation stage by stage
- Inspect the generated Assertion Store JSON and audit trail
- Copy the full JSON output for use in downstream systems

## Repository Structure

```
uil-prototype/
├── src/uil/
│   ├── __init__.py
│   ├── pipeline.py          # Main five-stage pipeline orchestrator
│   ├── normalizer.py        # Stage 1: artifact normalization
│   ├── identity.py          # Stage 2: hierarchical identity resolution
│   ├── correlator.py        # Stage 3: σ_S / σ_L / σ_A / σ_AI extractors
│   ├── assertion_store.py   # Stage 4: assertion storage and querying
│   ├── policy_engine.py     # Stage 5: Rego / Python policy evaluation
│   └── models.py            # Data models: Assertion, Confidence, Claim
├── policy/
│   ├── release.rego         # Strict-veto Φ_P policy (Listing 1 in paper)
│   └── release_weighted.rego# Weighted threshold Φ_P variant
├── examples/
│   ├── openssl_scenario.json        # §8 worked example inputs
│   ├── synthetic_vex_4pct.json      # 4% VEX overlay used in §8.3
│   ├── minimal_tmbom.json           # Minimal TMBOM for §8.3 experiment
│   └── assertion_store_example.json # Expected output (Listing 2 in paper)
├── tests/
│   ├── test_normalizer.py
│   ├── test_identity.py
│   ├── test_correlator.py
│   ├── test_pipeline.py
│   └── test_policy.py
├── docs/
│   └── index.html           # Interactive browser prototype
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Confidence Model

Assertion confidence is computed multiplicatively:

```
Conf(A) = Q_artifact · Q_identity · Q_correlation
```

| Factor | Description |
|--------|-------------|
| Q_artifact | Completeness and provenance quality of the source artifact |
| Q_identity | Strength of cross-artifact identity resolution (see Algorithm 1) |
| Q_correlation | Strength of the inferential step that combined the inputs |

Identity resolution strategies and their Q_identity values:

| Strategy | Q_identity | Condition |
|----------|-----------|-----------|
| DIGEST | 1.00 | Content-addressed digest match |
| EXACT_PURL | 0.90 | Canonical PURL exact match |
| NORMALIZED_COORDS | 0.75 | Type + name + resolved version |
| FUZZY_VERSION | 0.50 | Type + name match, version range overlap |
| NONE | 0.00 | No match; assertion suppressed |

## Policy Engine

The prototype ships with two Rego policies:

- `policy/release.rego` — strict-veto Φ_P: any `REMEDIATION_REQUIRED` or `AI_BEHAVIOR_RISK`
  assertion blocks release; `ELEVATED_THREAT` routes to risk acceptance
- `policy/release_weighted.rego` — weighted threshold Φ_P: assertions are aggregated
  against a configurable threshold τ_P

A Python-native fallback evaluator (`uil/policy_engine.py`) implements the same logic
without requiring OPA, enabling the prototype to run in environments without OPA installed.

## Scalability Results

From §8.2 of the paper (single-threaded Python, commodity hardware):

| Components | Assertions | Runtime | Peak RSS |
|-----------|-----------|---------|---------|
| 10 | 6 | 0.002s | 19.2 MB |
| 100 | 34 | 0.004s | 19.6 MB |
| 1,000 | 337 | 0.034s | 23.3 MB |
| 10,000 | 3,328 | 0.661s | 58.6 MB |
| 50,000 | 17,007 | 11.110s | 227.4 MB |

All sizes produce deterministic rerun output.

## Citation

If you use this prototype in your research, please cite:

```bibtex
@inproceedings{uil2026,
  title     = {A Unified Intelligence Layer for Software Supply Chain Governance},
  author    = {Anonymous},
  booktitle = {ACM SCORED '26: Workshop on Software Supply Chain Offensive Research
               and Ecosystem Defenses},
  year      = {2026},
  note      = {Companion prototype: https://github.com/[AUTHOR]/uil-prototype}
}
```

## License

Apache 2.0 — see LICENSE.
