"""
uil/identity.py — Stage 2: Hierarchical identity resolution (Algorithm 1, §4.3).

Resolves a reference r (PURL, CPE, SWID, or digest) against a normalized
component set C, returning the highest-confidence match.
"""
from __future__ import annotations
import re
from typing import List, Optional, Tuple
from .models import NormalizedComponent, IdentityStrategy, Q_IDENTITY


def normalize_purl(purl: str) -> Optional[Tuple[str, str, str]]:
    """
    Extract (ecosystem, name, version) triple from a PURL string,
    stripping qualifiers and subpaths.

    Returns None if the PURL cannot be parsed.
    """
    # pkg:ecosystem/[namespace/]name@version[?qualifiers][#subpath]
    pattern = re.compile(
        r"^pkg:(?P<eco>[^/]+)/(?:(?P<ns>[^/]+)/)?(?P<name>[^@?#]+)"
        r"(?:@(?P<ver>[^?#]+))?",
        re.IGNORECASE,
    )
    m = pattern.match(purl.strip())
    if not m:
        return None
    eco  = m.group("eco").lower()
    name = m.group("name").lower()
    ver  = (m.group("ver") or "").lower()
    return (eco, name, ver)


def resolve_version_range(version: str) -> str:
    """
    Collapse a version range expression to its lower bound for fuzzy matching.
    e.g. ">=3.0.0,<4.0.0" → "3.0.0"
    """
    # Extract first version-like token
    m = re.search(r"(\d+\.\d+[\.\d]*)", version)
    return m.group(1) if m else version


def hierarchical_resolve(
    reference: str,
    component_set: List[NormalizedComponent],
    digest: Optional[str] = None,
) -> Tuple[Optional[NormalizedComponent], IdentityStrategy, float]:
    """
    Algorithm 1: Hierarchical identity resolution.

    Input:
      reference      — PURL, CPE, SWID, or content-addressed digest string
      component_set  — normalized component set C from Stage 1
      digest         — optional content-addressed digest for highest-confidence match

    Output:
      (component, strategy, q_identity)

    Resolution order (highest confidence first):
      1. DIGEST        — exact content-hash match              Q = 1.00
      2. EXACT_PURL    — canonical PURL exact match            Q = 0.90
      3. NORMALIZED_COORDS — type + name + resolved version    Q = 0.75
      4. FUZZY_VERSION — type + name match (any version)       Q = 0.50
      5. NONE          — no match; assertion suppressed        Q = 0.00
    """
    # ── Step 1: Digest match ──────────────────────────────────────────────────
    if digest:
        for c in component_set:
            if c.digest and c.digest == digest:
                return c, IdentityStrategy.DIGEST, Q_IDENTITY[IdentityStrategy.DIGEST]

    # ── Step 2: Exact PURL match ──────────────────────────────────────────────
    for c in component_set:
        if c.canonical_id.strip().lower() == reference.strip().lower():
            return c, IdentityStrategy.EXACT_PURL, Q_IDENTITY[IdentityStrategy.EXACT_PURL]

    # ── Step 3: Normalized coords match ───────────────────────────────────────
    ref_coords = normalize_purl(reference)
    if ref_coords:
        ref_eco, ref_name, ref_ver = ref_coords
        for c in component_set:
            c_eco, c_name, c_ver = c.ecosystem.lower(), c.name.lower(), c.version.lower()
            if c_eco == ref_eco and c_name == ref_name and c_ver == ref_ver:
                return (
                    c,
                    IdentityStrategy.NORMALIZED_COORDS,
                    Q_IDENTITY[IdentityStrategy.NORMALIZED_COORDS],
                )

    # ── Step 4: Fuzzy version match ───────────────────────────────────────────
    if ref_coords:
        ref_eco, ref_name, _ = ref_coords
        for c in component_set:
            if c.ecosystem.lower() == ref_eco and c.name.lower() == ref_name:
                return (
                    c,
                    IdentityStrategy.FUZZY_VERSION,
                    Q_IDENTITY[IdentityStrategy.FUZZY_VERSION],
                )

    # ── Step 5: No match ─────────────────────────────────────────────────────
    return None, IdentityStrategy.NONE, Q_IDENTITY[IdentityStrategy.NONE]


def resolve_all(
    references: List[str],
    component_set: List[NormalizedComponent],
    digests: Optional[dict] = None,
) -> List[Tuple[str, Optional[NormalizedComponent], IdentityStrategy, float]]:
    """
    Resolve a list of references against a component set.

    Returns a list of (reference, component, strategy, q_identity) tuples.
    """
    digests = digests or {}
    results = []
    for ref in references:
        digest = digests.get(ref)
        component, strategy, q_id = hierarchical_resolve(ref, component_set, digest)
        results.append((ref, component, strategy, q_id))
    return results
