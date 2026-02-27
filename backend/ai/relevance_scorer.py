"""
Unified CVE Relevance Scorer

Combines rule-based contextual scoring (always available) and SecBERT
semantic scoring (optional) into a single coherent 'relevance' field.

Usage:
    from ai.relevance_scorer import score_cves, is_semantic_available

    cves = score_cves(software_analysis, cves)
    # Each CVE now has: cve['relevance'] = {score, label, method, reasons}
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

try:
    from contextual_scorer import (
        score_cves as _ctx_score,
        build_file_profile as _build_profile,
    )
    _CTX_OK = True
except Exception:
    _CTX_OK = False

try:
    from secbert_cve_scorer import (
        score_cves_semantic as _sec_score,
        build_profile_text  as _build_profile_text,
        is_available        as _sec_ok,
    )
    _SECBERT_IMPORTED = True
except Exception:
    _SECBERT_IMPORTED = False
    _sec_ok = lambda: False


# ── Label thresholds ─────────────────────────────────────────────────────────
def _score_to_label(score: float) -> str:
    if score >= 0.75:
        return 'CRITICAL'
    if score >= 0.55:
        return 'HIGH'
    if score >= 0.35:
        return 'MEDIUM'
    if score >= 0.15:
        return 'LOW'
    return 'MINIMAL'


def score_cves(software_analysis: dict, cves: list) -> list:
    """
    Score CVE relevance to a specific piece of software.

    Args:
        software_analysis: Output from software_analyzer (PE analysis dict)
                           or a simplified dict for package-based analysis.
        cves:              List of CVE dicts from NVD.

    Returns:
        Same CVE list with each entry enriched:
        cve['relevance'] = {
            'score':   float,           # 0.0 – 1.0
            'label':   str,             # CRITICAL/HIGH/MEDIUM/LOW/MINIMAL
            'method':  str,             # 'combined'|'semantic'|'contextual'|'none'
            'reasons': [str, ...],      # human-readable reasons (from contextual scorer)
        }
        List is sorted by relevance score DESC, then CVSS score DESC.
    """
    if not cves:
        return cves

    # ── 1. Rule-based contextual scoring ─────────────────────────────────────
    if _CTX_OK:
        try:
            cves = _ctx_score(software_analysis, cves)
        except Exception:
            pass

    # ── 2. SecBERT semantic scoring ───────────────────────────────────────────
    if _SECBERT_IMPORTED and _sec_ok():
        try:
            cves = _sec_score(software_analysis, cves)
        except Exception:
            pass

    # ── 3. Merge into unified 'relevance' field ───────────────────────────────
    for cve in cves:
        ctx = cve.get('contextual_relevance', {})
        sec = cve.get('secbert_relevance', {})

        ctx_score  = float(ctx.get('score', 0))
        sec_score  = float(sec.get('score', 0))
        ctx_reasons = ctx.get('reasons', [])

        if ctx_score > 0 and sec_score > 0:
            # Weighted combination: SecBERT = 60%, contextual = 40%
            combined = ctx_score * 0.40 + sec_score * 0.60
            method   = 'combined'
        elif sec_score > 0:
            combined = sec_score
            method   = 'semantic'
        elif ctx_score > 0:
            combined = ctx_score
            method   = 'contextual'
        else:
            combined = 0.0
            method   = 'none'

        cve['relevance'] = {
            'score':   round(combined, 4),
            'label':   _score_to_label(combined),
            'method':  method,
            'reasons': ctx_reasons,
        }

    # ── 4. Sort: relevance DESC, then CVSS DESC ───────────────────────────────
    cves.sort(
        key=lambda c: (
            c.get('relevance', {}).get('score', 0.0),
            c.get('cvss_score', 0.0),
        ),
        reverse=True,
    )

    return cves


def get_profile_text(software_analysis: dict) -> str:
    """Return natural-language behavior profile for display."""
    if _SECBERT_IMPORTED:
        try:
            return _build_profile_text(software_analysis)
        except Exception:
            pass
    return ''


def is_semantic_available() -> bool:
    return _SECBERT_IMPORTED and _sec_ok()
