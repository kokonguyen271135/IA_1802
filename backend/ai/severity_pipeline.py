"""
Unified Severity Classification Pipeline

Combines TF-IDF + Logistic Regression, Fine-tuned BERT, and Zero-Shot NLI
into a single ensemble prediction with confidence-weighted voting.

Usage:
    from ai.severity_pipeline import enrich_cves, get_status

    cves = enrich_cves(cves)   # adds 'ai_severity' key to each CVE
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

# ── Import individual models (graceful degradation) ──────────────────────────
try:
    from severity_classifier import predict as _tfidf_predict, is_available as _tfidf_ok
except Exception:
    _tfidf_predict = None
    _tfidf_ok = lambda: False

try:
    from bert_severity_classifier import predict as _bert_predict, is_available as _bert_ok
except Exception:
    _bert_predict = None
    _bert_ok = lambda: False

try:
    from zero_shot_severity import predict as _zs_predict, is_available as _zs_ok
except Exception:
    _zs_predict = None
    _zs_ok = lambda: False


SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

# Weights reflect expected model accuracy (higher = more trust)
_MODEL_WEIGHTS = {
    'bert':      1.00,
    'zero_shot': 0.85,
    'tfidf':     0.70,
}


def predict_severity(description: str, vector_string: str = '') -> dict | None:
    """
    Ensemble severity prediction from all available models.

    Returns:
        {
            'predicted_severity': 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW',
            'confidence': float,          # 0.0 – 1.0
            'source': 'ensemble'|'bert'|'tfidf'|'zero_shot',
            'models_used': [str, ...],
            'individual': {               # raw output from each model
                'tfidf': {...} | None,
                'bert':  {...} | None,
                'zero_shot': {...} | None,
            },
            'ensemble_scores': {severity: score, ...}  # only when ensemble
        }
        or None if no model is available.
    """
    results: dict[str, dict] = {}

    if _tfidf_ok() and _tfidf_predict:
        try:
            r = _tfidf_predict(description=description, vector_string=vector_string)
            if r:
                results['tfidf'] = r
        except Exception:
            pass

    if _bert_ok() and _bert_predict:
        try:
            r = _bert_predict(description=description, vector_string=vector_string)
            if r:
                results['bert'] = r
        except Exception:
            pass

    if _zs_ok() and _zs_predict:
        try:
            r = _zs_predict(description=description, vector_string=vector_string)
            if r:
                results['zero_shot'] = r
        except Exception:
            pass

    if not results:
        return None

    models_used = list(results.keys())

    # ── Single model: return directly ────────────────────────────────────────
    if len(results) == 1:
        key = models_used[0]
        r   = results[key]
        return {
            'predicted_severity': r['predicted_severity'],
            'confidence':         round(r.get('confidence', 0.0), 3),
            'source':             key,
            'models_used':        [key],
            'individual':         {k: results.get(k) for k in ('tfidf', 'bert', 'zero_shot')},
        }

    # ── Multi-model ensemble: confidence-weighted voting ─────────────────────
    sev_scores: dict[str, float] = {s: 0.0 for s in SEVERITY_LEVELS}

    for model, result in results.items():
        weight = _MODEL_WEIGHTS.get(model, 0.75)
        conf   = result.get('confidence', 0.5)
        sev    = result.get('predicted_severity', 'MEDIUM')

        # Primary vote: full weight × confidence on predicted severity
        if sev in sev_scores:
            sev_scores[sev] += weight * conf

        # Soft vote: partial weight distributed via probability vector
        probs = result.get('probabilities', {})
        for s, p in probs.items():
            if s in sev_scores:
                sev_scores[s] += weight * 0.25 * p

    # Normalize
    total = sum(sev_scores.values()) or 1.0
    normalized = {k: round(v / total, 4) for k, v in sev_scores.items()}

    best = max(normalized, key=normalized.get)

    return {
        'predicted_severity': best,
        'confidence':         normalized[best],
        'source':             'ensemble',
        'models_used':        models_used,
        'individual':         {k: results.get(k) for k in ('tfidf', 'bert', 'zero_shot')},
        'ensemble_scores':    normalized,
    }


def enrich_cves(cves: list) -> list:
    """
    Add 'ai_severity' key to each CVE dict.
    Returns the same list (mutated in place).
    """
    for cve in cves:
        pred = predict_severity(
            description=cve.get('description', ''),
            vector_string=cve.get('vector_string', ''),
        )
        if pred:
            cve['ai_severity'] = pred
    return cves


def is_available() -> bool:
    return _tfidf_ok() or _bert_ok() or _zs_ok()


def get_status() -> dict:
    return {
        'tfidf':     _tfidf_ok(),
        'bert':      _bert_ok(),
        'zero_shot': _zs_ok(),
        'available': is_available(),
    }
