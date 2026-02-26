# backend/zero_shot_severity.py

"""
Zero-Shot CVE Severity Classifier using NLI
=============================================

Uses Natural Language Inference (NLI) to classify CVE severity
WITHOUT any task-specific training data.

How it works:
    NLI = "Does this CVE description ENTAIL that it is a CRITICAL vulnerability?"
    → The model answers yes/no/neutral for each severity label
    → The label with highest entailment probability is predicted

Academic significance:
    Zero-shot learning allows the model to generalize to new tasks
    using only pre-trained language understanding. This demonstrates
    that the model truly "understands" security concepts, not just
    pattern-matches on training data keywords.

    Reference: Yin et al. (2019). "Benchmarking Zero-shot Text Classification"
               EMNLP 2019.

    Model: facebook/bart-large-mnli (Lewis et al., 2020, ACL 2020)
    Alternative: typeform/distilbart-mnli-12-3 (smaller, faster)

Models tried (in order):
    1. typeform/distilbart-mnli-12-3    ~600MB  good balance
    2. facebook/bart-large-mnli         ~1.6GB  highest accuracy
    3. cross-encoder/nli-MiniLM2-L6-H768  ~90MB  fastest, smallest

Public API:
    is_available() -> bool
    predict(description, vector_string='') -> dict
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Model preference order (first available is used)
_CANDIDATE_MODELS = [
    "typeform/distilbart-mnli-12-3",         # ~600MB balanced
    "facebook/bart-large-mnli",              # ~1.6GB best accuracy
    "cross-encoder/nli-MiniLM2-L6-H768",    # ~90MB fastest
]

# Hypothesis templates for each severity level
# These are the "labels" passed to zero-shot classification
_HYPOTHESES = {
    "CRITICAL": "This is a critical severity vulnerability that allows remote code execution, complete system compromise, or causes critical impact.",
    "HIGH":     "This is a high severity vulnerability that allows significant privilege escalation, data exposure, or major impact requiring immediate patching.",
    "MEDIUM":   "This is a medium severity vulnerability that requires specific conditions or user interaction and has moderate impact.",
    "LOW":      "This is a low severity vulnerability with minimal impact, requiring complex conditions or physical access to exploit.",
}

# Simple candidate labels for pipeline (shorter = more reliable)
_LABELS = [
    "critical severity vulnerability",
    "high severity vulnerability",
    "medium severity vulnerability",
    "low severity vulnerability",
]

_LABEL_MAP = {
    "critical severity vulnerability": "CRITICAL",
    "high severity vulnerability":     "HIGH",
    "medium severity vulnerability":   "MEDIUM",
    "low severity vulnerability":      "LOW",
}

# ── Module-level state ─────────────────────────────────────────────────────────
_pipeline    = None
_model_name  = ""
_loaded      = False
_available   = False


def _load():
    global _pipeline, _model_name, _loaded, _available

    if _loaded:
        return
    _loaded = True

    try:
        from transformers import pipeline as hf_pipeline

        for model_name in _CANDIDATE_MODELS:
            try:
                logger.info("[ZeroShot] Trying %s …", model_name)
                _pipeline   = hf_pipeline(
                    "zero-shot-classification",
                    model=model_name,
                    # device=-1 forces CPU; remove for GPU
                )
                _model_name = model_name
                _available  = True
                logger.info("[ZeroShot] Loaded: %s", model_name)
                break
            except Exception as e:
                logger.debug("[ZeroShot] %s failed: %s", model_name, e)

        if not _available:
            logger.warning(
                "[ZeroShot] No zero-shot model loaded. "
                "pip install transformers torch"
            )

    except ImportError:
        logger.warning("[ZeroShot] transformers not installed")


# ── Public API ─────────────────────────────────────────────────────────────────

def is_available() -> bool:
    _load()
    return _available


def get_model_name() -> str:
    _load()
    return _model_name


def predict(description: str, vector_string: str = "") -> dict:
    """
    Zero-shot classify CVE severity using NLI.

    No training data required — uses pre-trained NLI model to infer
    which severity label best entails from the CVE description.

    Parameters
    ----------
    description   : English CVE description text
    vector_string : optional CVSS vector string (used as extra context)

    Returns
    -------
    dict:
        predicted_severity : "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        confidence         : float  (entailment probability of top label)
        probabilities      : {CRITICAL: f, HIGH: f, MEDIUM: f, LOW: f}
        source             : "zero_shot_nli"
        model              : model name used
    """
    if not is_available():
        return {}

    try:
        # Build input text
        text = description.strip()
        if vector_string:
            # Append CVSS metadata as natural language hint
            av_hint = ""
            for part in vector_string.split("/"):
                if part.startswith("AV:"):
                    av_hint = {
                        "N": " This vulnerability is exploitable over the network.",
                        "A": " This vulnerability requires adjacent network access.",
                        "L": " This vulnerability requires local access.",
                        "P": " This vulnerability requires physical access.",
                    }.get(part.split(":")[1], "")
            text = text + av_hint

        # Truncate to avoid model limits
        if len(text) > 1500:
            text = text[:1500]

        # Run zero-shot classification
        result = _pipeline(
            text,
            candidate_labels=_LABELS,
            multi_label=False,
            hypothesis_template="{}.",
        )

        # Map labels back to severity names
        probs = {}
        for label, score in zip(result["labels"], result["scores"]):
            sev = _LABEL_MAP.get(label, label.upper())
            probs[sev] = round(float(score), 4)

        top_label  = result["labels"][0]
        top_sev    = _LABEL_MAP.get(top_label, "MEDIUM")
        confidence = float(result["scores"][0])

        # Ensure all 4 labels are present
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            probs.setdefault(sev, 0.0)

        return {
            "predicted_severity": top_sev,
            "confidence":  round(confidence, 4),
            "probabilities": probs,
            "source": "zero_shot_nli",
            "model":  _model_name,
        }

    except Exception as e:
        logger.error("[ZeroShot] predict error: %s", e)
        return {}
