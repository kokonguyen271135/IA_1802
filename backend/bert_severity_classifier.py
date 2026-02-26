# backend/bert_severity_classifier.py

"""
Fine-tuned BERT CVE Severity Classifier
=========================================

Loads the fine-tuned DistilBERT (or SecBERT) model saved by:
    python untils/finetune_bert_severity.py

Replaces the TF-IDF + Logistic Regression classifier with a
transformer-based model trained on NVD CVE descriptions.

Why fine-tuning is better than TF-IDF+LR:
  - Understands semantic context, not just word frequency
  - "exploiting a memory boundary check" ≈ "buffer overflow"
    (TF-IDF misses this; BERT catches it)
  - Trained end-to-end on actual CVE text
  - Significantly higher accuracy on long, technical descriptions

Public API (same interface as severity_classifier.py):
    is_available() -> bool
    predict(description, vector_string='') -> dict

Academic reference:
    Sanh et al. (2020). "DistilBERT, a distilled version of BERT"
    arXiv:1910.01108
"""

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_ROOT       = Path(__file__).parent.parent
_MODEL_DIR  = _ROOT / "models" / "bert_severity"
_META_PATH  = _ROOT / "models" / "bert_severity_meta.json"

# ── Module-level state ─────────────────────────────────────────────────────────
_tokenizer   = None
_model       = None
_meta        = {}
_label2id    = {}
_id2label    = {}
_max_length  = 256
_loaded      = False
_available   = False


def _load():
    global _tokenizer, _model, _meta, _label2id, _id2label
    global _max_length, _loaded, _available

    if _loaded:
        return
    _loaded = True

    if not _MODEL_DIR.exists():
        logger.info(
            "[BERTSeverity] Model not found at %s\n"
            "               Run: python untils/finetune_bert_severity.py",
            _MODEL_DIR,
        )
        return

    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        # Load metadata
        if _META_PATH.exists():
            with open(_META_PATH) as f:
                _meta = json.load(f)
            _label2id   = _meta.get("label2id", {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3})
            _id2label   = {int(k): v for k, v in _meta.get("id2label", {}).items()}
            _max_length = _meta.get("max_length", 256)
        else:
            _label2id = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            _id2label = {0: "CRITICAL", 1: "HIGH", 2: "MEDIUM", 3: "LOW"}

        logger.info("[BERTSeverity] Loading tokenizer + model from %s …", _MODEL_DIR)
        _tokenizer = AutoTokenizer.from_pretrained(str(_MODEL_DIR))
        _model     = AutoModelForSequenceClassification.from_pretrained(str(_MODEL_DIR))
        _model.eval()

        base = _meta.get("base_model", "unknown")
        acc  = _meta.get("test_accuracy", 0)
        f1   = _meta.get("test_macro_f1", 0)
        logger.info(
            "[BERTSeverity] Loaded  base=%s  acc=%.2f%%  macro-F1=%.2f%%",
            base, acc * 100, f1 * 100,
        )

        _available = True

    except Exception as e:
        logger.warning("[BERTSeverity] Load failed: %s", e)
        _available = False


# ── Public API ─────────────────────────────────────────────────────────────────

def is_available() -> bool:
    _load()
    return _available


def get_meta() -> dict:
    """Return training metadata (base model, accuracy, F1, etc.)."""
    _load()
    return _meta


def predict(description: str, vector_string: str = "") -> dict:
    """
    Predict CVE severity from description text using fine-tuned BERT.

    Parameters
    ----------
    description   : English CVE description text
    vector_string : optional CVSS vector string

    Returns
    -------
    dict:
        predicted_severity : "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        confidence         : float  (softmax probability of top class)
        probabilities      : {CRITICAL: f, HIGH: f, MEDIUM: f, LOW: f}
        source             : "bert_finetuned"
        model              : base model name
    """
    if not is_available():
        return {}

    try:
        import torch
        import torch.nn.functional as F

        # Build input text (same format as training)
        text = description.strip()
        if vector_string:
            vtokens = " ".join(
                f"{p.split(':')[0]}_{p.split(':')[1]}"
                for p in vector_string.split("/") if ":" in p
            )
            text = f"{text} [SEP] {vtokens}"

        # Tokenize
        inputs = _tokenizer(
            text,
            max_length=_max_length,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )

        # Inference
        with torch.no_grad():
            outputs = _model(**inputs)
            probs   = F.softmax(outputs.logits, dim=-1).squeeze()

        probs_list = probs.tolist()
        idx        = int(probs.argmax().item())
        predicted  = _id2label.get(idx, "UNKNOWN")
        confidence = float(probs_list[idx])

        return {
            "predicted_severity": predicted,
            "confidence":  round(confidence, 4),
            "probabilities": {
                _id2label.get(i, str(i)): round(float(p), 4)
                for i, p in enumerate(probs_list)
            },
            "source": "bert_finetuned",
            "model":  _meta.get("base_model", str(_MODEL_DIR)),
        }

    except Exception as e:
        logger.error("[BERTSeverity] predict error: %s", e)
        return {}
