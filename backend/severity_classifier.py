# backend/severity_classifier.py

"""
Severity Classifier — inference module.

Loads models/severity_clf.pkl (TF-IDF + Logistic Regression pipeline)
trained by untils/train_severity_model.py.

Public API
----------
is_available() -> bool
    True when the model file exists and loaded without error.

predict(description, vector_string='') -> dict
    {
        "predicted_severity": "CRITICAL|HIGH|MEDIUM|LOW",
        "confidence": float,          # max class probability
        "probabilities": {            # all class probabilities
            "CRITICAL": float, "HIGH": float,
            "MEDIUM": float, "LOW": float,
        },
        "source": "ml_classifier",
    }
    Returns {} on failure / unavailability.
"""

import pickle
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_MODEL_PATH = _ROOT / "models" / "severity_clf.pkl"

# Module-level cache
_pipeline = None
_classes = None
_loaded = False


def _load():
    """Attempt to load the model once."""
    global _pipeline, _classes, _loaded
    if _loaded:
        return
    _loaded = True
    try:
        import sklearn  # noqa: F401 – ensure scikit-learn is available
        with open(_MODEL_PATH, "rb") as f:
            data = pickle.load(f)
        _pipeline = data["pipeline"]
        _classes = list(data.get("classes", []))
        print(f"[+] Severity Classifier loaded  ({len(_classes)} classes: {_classes})")
    except FileNotFoundError:
        print(f"[i] Severity Classifier: model not found at {_MODEL_PATH}")
        print("    Run:  python untils/train_severity_model.py")
    except ImportError:
        print("[i] Severity Classifier: scikit-learn not installed")
    except Exception as exc:
        print(f"[!] Severity Classifier load error: {exc}")


def is_available() -> bool:
    """Return True if the classifier is ready to use."""
    _load()
    return _pipeline is not None


def predict(description: str, vector_string: str = "") -> dict:
    """
    Predict CVE severity from description text.

    Parameters
    ----------
    description   : English CVE description text
    vector_string : optional CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/…")

    Returns
    -------
    dict with predicted_severity, confidence, probabilities, source
    or empty dict if classifier unavailable.
    """
    if not is_available():
        return {}

    try:
        import numpy as np

        # Feature engineering — mirror untils/train_severity_model.py
        vscore_tokens = _vectorize_cvss(vector_string)
        text = f"{description} {vscore_tokens}".strip()

        proba = _pipeline.predict_proba([text])[0]
        idx = int(np.argmax(proba))
        predicted = _classes[idx]
        confidence = float(proba[idx])

        probabilities = {cls: float(p) for cls, p in zip(_classes, proba)}
        return {
            "predicted_severity": predicted,
            "confidence": round(confidence, 4),
            "probabilities": probabilities,
            "source": "ml_classifier",
        }
    except Exception as exc:
        print(f"[!] Severity Classifier predict error: {exc}")
        return {}


# ── helpers ───────────────────────────────────────────────────────────────────

def _vectorize_cvss(vector_string: str) -> str:
    """
    Convert CVSS vector string into space-separated tokens.
    e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
         → "av_n ac_l pr_n ui_n s_u c_h i_h a_h"
    """
    if not vector_string:
        return ""
    tokens = []
    for part in vector_string.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            tokens.append(f"{key.lower()}_{val.lower()}")
    return " ".join(tokens)
