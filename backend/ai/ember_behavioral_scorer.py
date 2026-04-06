"""
EMBER Behavioral Scorer
=======================

Dùng XGBoost model được train trên EMBER 2017 (600K PE samples) để
tính xác suất malware cho file PE từ 1390 static features.

Đây là AI scoring thực sự dựa trên ML — thay thế heuristic rule-based
scoring trong PEStaticAnalyzer._calculate_risk().

Metrics khi train:
    ROC-AUC  : 0.9994
    F1-score : 0.9906
    Accuracy : 98.99%
    Dataset  : EMBER 2017 — 600K samples (train) + 200K (test)

Usage:
    from ai.ember_behavioral_scorer import score_file, is_available, get_status

    result = score_file("/path/to/file.exe")
    # result = {
    #     'probability': 0.87,
    #     'level': 'HIGH',
    #     'label': 'MALWARE',
    #     'threshold': 0.51,
    #     'method': 'EMBER XGBoost',
    #     'available': True,
    # }
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

# ── Resolve model path ────────────────────────────────────────────────────────
_BASE      = Path(__file__).parent.parent.parent
_MODEL_PATH = _BASE / 'models' / 'ember2017_xgb.json'

BEST_THRESHOLD = 0.51

# ── Lazy-load expensive dependencies ─────────────────────────────────────────
_model        = None
_load_error   = None
_encoder_ok   = False

def _load():
    global _model, _load_error, _encoder_ok

    if _load_error is not None:
        return False
    if _model is not None:
        return True

    try:
        import xgboost as xgb
        import numpy as np  # noqa: F401 — ensure numpy available
        from ember1390_encoder import extract_feature1390_from_exe  # noqa: F401
        _encoder_ok = True
    except Exception as e:
        _load_error = f"Import error: {e}"
        return False

    if not _MODEL_PATH.exists():
        _load_error = f"Model file not found: {_MODEL_PATH}"
        return False

    try:
        m = xgb.Booster()
        m.load_model(str(_MODEL_PATH))
        _model = m
        return True
    except Exception as e:
        _load_error = f"Model load error: {e}"
        return False


def is_available() -> bool:
    return _load()


def get_status() -> dict:
    ok = _load()
    return {
        'available':   ok,
        'model_path':  str(_MODEL_PATH),
        'model_exists': _MODEL_PATH.exists(),
        'error':       _load_error,
        'threshold':   BEST_THRESHOLD,
        'train_auc':   0.9994,
        'train_f1':    0.9906,
    }


def score_file(file_path: str) -> dict:
    """
    Chạy EMBER XGBoost inference trên một file PE.

    Returns:
        {
            'probability': float,   # 0.0 – 1.0 malware probability
            'level':       str,     # CRITICAL / HIGH / MEDIUM / LOW / CLEAN
            'label':       str,     # MALWARE / SUSPICIOUS / BENIGN
            'threshold':   float,
            'method':      str,
            'available':   bool,
            'error':       str | None,
        }
    """
    _not_available = {
        'probability': None,
        'level':       None,
        'label':       None,
        'threshold':   BEST_THRESHOLD,
        'method':      'EMBER XGBoost (EMBER 2017, 600K samples)',
        'available':   False,
        'error':       None,
    }

    if not _load():
        _not_available['error'] = _load_error
        return _not_available

    try:
        import xgboost as xgb
        import numpy as np
        from ember1390_encoder import extract_feature1390_from_exe

        # Kiểm tra MZ header
        with open(file_path, 'rb') as f:
            sig = f.read(2)
        if sig != b'MZ':
            return {**_not_available, 'available': True,
                    'error': 'Not a PE file (no MZ header)'}

        feats = extract_feature1390_from_exe(file_path)
        feats = np.asarray(feats, dtype=np.float32)
        if feats.ndim == 1:
            feats = feats.reshape(1, -1)

        dtest = xgb.DMatrix(feats)
        prob  = float(_model.predict(dtest)[0])

        # Level mapping
        if prob >= 0.80:
            level = 'CRITICAL'
            label = 'MALWARE'
        elif prob >= 0.51:
            level = 'HIGH'
            label = 'MALWARE'
        elif prob >= 0.35:
            level = 'MEDIUM'
            label = 'SUSPICIOUS'
        elif prob >= 0.15:
            level = 'LOW'
            label = 'SUSPICIOUS'
        else:
            level = 'CLEAN'
            label = 'BENIGN'

        return {
            'probability': round(prob, 4),
            'level':       level,
            'label':       label,
            'threshold':   BEST_THRESHOLD,
            'method':      'EMBER XGBoost (EMBER 2017, 600K samples)',
            'available':   True,
            'error':       None,
        }

    except Exception as e:
        return {**_not_available, 'available': True, 'error': str(e)}
