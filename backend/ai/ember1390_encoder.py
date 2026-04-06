"""
ember1390_encoder.py
====================
Feature extractor cho file PE — khớp CHÍNH XÁC với pipeline train trong V3.0
(train_ember2017_full_gpu.py / vectorize_ember_raw).

Public API (không đổi):
    extract_feature1390_from_exe(exe_path: str) -> np.ndarray  # shape (1, 1390)
    raw_to_feature1390(raw_obj: dict)            -> np.ndarray  # shape (1390,)
"""

import json
from typing import Any, Dict

import numpy as np
from sklearn.feature_extraction import FeatureHasher

# =========================
# NUMPY COMPAT PATCH
# ember cũ dùng np.int / np.bool / np.float...
# Dùng warnings filter để tránh FutureWarning khi check hasattr trên deprecated aliases
# =========================
import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore", FutureWarning)
    warnings.simplefilter("ignore", DeprecationWarning)
    for _attr, _val in [("int", int), ("bool", bool), ("float", float), ("object", object), ("complex", complex)]:
        if not hasattr(np, _attr):
            setattr(np, _attr, _val)

try:
    import lief
except ImportError:
    lief = None

try:
    import ember
except ImportError as e:
    ember = None
    EMBER_IMPORT_ERROR = e
else:
    EMBER_IMPORT_ERROR = None


def _patch_lief_compat():
    if lief is None:
        return
    fallback_exc = Exception
    for name in ["bad_format", "bad_file", "pe_error", "parser_error", "read_out_of_bound"]:
        if not hasattr(lief, name):
            setattr(lief, name, fallback_exc)


_patch_lief_compat()


def _safe_list(x, n=0):
    if isinstance(x, list):
        return x
    return [0] * n


# =========================
# RAW FEATURE EXTRACTION
# =========================
def extract_raw_features_from_exe(exe_path: str) -> Dict[str, Any]:
    if ember is None:
        raise ImportError(f"Không import được thư viện ember: {EMBER_IMPORT_ERROR}")

    with open(exe_path, "rb") as f:
        bytez = f.read()

    try:
        extractor = ember.PEFeatureExtractor(feature_version=1)
        raw_obj = extractor.raw_features(bytez)
    except Exception as e:
        raise RuntimeError(
            f"Không trích được raw features từ file PE. "
            f"Có thể file không hợp lệ hoặc ember/lief/numpy chưa tương thích. "
            f"Chi tiết: {e}"
        ) from e

    if isinstance(raw_obj, str):
        raw_obj = json.loads(raw_obj)

    return raw_obj


# =========================
# VECTORIZE — khớp với train_ember2017_full_gpu.py :: vectorize_ember_raw()
# =========================
def raw_to_feature1390(obj: Dict[str, Any]) -> np.ndarray:
    feats = []

    # 1) histogram: 256
    histogram = _safe_list(obj.get("histogram", []), 256)
    if len(histogram) < 256:
        histogram = histogram + [0] * (256 - len(histogram))
    feats.extend(histogram[:256])

    # 2) byteentropy: 256
    byteentropy = _safe_list(obj.get("byteentropy", []), 256)
    if len(byteentropy) < 256:
        byteentropy = byteentropy + [0] * (256 - len(byteentropy))
    feats.extend(byteentropy[:256])

    # 3) strings: 7 scalars + printabledist[96] = 103
    strings = obj.get("strings", {}) or {}
    printabledist = _safe_list(strings.get("printabledist", []), 96)
    if len(printabledist) < 96:
        printabledist = printabledist + [0] * (96 - len(printabledist))

    feats.extend([
        float(strings.get("numstrings", 0)),
        float(strings.get("avlength", 0)),
        float(strings.get("entropy", 0)),
        float(strings.get("paths", 0)),
        float(strings.get("urls", 0)),
        float(strings.get("registry", 0)),
        float(strings.get("MZ", 0)),
    ])
    feats.extend(printabledist[:96])

    # 4) general: 10
    general = obj.get("general", {}) or {}
    feats.extend([
        float(general.get("size", 0)),
        float(general.get("vsize", 0)),
        float(general.get("has_debug", 0)),
        float(general.get("exports", 0)),
        float(general.get("imports", 0)),
        float(general.get("has_relocations", 0)),
        float(general.get("has_resources", 0)),
        float(general.get("has_signature", 0)),
        float(general.get("has_tls", 0)),
        float(general.get("symbols", 0)),
    ])

    # 5) header: FeatureHasher(128)
    header = obj.get("header", {}) or {}
    coff = header.get("coff", {}) or {}
    optional = header.get("optional", {}) or {}

    header_tokens = []
    for k, v in coff.items():
        header_tokens.append(f"coff_{k}={v}")
    for k, v in optional.items():
        header_tokens.append(f"opt_{k}={v}")

    header_hashed = (
        FeatureHasher(n_features=128, input_type="string")
        .transform([header_tokens])
        .toarray()[0]
    )
    feats.extend(header_hashed)

    # 6) section: 3 nums + 5×FeatureHasher(50) = 253
    section = obj.get("section", {}) or {}
    sections = section.get("sections", []) or []
    entry = section.get("entry", "") or ""

    feats.extend([
        float(len(sections)),
        float(sum(1 for s in sections if s.get("size", 0) == 0)),
        float(sum(1 for s in sections if s.get("name", "") == "")),
    ])

    section_size_pairs    = [(s.get("name", ""), float(s.get("size", 0)))    for s in sections]
    section_entropy_pairs = [(s.get("name", ""), float(s.get("entropy", 0))) for s in sections]
    section_vsize_pairs   = [(s.get("name", ""), float(s.get("vsize", 0)))   for s in sections]

    entry_props = []
    for s in sections:
        if s.get("name", "") == entry:
            entry_props.extend(s.get("props", []))

    feats.extend(FeatureHasher(n_features=50, input_type="pair").transform([section_size_pairs]).toarray()[0])
    feats.extend(FeatureHasher(n_features=50, input_type="pair").transform([section_entropy_pairs]).toarray()[0])
    feats.extend(FeatureHasher(n_features=50, input_type="pair").transform([section_vsize_pairs]).toarray()[0])
    feats.extend(FeatureHasher(n_features=50, input_type="string").transform([[entry]]).toarray()[0])
    feats.extend(FeatureHasher(n_features=50, input_type="string").transform([entry_props]).toarray()[0])

    # 7) imports: FeatureHasher(256)
    imports = obj.get("imports", {}) or {}
    import_tokens = []
    if isinstance(imports, dict):
        for dll, funcs in imports.items():
            import_tokens.append(f"dll:{dll}")
            if isinstance(funcs, list):
                for fn in funcs:
                    import_tokens.append(f"imp:{dll}:{fn}")

    feats.extend(FeatureHasher(n_features=256, input_type="string").transform([import_tokens]).toarray()[0])

    # 8) exports: FeatureHasher(128)
    exports = obj.get("exports", []) or []
    if not isinstance(exports, list):
        exports = []

    feats.extend(FeatureHasher(n_features=128, input_type="string").transform([exports]).toarray()[0])

    x = np.asarray(feats, dtype=np.float32)
    assert x.shape[0] == 1390, f"Feature dim={x.shape[0]}, expected 1390"
    return x


def extract_feature1390_from_exe(exe_path: str) -> np.ndarray:
    raw_obj = extract_raw_features_from_exe(exe_path)
    x = raw_to_feature1390(raw_obj)
    return x.reshape(1, -1)


if __name__ == "__main__":
    x = extract_feature1390_from_exe("sample.exe")
    print("Feature shape:", x.shape)
    print("First 30 values:", x[0][:30])
