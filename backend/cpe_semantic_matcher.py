# backend/cpe_semantic_matcher.py

"""
Semantic CPE Matcher — inference module.

Loads:
  models/cpe_index.faiss   — FAISS IndexFlatIP (cosine on normalised vecs)
  models/cpe_meta.pkl      — metadata: {entries: [...], model_name: str}

Built by untils/build_cpe_index.py.

Public API
----------
is_available() -> bool
    True when index + metadata are loaded and SentenceTransformer is present.

match(query, top_k=3) -> list[dict]
    Return top_k candidates with keys:
        vendor, product, cpe_name, display, score (float 0-1)

match_best(query, min_score=0.50) -> dict | None
    Return the single best match (with confidence label) or None.
    {vendor, product, cpe_name, display, score, confidence: "high|medium|low"}
    confidence thresholds:  >= 0.80 → high,  >= 0.60 → medium,  else low
"""

import pickle
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_INDEX_PATH = _ROOT / "models" / "cpe_index.faiss"
_META_PATH  = _ROOT / "models" / "cpe_meta.pkl"

# Module-level cache
_index    = None
_entries  = None
_model    = None
_loaded   = False


def _load():
    """Attempt to load FAISS index + sentence-transformer model once."""
    global _index, _entries, _model, _loaded
    if _loaded:
        return
    _loaded = True

    if not _INDEX_PATH.exists() or not _META_PATH.exists():
        print(f"[i] Semantic CPE Matcher: index files not found.")
        print("    Run:  python untils/build_cpe_index.py")
        return

    try:
        import faiss
        from sentence_transformers import SentenceTransformer

        # Load FAISS index
        _index = faiss.read_index(str(_INDEX_PATH))

        # Load metadata
        with open(_META_PATH, "rb") as f:
            meta = pickle.load(f)
        _entries = meta["entries"]
        model_name = meta.get("model_name", "all-MiniLM-L6-v2")

        # Load (or reuse cached) sentence-transformer
        _model = SentenceTransformer(model_name)

        print(f"[+] Semantic CPE Matcher loaded  "
              f"({_index.ntotal} vectors, model={model_name})")

    except ImportError as exc:
        print(f"[i] Semantic CPE Matcher: missing package — {exc}")
        print("    Install:  pip install sentence-transformers faiss-cpu")
        _index = _entries = _model = None
    except Exception as exc:
        print(f"[!] Semantic CPE Matcher load error: {exc}")
        _index = _entries = _model = None


def is_available() -> bool:
    """Return True if the matcher is ready to use."""
    _load()
    return _index is not None and _entries is not None and _model is not None


def match(query: str, top_k: int = 3) -> list:
    """
    Return top_k CPE candidates for *query* (a software display name).

    Each result dict:
        {vendor, product, cpe_name, display, score}
    Empty list on failure / unavailability.
    """
    if not is_available():
        return []
    try:
        import numpy as np
        emb = _model.encode([query], normalize_embeddings=True).astype("float32")
        k = min(top_k, _index.ntotal)
        scores, indices = _index.search(emb, k)
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0:
                continue
            e = _entries[idx]
            results.append({
                "vendor":   e["vendor"],
                "product":  e["product"],
                "cpe_name": e["cpe_name"],
                "display":  e["display"],
                "score":    round(float(score), 4),
            })
        return results
    except Exception as exc:
        print(f"[!] Semantic CPE Matcher match error: {exc}")
        return []


def match_best(query: str, min_score: float = 0.50) -> dict | None:
    """
    Return the single best match for *query*, or None if below *min_score*.

    Result dict adds a 'confidence' key: "high" / "medium" / "low".
    """
    results = match(query, top_k=1)
    if not results:
        return None
    best = results[0]
    if best["score"] < min_score:
        return None
    score = best["score"]
    if score >= 0.80:
        confidence = "high"
    elif score >= 0.60:
        confidence = "medium"
    else:
        confidence = "low"
    return {**best, "confidence": confidence}
