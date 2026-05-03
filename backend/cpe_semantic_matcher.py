# backend/cpe_semantic_matcher.py

"""
Semantic CPE Matcher — inference module.

Loads:
  models/cpe_index.faiss   — FAISS IndexFlatIP (cosine on normalised vecs)
  models/cpe_meta.pkl      — metadata: {entries: [...], model_name: str}

Built by utils/build_cpe_index.py.

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
import re
from difflib import SequenceMatcher
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_INDEX_PATH = _ROOT / "models" / "cpe_index.faiss"
_META_PATH  = _ROOT / "models" / "cpe_meta.pkl"

# Module-level cache
_index    = None
_entries  = None
_model    = None
_loaded   = False

_GENERIC_TECH_PRODUCTS: set[str] = {
    "rust", "python", "php", "ruby", "go", "node js", "nodejs",
    "jre", "jdk", "openjdk", "perl", "git", "docker",
    "kubernetes", "terraform", "ansible",
}

_QUERY_NOISE_TOKENS: set[str] = {
    "windows", "window", "setup", "installer", "install", "portable",
    "desktop", "client", "clients", "launcher", "service", "services",
    "update", "updater", "tool", "tools", "runtime", "release",
    "x64", "x86", "amd64", "arm64", "win64", "win32",
}


def _normalize_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(text))
    text = re.sub(r"[^a-z0-9]+", " ", text.lower())
    return " ".join(text.split())


def _tokenize_text(text: str) -> set[str]:
    return {tok for tok in _normalize_text(text).split() if tok}


def _passes_lexical_sanity(query: str, candidate: dict) -> bool:
    """
    Reject semantic nearest-neighbour hits that share almost no lexical signal.

    This prevents broad embedding matches such as "PeaZip" -> "WinZip" from
    becoming a hard CPE decision. We still allow semantically close matches when
    the normalized strings or meaningful tokens overlap.
    """
    q_norm = _normalize_text(query)
    if not q_norm:
        return False

    candidate_fields = [
        candidate.get("display", ""),
        candidate.get("product", ""),
        candidate.get("vendor", ""),
    ]
    candidate_norms = [n for n in (_normalize_text(text) for text in candidate_fields) if n]
    if not candidate_norms:
        return False

    query_tokens = {tok for tok in _tokenize_text(query) if len(tok) >= 4}
    candidate_tokens = {
        tok
        for text in candidate_fields
        for tok in _tokenize_text(text)
        if len(tok) >= 4
    }
    best_ratio = max(SequenceMatcher(None, q_norm, cand).ratio() for cand in candidate_norms)

    candidate_product = _normalize_text(candidate.get("product", ""))
    meaningful_extra_query_tokens = {
        tok for tok in query_tokens
        if tok not in candidate_tokens and tok not in _QUERY_NOISE_TOKENS
    }
    if (
        candidate_product in _GENERIC_TECH_PRODUCTS
        and meaningful_extra_query_tokens
        and q_norm != candidate_product
        and best_ratio < 0.90
    ):
        return False

    if any(q_norm == cand or q_norm in cand or cand in q_norm for cand in candidate_norms):
        return True

    if query_tokens & candidate_tokens:
        return True

    return best_ratio >= 0.78


def _load():
    """Attempt to load FAISS index + sentence-transformer model once."""
    global _index, _entries, _model, _loaded
    if _loaded:
        return
    _loaded = True

    if not _INDEX_PATH.exists() or not _META_PATH.exists():
        print(f"[i] Semantic CPE Matcher: index files not found.")
        print("    Run:  python utils/build_cpe_index.py")
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
    if not _passes_lexical_sanity(query, best):
        return None
    score = best["score"]
    if score >= 0.80:
        confidence = "high"
    elif score >= 0.60:
        confidence = "medium"
    else:
        confidence = "low"
    return {**best, "confidence": confidence}
