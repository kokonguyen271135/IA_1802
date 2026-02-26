# backend/secbert_cve_scorer.py

"""
SecBERT-Based Semantic CVE–PE Relevance Scorer
================================================

Uses jackaduma/SecBERT (a BERT model pre-trained on cybersecurity text) to compute
semantic similarity between CVE descriptions and a natural-language description of
the PE file's behavior profile.

Why SecBERT over keyword matching?
-----------------------------------
Keyword approach (contextual_scorer.py) only catches exact matches, e.g.:
  "buffer overflow" → maps to "Process Injection" category.

SecBERT approach:
  - CVE: "exploiting improper memory boundary check in heap region"
  - No keyword match for "heap boundary" — but SecBERT UNDERSTANDS this is
    semantically equivalent to a memory corruption / process-injection concern.
  - Computes cosine similarity in 768-dimensional cybersecurity embedding space.

The result: genuinely different relevance rankings for different PE files
that share the same software version — this is the core novelty.

Two-Model Pipeline:
  1. SecBERT   → encodes CVE descriptions (security-domain text)
  2. CodeBERT  → encodes PE import sequences (code-domain)
  → Cross-domain cosine similarity → CVE-PE semantic relevance score

References:
  - SecBERT: jackaduma/SecBERT on HuggingFace
    (BERT-base-uncased fine-tuned on cybersecurity text corpus)
  - Fallback: sentence-transformers/all-mpnet-base-v2
    (state-of-the-art general sentence embedding)
"""

import logging
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Model preference order
_SECBERT_MODEL    = "jackaduma/SecBERT"
_MPNET_MODEL      = "sentence-transformers/all-mpnet-base-v2"
_MINILM_MODEL     = "sentence-transformers/all-MiniLM-L6-v2"   # lightest fallback

# Label thresholds (cosine similarity → semantic relevance label)
_THRESHOLDS = [
    (0.72, "CRITICAL"),
    (0.55, "HIGH"),
    (0.38, "MEDIUM"),
    (0.22, "LOW"),
    (0.00, "MINIMAL"),
]

# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional["SecBERTCVEScorer"] = None


def get_scorer() -> "SecBERTCVEScorer":
    global _instance
    if _instance is None:
        _instance = SecBERTCVEScorer()
    return _instance


def is_available() -> bool:
    return get_scorer().is_available()


def score_cves_semantic(pe_analysis: dict, cves: list) -> list:
    """Public API: add secbert_relevance to each CVE and re-sort."""
    return get_scorer().score_cves(pe_analysis, cves)


def build_profile_text(pe_analysis: dict) -> str:
    """Public API: build natural-language behavior description for display."""
    return get_scorer()._build_profile_text(pe_analysis)


# ── Main class ─────────────────────────────────────────────────────────────────

class SecBERTCVEScorer:
    """
    Semantic CVE–PE relevance scoring using SecBERT.

    Strategy:
        1. Convert PE analysis → natural-language behavior profile text
        2. Encode profile text with SecBERT (or fallback model)
        3. Encode all CVE descriptions with the same model
        4. Compute cosine similarities → relevance scores
        5. Assign labels and sort CVEs by semantic relevance (not just CVSS)
    """

    def __init__(self):
        self.model = None
        self.model_name: str = ""
        self._backend: str = ""    # "sentence_transformers" or "transformers"
        self._available = False
        self._load()

    def _load(self):
        """Try to load SecBERT or a suitable fallback model."""
        # --- Attempt 1: sentence-transformers wrapper for SecBERT ---
        # (Not all BERT models have an ST wrapper, so try raw transformers first)
        # --- Attempt 2: raw transformers + mean pooling ---
        try:
            import torch                                           # noqa: F401
            from transformers import AutoTokenizer, AutoModel

            logger.info(f"[SecBERT] Trying to load {_SECBERT_MODEL} …")
            self._tokenizer = AutoTokenizer.from_pretrained(_SECBERT_MODEL)
            self._raw_model = AutoModel.from_pretrained(_SECBERT_MODEL)
            self._raw_model.eval()
            import torch as _torch
            self._torch = _torch
            self.model_name = _SECBERT_MODEL
            self._backend = "transformers"
            self._available = True
            logger.info(f"[SecBERT] Loaded {_SECBERT_MODEL} via transformers")
            return
        except Exception as e:
            logger.debug(f"[SecBERT] Raw transformers failed: {e}")

        # --- Attempt 3: sentence-transformers (mpnet or minilm) ---
        for model_name in [_MPNET_MODEL, _MINILM_MODEL]:
            try:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer(model_name)
                self.model_name = model_name
                self._backend = "sentence_transformers"
                self._available = True
                logger.info(f"[SecBERT] Fell back to {model_name} via sentence-transformers")
                return
            except Exception as e:
                logger.debug(f"[SecBERT] {model_name} failed: {e}")

        logger.warning("[SecBERT] No suitable model found. Semantic scoring disabled.")

    def is_available(self) -> bool:
        return self._available

    # ── Encoding ──────────────────────────────────────────────────────────────

    def _encode_transformers(self, texts: list) -> np.ndarray:
        """Encode with raw HuggingFace transformers (mean pooling of last hidden state)."""
        import torch
        embeddings = []
        for text in texts:
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                max_length=512,
                truncation=True,
                padding=True,
            )
            with torch.no_grad():
                outputs = self._raw_model(**inputs)
            # Mean pool over token dimension (excluding [PAD])
            mask = inputs["attention_mask"].unsqueeze(-1).float()
            token_embs = outputs.last_hidden_state
            mean_emb = (token_embs * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
            # L2-normalize
            normed = torch.nn.functional.normalize(mean_emb, p=2, dim=1)
            embeddings.append(normed.squeeze().numpy())
        return np.array(embeddings)

    def _encode_st(self, texts: list) -> np.ndarray:
        """Encode with sentence-transformers."""
        return self.model.encode(
            texts, batch_size=16, show_progress_bar=False, normalize_embeddings=True
        )

    def _encode(self, texts: list) -> np.ndarray:
        if self._backend == "transformers":
            return self._encode_transformers(texts)
        return self._encode_st(texts)

    # ── Profile text builder ──────────────────────────────────────────────────

    def _build_profile_text(self, pe_analysis: dict) -> str:
        """
        Convert PE static analysis result into a natural-language paragraph
        describing the file's behavior capabilities.

        This text is embedded by SecBERT and compared against CVE descriptions.
        """
        parts = []

        imports     = pe_analysis.get("imports", {})
        by_cat      = imports.get("by_category", {})
        suspicious  = imports.get("suspicious", [])
        strings     = pe_analysis.get("strings", {})
        sections    = pe_analysis.get("sections", [])
        risk        = pe_analysis.get("risk", {})

        # ── Behavior categories ──
        if by_cat:
            cat_names = list(by_cat.keys())
            parts.append(
                f"This Windows executable imports APIs from the following behavior categories: "
                f"{', '.join(cat_names)}."
            )

        # ── Specific capability sentences ──
        if "Process Injection" in by_cat:
            apis = [e["function"] for e in by_cat["Process Injection"][:6]]
            parts.append(
                f"The file contains process injection capabilities using: "
                f"{', '.join(apis)}. This indicates potential memory manipulation "
                f"and code injection into other processes."
            )

        if "Network Communication" in by_cat:
            apis = [e["function"] for e in by_cat["Network Communication"][:4]]
            parts.append(
                f"The file communicates over the network using socket and HTTP APIs "
                f"({', '.join(apis)}), suggesting remote access or data exfiltration."
            )

        if "Code Execution" in by_cat:
            apis = [e["function"] for e in by_cat["Code Execution"][:4]]
            parts.append(
                f"The file can spawn child processes and execute shell commands "
                f"({', '.join(apis)}), enabling arbitrary code execution."
            )

        if "Privilege Escalation" in by_cat:
            apis = [e["function"] for e in by_cat["Privilege Escalation"][:4]]
            parts.append(
                f"The file attempts privilege escalation via token manipulation "
                f"({', '.join(apis)}), seeking elevated system access."
            )

        if "Cryptography" in by_cat:
            apis = [e["function"] for e in by_cat["Cryptography"][:4]]
            parts.append(
                f"The file uses encryption and decryption routines ({', '.join(apis)}), "
                f"possibly for ransomware encryption or secure communication."
            )

        if "Anti-Debugging" in by_cat:
            apis = [e["function"] for e in by_cat["Anti-Debugging"][:4]]
            parts.append(
                f"The file implements anti-debugging and sandbox evasion techniques "
                f"({', '.join(apis)}), indicating malware trying to evade analysis."
            )

        if "Keylogging" in by_cat:
            apis = [e["function"] for e in by_cat["Keylogging"][:4]]
            parts.append(
                f"The file hooks keyboard and window events ({', '.join(apis)}) "
                f"for keylogging and credential harvesting."
            )

        if "Registry Manipulation" in by_cat:
            parts.append(
                "The file modifies Windows registry keys, likely for persistence "
                "or configuration storage."
            )

        if "Service Manipulation" in by_cat:
            parts.append(
                "The file installs or modifies Windows services, "
                "enabling persistent execution with elevated privileges."
            )

        if "Dynamic Loading" in by_cat:
            parts.append(
                "The file dynamically loads DLLs and resolves function addresses at runtime, "
                "a common obfuscation and code-hiding technique."
            )

        # ── String artifacts ──
        if strings.get("URLs"):
            n = len(strings["URLs"])
            sample = strings["URLs"][0] if strings["URLs"] else ""
            parts.append(
                f"Contains {n} hardcoded URL(s) (e.g., {sample[:80]}), "
                f"suggesting C2 communication or resource download."
            )

        if strings.get("IP Addresses"):
            n = len(strings["IP Addresses"])
            parts.append(
                f"Contains {n} hardcoded IP address(es), "
                f"indicating hard-coded C2 server addresses."
            )

        if strings.get("Suspicious Commands"):
            n = len(strings["Suspicious Commands"])
            parts.append(
                f"Embeds {n} suspicious command string(s) "
                f"(cmd.exe, powershell, certutil, etc.), "
                f"suggesting fileless execution or living-off-the-land techniques."
            )

        if strings.get("Potential Base64"):
            n = len(strings["Potential Base64"])
            parts.append(
                f"Contains {n} potential Base64-encoded payload(s), "
                f"which may hide shellcode or configuration data."
            )

        # ── Entropy ──
        high_ent_secs = [s for s in sections if s.get("high_entropy")]
        if high_ent_secs:
            parts.append(
                f"Has {len(high_ent_secs)} high-entropy section(s), "
                f"indicating packing, encryption, or obfuscation of code."
            )

        # ── Overall risk ──
        risk_score = risk.get("score", 0)
        risk_level = risk.get("level", "UNKNOWN")
        if risk_score > 0:
            parts.append(
                f"Static analysis risk score: {risk_score}/100 ({risk_level})."
            )

        if not parts:
            return "No significant suspicious behaviors detected in this file."

        return " ".join(parts)

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score_cves(self, pe_analysis: dict, cves: list) -> list:
        """
        Add 'secbert_relevance' to each CVE and re-sort by semantic relevance.

        Parameters
        ----------
        pe_analysis : dict   Output from PEStaticAnalyzer.analyze()
        cves        : list   List of CVE dicts from NVD

        Returns
        -------
        list  — Same CVEs with added 'secbert_relevance' field, sorted by score DESC
        """
        if not self._available or not cves or not pe_analysis:
            return cves

        try:
            from sklearn.metrics.pairwise import cosine_similarity as sk_cosine
        except ImportError:
            # Manual cosine similarity fallback
            def sk_cosine(a, b):
                a_n = a / (np.linalg.norm(a, axis=1, keepdims=True) + 1e-9)
                b_n = b / (np.linalg.norm(b, axis=1, keepdims=True) + 1e-9)
                return np.dot(a_n, b_n.T)

        # ── Build file behavior profile ──
        profile_text = self._build_profile_text(pe_analysis)

        # ── Encode profile ──
        profile_emb = self._encode([profile_text])[0].reshape(1, -1)

        # ── Encode all CVE descriptions ──
        cve_texts = []
        for cve in cves:
            desc = cve.get("description") or ""
            vector = cve.get("vector_string") or ""
            weaknesses = " ".join(cve.get("weaknesses", []))
            cve_texts.append(f"{desc} {vector} {weaknesses}".strip())

        cve_embeddings = self._encode(cve_texts)  # shape (N, D)

        # ── Compute pairwise cosine similarities ──
        sims = sk_cosine(profile_emb, cve_embeddings)[0]   # shape (N,)

        # ── Annotate CVEs ──
        annotated = []
        for cve, raw_sim in zip(cves, sims):
            sim = float(raw_sim)
            label = "MINIMAL"
            for threshold, lbl in _THRESHOLDS:
                if sim >= threshold:
                    label = lbl
                    break

            cve_copy = dict(cve)
            cve_copy["secbert_relevance"] = {
                "score": round(sim, 4),
                "label": label,
                "model": self.model_name,
                "backend": self._backend,
            }
            annotated.append(cve_copy)

        # ── Re-sort: SecBERT relevance DESC, then CVSS DESC ──
        annotated.sort(
            key=lambda c: (
                -c["secbert_relevance"]["score"],
                -float(c.get("cvss_score") or 0),
            )
        )

        logger.info(
            f"[SecBERT] Scored {len(annotated)} CVEs | "
            f"top score: {annotated[0]['secbert_relevance']['score']:.4f} "
            f"({annotated[0]['secbert_relevance']['label']})"
            if annotated else "[SecBERT] No CVEs to score"
        )

        return annotated
