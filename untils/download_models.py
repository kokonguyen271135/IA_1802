#!/usr/bin/env python3
# untils/download_models.py

"""
Pre-download all AI/ML models used by the CVE Scanner.
Run this ONCE before starting the app to cache models locally.

Models downloaded:
  1. microsoft/codebert-base        (~500MB) — CodeBERT PE behavior analysis
  2. jackaduma/SecBERT               (~440MB) — SecBERT CVE semantic scoring
  3. sentence-transformers/all-mpnet-base-v2  (~420MB) — Fallback semantic matcher
  4. sentence-transformers/all-MiniLM-L6-v2  (~90MB)  — Lightweight CPE matcher

Usage:
    cd IA_1802
    python untils/download_models.py

All models are cached to ~/.cache/huggingface/hub/ by default.
"""

import sys
import time

# ── Pretty printing ────────────────────────────────────────────────────────────

def step(msg: str):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")

def ok(msg: str):
    print(f"  [OK] {msg}")

def warn(msg: str):
    print(f"  [!]  {msg}")

def info(msg: str):
    print(f"  [i]  {msg}")


# ── Check prerequisites ────────────────────────────────────────────────────────

def check_packages():
    step("Checking prerequisites")
    missing = []
    packages = {
        "torch":                "PyTorch",
        "transformers":         "HuggingFace Transformers",
        "sentence_transformers": "Sentence-Transformers",
    }
    for pkg, name in packages.items():
        try:
            __import__(pkg)
            ok(f"{name} installed")
        except ImportError:
            warn(f"{name} NOT installed")
            missing.append(pkg)

    if missing:
        print()
        print("  Install missing packages with:")
        print(f"    pip install {' '.join(missing)}")
        print()
        sys.exit(1)


# ── Download functions ─────────────────────────────────────────────────────────

def download_codebert():
    """Download microsoft/codebert-base for PE API sequence analysis."""
    step("Downloading CodeBERT (microsoft/codebert-base) — ~500MB")
    info("Used for: deep semantic analysis of PE import API sequences")
    info("Paper: Feng et al. 2020, arXiv:2002.08155")
    try:
        from transformers import AutoTokenizer, AutoModel
        t0 = time.time()
        AutoTokenizer.from_pretrained("microsoft/codebert-base")
        AutoModel.from_pretrained("microsoft/codebert-base")
        elapsed = time.time() - t0
        ok(f"microsoft/codebert-base downloaded in {elapsed:.1f}s")
    except Exception as e:
        warn(f"CodeBERT download failed: {e}")


def download_secbert():
    """Download jackaduma/SecBERT for CVE semantic scoring."""
    step("Downloading SecBERT (jackaduma/SecBERT) — ~440MB")
    info("Used for: semantic CVE-PE relevance scoring (cybersecurity-domain BERT)")
    info("Pre-trained on large cybersecurity text corpus")
    try:
        from transformers import AutoTokenizer, AutoModel
        t0 = time.time()
        AutoTokenizer.from_pretrained("jackaduma/SecBERT")
        AutoModel.from_pretrained("jackaduma/SecBERT")
        elapsed = time.time() - t0
        ok(f"jackaduma/SecBERT downloaded in {elapsed:.1f}s")
    except Exception as e:
        warn(f"SecBERT download failed: {e}")
        info("Fallback: all-mpnet-base-v2 will be used instead")


def download_mpnet():
    """Download sentence-transformers/all-mpnet-base-v2 as fallback."""
    step("Downloading all-mpnet-base-v2 (fallback) — ~420MB")
    info("Used for: CPE semantic matching + SecBERT fallback")
    try:
        from sentence_transformers import SentenceTransformer
        t0 = time.time()
        SentenceTransformer("sentence-transformers/all-mpnet-base-v2")
        elapsed = time.time() - t0
        ok(f"all-mpnet-base-v2 downloaded in {elapsed:.1f}s")
    except Exception as e:
        warn(f"all-mpnet-base-v2 download failed: {e}")


def download_minilm():
    """Download MiniLM (lightweight, already used by CPE matcher)."""
    step("Downloading all-MiniLM-L6-v2 (lightweight) — ~90MB")
    info("Used for: FAISS CPE semantic matching (existing module)")
    try:
        from sentence_transformers import SentenceTransformer
        t0 = time.time()
        SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        elapsed = time.time() - t0
        ok(f"all-MiniLM-L6-v2 downloaded in {elapsed:.1f}s")
    except Exception as e:
        warn(f"MiniLM download failed: {e}")


# ── Verify all models ──────────────────────────────────────────────────────────

def verify_all():
    step("Verifying all models")

    # CodeBERT
    try:
        from transformers import AutoTokenizer, AutoModel
        import torch
        tok = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        mdl = AutoModel.from_pretrained("microsoft/codebert-base")
        inputs = tok("VirtualAlloc() WriteProcessMemory()", return_tensors="pt")
        with torch.no_grad():
            out = mdl(**inputs)
        ok(f"CodeBERT OK — output shape: {out.last_hidden_state.shape}")
    except Exception as e:
        warn(f"CodeBERT verification failed: {e}")

    # SecBERT
    try:
        from transformers import AutoTokenizer, AutoModel
        import torch
        tok = AutoTokenizer.from_pretrained("jackaduma/SecBERT")
        mdl = AutoModel.from_pretrained("jackaduma/SecBERT")
        inputs = tok("remote code execution buffer overflow", return_tensors="pt", truncation=True)
        with torch.no_grad():
            out = mdl(**inputs)
        ok(f"SecBERT OK — output shape: {out.last_hidden_state.shape}")
    except Exception as e:
        warn(f"SecBERT verification failed: {e}")

    # Sentence-transformers
    try:
        from sentence_transformers import SentenceTransformer
        mdl = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        emb = mdl.encode(["test"])
        ok(f"MiniLM OK — embedding dim: {emb.shape[1]}")
    except Exception as e:
        warn(f"MiniLM verification failed: {e}")


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("=" * 60)
    print("  CVE Scanner — AI Model Downloader")
    print("  Downloads all Deep Learning models from HuggingFace")
    print("=" * 60)
    print()
    print("  Models to download:")
    print("    1. microsoft/codebert-base        ~500MB")
    print("    2. jackaduma/SecBERT              ~440MB")
    print("    3. sentence-transformers/all-mpnet ~420MB")
    print("    4. sentence-transformers/MiniLM    ~90MB")
    print()
    print("  Total download size: ~1.5GB")
    print("  Models are cached in: ~/.cache/huggingface/hub/")
    print()

    check_packages()

    total_start = time.time()
    download_codebert()
    download_secbert()
    download_mpnet()
    download_minilm()

    verify_all()

    total = time.time() - total_start
    print()
    step(f"Done! Total time: {total:.1f}s")
    print()
    print("  You can now start the application:")
    print("    python backend/app.py")
    print()
