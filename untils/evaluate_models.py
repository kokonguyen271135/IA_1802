#!/usr/bin/env python3
# untils/evaluate_models.py

"""
Evaluate & Compare All Severity Classification Models
======================================================

Loads the held-out test split from the training CSV and evaluates:
  1. TF-IDF + Logistic Regression (models/severity_clf.pkl)
  2. Fine-tuned SecBERT/DistilBERT  (models/bert_severity/)
  3. Zero-shot NLI (facebook/bart-large-mnli — no training required)

Outputs
-------
  Console: Comparison table with Accuracy, Macro-F1, per-class F1
  File:    models/evaluation_report.json  (for thesis documentation)
  File:    models/evaluation_report.txt   (human-readable)

Usage
-----
    python untils/evaluate_models.py
    python untils/evaluate_models.py --samples 500   # use subset (faster)

Academic purpose
----------------
  This script produces the metrics table required for Section 3/4
  of the thesis comparing ML/DL/Zero-shot approaches for CVE severity
  classification. It reports:
    - Per-class Precision, Recall, F1
    - Macro-averaged F1 (primary metric for imbalanced data)
    - Weighted F1
    - Overall Accuracy
    - Inference time per sample
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "backend"))

LABEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
LABEL2ID    = {l: i for i, l in enumerate(LABEL_ORDER)}

DATASET_PATH = ROOT / "data" / "training" / "cve_severity_train.csv"
REPORT_JSON  = ROOT / "models" / "evaluation_report.json"
REPORT_TXT   = ROOT / "models" / "evaluation_report.txt"


# ── Dataset helpers ────────────────────────────────────────────────────────────

def load_test_split(
    path: Path,
    test_size: float = 0.15,
    seed: int        = 42,
    max_samples: int = 0,
) -> list[dict]:
    """
    Reproduce the same stratified test split used in finetune_bert_severity.py.
    Returns list of {description, vector_string, true_severity}.
    """
    import random
    random.seed(seed)

    rows: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            desc = (row.get("description") or "").strip()
            sev  = (row.get("severity")    or "").upper().strip()
            if desc and sev in LABEL2ID:
                rows.append({
                    "description":   desc,
                    "vector_string": (row.get("vector_string") or "").strip(),
                    "severity":      sev,
                })

    # Stratified split (reproduce same split as training)
    by_class: dict[str, list] = {}
    for r in rows:
        by_class.setdefault(r["severity"], []).append(r)

    test_rows: list[dict] = []
    for sev, items in by_class.items():
        random.shuffle(items)
        n_test = max(1, int(len(items) * test_size))
        test_rows.extend(items[:n_test])

    random.shuffle(test_rows)

    if max_samples and len(test_rows) > max_samples:
        test_rows = test_rows[:max_samples]

    print(f"  Test split: {len(test_rows):,} samples (stratified 15%)")
    from collections import Counter
    dist = Counter(r["severity"] for r in test_rows)
    for s in LABEL_ORDER:
        print(f"    {s:<10}: {dist.get(s, 0):>5}")

    return test_rows


# ── Metrics ────────────────────────────────────────────────────────────────────

def compute_metrics(
    y_true: list[str],
    y_pred: list[str],
) -> dict:
    """Compute per-class + macro + weighted metrics."""
    from sklearn.metrics import (
        classification_report,
        accuracy_score,
        f1_score,
        precision_score,
        recall_score,
    )
    import numpy as np

    acc     = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro",    labels=LABEL_ORDER, zero_division=0)
    wt_f1    = f1_score(y_true, y_pred, average="weighted", labels=LABEL_ORDER, zero_division=0)

    # Per-class
    per_class: dict[str, dict] = {}
    for label in LABEL_ORDER:
        mask_t = [1 if y == label else 0 for y in y_true]
        mask_p = [1 if y == label else 0 for y in y_pred]
        p  = precision_score(mask_t, mask_p, zero_division=0)
        r  = recall_score   (mask_t, mask_p, zero_division=0)
        f1 = f1_score       (mask_t, mask_p, zero_division=0)
        n  = sum(mask_t)
        per_class[label] = {
            "precision": round(p, 4),
            "recall":    round(r, 4),
            "f1":        round(f1, 4),
            "support":   n,
        }

    return {
        "accuracy":    round(acc, 4),
        "macro_f1":    round(macro_f1, 4),
        "weighted_f1": round(wt_f1, 4),
        "per_class":   per_class,
    }


# ── Evaluation runners ─────────────────────────────────────────────────────────

def evaluate_tfidf(test_rows: list[dict]) -> dict | None:
    """Evaluate TF-IDF + Logistic Regression classifier."""
    print("\n[Model 1] TF-IDF + Logistic Regression")
    try:
        from severity_classifier import predict, is_available
        if not is_available():
            print("  [SKIP] Model not found. Run: python untils/train_severity_model.py")
            return None
    except ImportError as e:
        print(f"  [SKIP] Import error: {e}")
        return None

    preds: list[str] = []
    t0 = time.perf_counter()
    for row in test_rows:
        r = predict(
            description   = row["description"],
            vector_string = row["vector_string"],
        )
        preds.append(r.get("predicted_severity", "MEDIUM") if r else "MEDIUM")
    elapsed = time.perf_counter() - t0

    y_true = [r["severity"] for r in test_rows]
    metrics = compute_metrics(y_true, preds)
    metrics["inference_ms_per_sample"] = round(elapsed / len(test_rows) * 1000, 3)
    metrics["model"] = "TF-IDF + Logistic Regression"
    print(f"  Accuracy: {metrics['accuracy']*100:.2f}%  Macro-F1: {metrics['macro_f1']*100:.2f}%  "
          f"({metrics['inference_ms_per_sample']:.2f} ms/sample)")
    return metrics


def evaluate_bert(test_rows: list[dict]) -> dict | None:
    """Evaluate fine-tuned SecBERT/DistilBERT classifier."""
    print("\n[Model 2] Fine-tuned BERT (SecBERT/DistilBERT)")
    try:
        from bert_severity_classifier import predict, is_available, get_meta
        if not is_available():
            print("  [SKIP] Model not found. Run: python untils/finetune_bert_severity.py")
            return None
        meta = get_meta()
        print(f"  Base model: {meta.get('base_model', 'unknown')}")
    except ImportError as e:
        print(f"  [SKIP] Import error: {e}")
        return None

    preds: list[str] = []
    t0 = time.perf_counter()
    for row in test_rows:
        r = predict(
            description   = row["description"],
            vector_string = row["vector_string"],
        )
        preds.append(r.get("predicted_severity", "MEDIUM") if r else "MEDIUM")
    elapsed = time.perf_counter() - t0

    y_true = [r["severity"] for r in test_rows]
    metrics = compute_metrics(y_true, preds)
    metrics["inference_ms_per_sample"] = round(elapsed / len(test_rows) * 1000, 3)
    metrics["model"] = f"Fine-tuned BERT ({meta.get('base_model', 'unknown')})"
    metrics["train_accuracy"] = meta.get("test_accuracy", None)
    metrics["train_macro_f1"] = meta.get("test_macro_f1", None)
    print(f"  Accuracy: {metrics['accuracy']*100:.2f}%  Macro-F1: {metrics['macro_f1']*100:.2f}%  "
          f"({metrics['inference_ms_per_sample']:.2f} ms/sample)")
    return metrics


def evaluate_zero_shot(test_rows: list[dict]) -> dict | None:
    """Evaluate zero-shot NLI classifier (no training needed)."""
    print("\n[Model 3] Zero-Shot NLI (facebook/bart-large-mnli)")
    try:
        from zero_shot_severity import predict, is_available
        if not is_available():
            print("  [SKIP] Classifier not initialised (likely missing transformers).")
            return None
    except ImportError as e:
        print(f"  [SKIP] Import error: {e}")
        return None

    print(f"  Running zero-shot on {len(test_rows)} samples (may be slow on CPU) …")
    preds: list[str] = []
    t0 = time.perf_counter()
    for i, row in enumerate(test_rows):
        r = predict(
            description   = row["description"],
            vector_string = row["vector_string"],
        )
        preds.append(r.get("predicted_severity", "MEDIUM") if r else "MEDIUM")
        if (i + 1) % 50 == 0:
            pct = (i + 1) / len(test_rows) * 100
            print(f"  Progress: {i+1}/{len(test_rows)} ({pct:.0f}%)", end="\r")
    elapsed = time.perf_counter() - t0
    print()

    y_true = [r["severity"] for r in test_rows]
    metrics = compute_metrics(y_true, preds)
    metrics["inference_ms_per_sample"] = round(elapsed / len(test_rows) * 1000, 3)
    metrics["model"] = "Zero-Shot NLI (BART-MNLI)"
    print(f"  Accuracy: {metrics['accuracy']*100:.2f}%  Macro-F1: {metrics['macro_f1']*100:.2f}%  "
          f"({metrics['inference_ms_per_sample']:.2f} ms/sample)")
    return metrics


# ── Report generation ──────────────────────────────────────────────────────────

def _bar(value: float, width: int = 20) -> str:
    filled = int(value * width)
    return "█" * filled + "░" * (width - filled)


def generate_text_report(results: list[dict], n_test: int) -> str:
    lines = [
        "=" * 72,
        "  CVE SEVERITY CLASSIFICATION — MODEL EVALUATION REPORT",
        "=" * 72,
        f"  Test samples : {n_test:,}",
        f"  Labels       : {', '.join(LABEL_ORDER)}",
        "",
    ]

    # ── Summary table ──
    lines += [
        "  SUMMARY TABLE",
        "  " + "-" * 68,
        f"  {'Model':<40} {'Accuracy':>9} {'Macro-F1':>9} {'ms/sample':>10}",
        "  " + "-" * 68,
    ]
    for r in results:
        lines.append(
            f"  {r['model']:<40} "
            f"{r['accuracy']*100:>8.2f}% "
            f"{r['macro_f1']*100:>8.2f}% "
            f"{r['inference_ms_per_sample']:>10.2f}"
        )
    lines += ["  " + "-" * 68, ""]

    # ── Per-class breakdown ──
    for r in results:
        lines += [
            f"  [{r['model']}]",
            f"  {'Label':<12} {'Precision':>10} {'Recall':>8} {'F1':>8} {'Support':>9}",
            "  " + "-" * 52,
        ]
        for label in LABEL_ORDER:
            pc = r["per_class"].get(label, {})
            lines.append(
                f"  {label:<12} "
                f"{pc.get('precision',0)*100:>9.2f}% "
                f"{pc.get('recall',0)*100:>7.2f}% "
                f"{pc.get('f1',0)*100:>7.2f}% "
                f"{pc.get('support',0):>9,}"
            )
        lines += [
            "  " + "-" * 52,
            f"  {'Macro avg':<12} "
            f"{'':>10} "
            f"{'':>8} "
            f"{r['macro_f1']*100:>7.2f}%",
            "",
        ]

    lines += ["=" * 72]
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate and compare all CVE severity classification models"
    )
    parser.add_argument(
        "--samples", type=int, default=0,
        help="Max test samples to use (0 = full test split, faster with e.g. 200)",
    )
    parser.add_argument(
        "--skip-zeroshot", action="store_true",
        help="Skip zero-shot evaluation (much slower on CPU)",
    )
    parser.add_argument(
        "--dataset", default=str(DATASET_PATH),
        help=f"Training CSV path (default: {DATASET_PATH})",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  MODEL EVALUATION")
    print("=" * 60)

    # ── Load test split ──
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"\n[ERR] Dataset not found: {dataset_path}")
        print("      Run: python untils/build_training_data.py")
        sys.exit(1)

    print("\n[Data] Loading test split …")
    test_rows = load_test_split(dataset_path, max_samples=args.samples)

    if not test_rows:
        print("[ERR] No test samples available.")
        sys.exit(1)

    # ── Evaluate models ──
    results: list[dict] = []

    m = evaluate_tfidf(test_rows)
    if m:
        results.append(m)

    m = evaluate_bert(test_rows)
    if m:
        results.append(m)

    if not args.skip_zeroshot:
        m = evaluate_zero_shot(test_rows)
        if m:
            results.append(m)

    if not results:
        print("\n[WARN] No models available for evaluation.")
        print("       Train models first:")
        print("         python untils/run_training_pipeline.py")
        sys.exit(0)

    # ── Generate reports ──
    report_txt = generate_text_report(results, n_test=len(test_rows))
    print("\n" + report_txt)

    # Save JSON
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    report_data = {
        "test_samples": len(test_rows),
        "label_order":  LABEL_ORDER,
        "models":       results,
    }
    with open(REPORT_JSON, "w") as f:
        json.dump(report_data, f, indent=2)
    print(f"\nSaved JSON report  → {REPORT_JSON}")

    # Save TXT
    with open(REPORT_TXT, "w", encoding="utf-8") as f:
        f.write(report_txt)
    print(f"Saved text report  → {REPORT_TXT}")

    # ── Best model summary ──
    best = max(results, key=lambda r: r["macro_f1"])
    print(f"\n[Best] {best['model']}")
    print(f"       Macro-F1: {best['macro_f1']*100:.2f}%")
    print(f"       Accuracy: {best['accuracy']*100:.2f}%")


if __name__ == "__main__":
    main()
