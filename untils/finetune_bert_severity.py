#!/usr/bin/env python3
# untils/finetune_bert_severity.py

"""
Fine-tune SecBERT (or DistilBERT) for CVE Severity Classification
==================================================================

Task   : 4-class text classification
Input  : CVE description (+ optional CVSS vector string appended)
Output : CRITICAL | HIGH | MEDIUM | LOW

Default model: jackaduma/SecBERT
  - Pre-trained on cybersecurity corpora (security papers, NVD, CVE text)
  - Domain-specific vocabulary → better representation of vulnerability text
  - Outperforms generic BERT on security classification tasks

Alternative: distilbert-base-uncased
  - 40% smaller, 60% faster than BERT-base, retains 97% accuracy
  - Good choice when compute is limited (CPU-only)

Dataset  : data/training/cve_severity_train.csv
           (built by: python untils/build_training_data.py)

Output files
  - models/bert_severity/      — fine-tuned model + tokenizer
  - models/bert_severity_meta.json — label map + evaluation metrics

Class Imbalance Handling
  NVD data is skewed toward MEDIUM/HIGH.
  We apply two complementary strategies:
  1. compute_class_weight (sklearn) → per-class loss weights
  2. Focal-loss-like scaling via Trainer's label_smoothing

Usage
-----
    # Recommended: GPU (CUDA or MPS)
    python untils/finetune_bert_severity.py

    # CPU only (slow, reduce epochs)
    python untils/finetune_bert_severity.py --model distilbert-base-uncased --epochs 2 --batch 8

    # Use SecBERT explicitly
    python untils/finetune_bert_severity.py --model jackaduma/SecBERT

Academic References
-------------------
    Devlin et al. (2019). BERT: Pre-training of Deep Bidirectional Transformers.
    NAACL 2019. https://arxiv.org/abs/1810.04805

    Sanh et al. (2020). DistilBERT: a distilled version of BERT.
    arXiv:1910.01108. https://arxiv.org/abs/1910.01108

    Aghaei et al. (2022). SecureBERT: A Domain-Specific Language Model for
    Cybersecurity. arXiv:2204.02685.

    NVD CVSS v3.1 Specification — https://www.first.org/cvss/v3.1/specification-document
"""

import argparse
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── Label config ───────────────────────────────────────────────────────────────
LABEL2ID = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ID2LABEL  = {v: k for k, v in LABEL2ID.items()}

# ── Defaults (overridable via CLI) ─────────────────────────────────────────────
DEFAULT_MODEL   = "jackaduma/SecBERT"   # cybersecurity-domain pre-trained
FALLBACK_MODEL  = "distilbert-base-uncased"

DEFAULT_DATASET = ROOT / "data"  / "training" / "cve_severity_train.csv"
DEFAULT_OUT_DIR = ROOT / "models" / "bert_severity"
DEFAULT_META    = ROOT / "models" / "bert_severity_meta.json"


# ── Dataset loading ────────────────────────────────────────────────────────────

def load_dataset(path: Path) -> tuple[list, int]:
    """
    Load CSV, return list of (text, label_id) tuples and skipped count.

    Text format: '{description} [SEP] {cvss_vector_tokens}'
    This mirrors the training format so inference uses the same input.
    """
    records: list[tuple[str, int]] = []
    skipped = 0

    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            desc   = (row.get("description")   or "").strip()
            sev    = (row.get("severity")       or "").upper().strip()
            vector = (row.get("vector_string")  or "").strip()

            if not desc or sev not in LABEL2ID:
                skipped += 1
                continue

            # Append CVSS vector as structured tokens so the model learns
            # both semantic description AND CVSS attributes.
            # e.g.  "AV:N/AC:L/PR:N" → "AV_N AC_L PR_N"
            text = desc
            if vector:
                vtokens = " ".join(
                    f"{p.split(':')[0]}_{p.split(':')[1]}"
                    for p in vector.split("/") if ":" in p
                )
                text = f"{desc} [SEP] {vtokens}"

            records.append((text, LABEL2ID[sev]))

    return records, skipped


# ── Stratified split ───────────────────────────────────────────────────────────

def stratified_split(
    records: list,
    test_size:  float = 0.15,
    val_size:   float = 0.10,
    seed:       int   = 42,
) -> tuple[list, list, list]:
    """Split into train/val/test preserving per-class ratio."""
    import random
    random.seed(seed)

    by_label: dict[int, list] = {}
    for item in records:
        by_label.setdefault(item[1], []).append(item)

    train, val, test = [], [], []
    for lbl, items in by_label.items():
        random.shuffle(items)
        n        = len(items)
        n_test   = max(1, int(n * test_size))
        n_val    = max(1, int(n * val_size))
        test    += items[:n_test]
        val     += items[n_test: n_test + n_val]
        train   += items[n_test + n_val:]

    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)
    return train, val, test


# ── Compute class weights for loss function ────────────────────────────────────

def compute_class_weights(records: list) -> list:
    """
    Return per-class weights to penalise errors on minority classes.

    Uses sklearn's 'balanced' strategy:
        w_i = n_samples / (n_classes * n_samples_for_class_i)
    """
    from sklearn.utils.class_weight import compute_class_weight
    import numpy as np

    labels = [lbl for _, lbl in records]
    classes = sorted(set(labels))
    weights = compute_class_weight("balanced", classes=np.array(classes), y=np.array(labels))
    # weights array aligns with classes; we need index-aligned list
    w_by_id = {c: w for c, w in zip(classes, weights)}
    return [w_by_id.get(i, 1.0) for i in range(len(LABEL2ID))]


# ── PyTorch Dataset ────────────────────────────────────────────────────────────

class CVEDataset:
    def __init__(self, records: list, tokenizer, max_len: int):
        self.records   = records
        self.tokenizer = tokenizer
        self.max_len   = max_len

    def __len__(self):
        return len(self.records)

    def __getitem__(self, idx: int):
        import torch
        text, label = self.records[idx]
        enc = self.tokenizer(
            text,
            max_length=self.max_len,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )
        return {
            "input_ids":      enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "labels":         torch.tensor(label, dtype=torch.long),
        }


# ── Metric function for HuggingFace Trainer ───────────────────────────────────

def make_compute_metrics():
    """Return a compute_metrics function with correct imports."""
    import numpy as np
    from sklearn.metrics import accuracy_score, f1_score

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        acc   = accuracy_score(labels, preds)
        f1    = f1_score(labels, preds, average="macro", zero_division=0)
        return {"accuracy": acc, "macro_f1": f1}

    return compute_metrics


# ── Weighted loss Trainer ──────────────────────────────────────────────────────

def make_weighted_trainer(class_weights_list: list):
    """
    Subclass HuggingFace Trainer to use weighted cross-entropy loss.
    This is the primary mechanism for handling class imbalance.
    """
    import torch
    import torch.nn as nn
    from transformers import Trainer

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels  = inputs.pop("labels")
            outputs = model(**inputs)
            logits  = outputs.logits

            weights = torch.tensor(
                class_weights_list, dtype=torch.float, device=logits.device
            )
            loss_fn = nn.CrossEntropyLoss(weight=weights)
            loss    = loss_fn(logits, labels)

            return (loss, outputs) if return_outputs else loss

    return WeightedTrainer


# ── Main training function ─────────────────────────────────────────────────────

def train(
    records:    list,
    model_name: str,
    out_dir:    Path,
    meta_path:  Path,
    max_len:    int   = 256,
    batch_size: int   = 16,
    epochs:     int   = 3,
    lr:         float = 2e-5,
    weight_decay: float = 0.01,
    use_class_weights: bool = True,
) -> tuple[float, float]:
    """Full fine-tuning pipeline. Returns (test_accuracy, test_macro_f1)."""
    import torch
    import numpy as np
    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
        TrainingArguments,
        EarlyStoppingCallback,
    )
    from sklearn.metrics import classification_report, accuracy_score, f1_score

    device = (
        "cuda"  if torch.cuda.is_available()
        else "mps" if torch.backends.mps.is_available()
        else "cpu"
    )
    print(f"\n[Device] {device.upper()}")
    print(f"[Model]  {model_name}")

    if device == "cpu":
        print("[WARN]  CPU-only training is slow. Consider reducing --epochs to 2.")
        if batch_size > 8:
            batch_size = 8
            print(f"[INFO]  Reduced batch_size to {batch_size} for CPU.")

    # ── Split ──
    train_data, val_data, test_data = stratified_split(records)
    print(f"[Split] train={len(train_data):,}  val={len(val_data):,}  test={len(test_data):,}")

    # ── Class weights ──
    class_weights_list = None
    if use_class_weights:
        class_weights_list = compute_class_weights(train_data)
        print("[Class weights]", {
            ID2LABEL[i]: round(w, 3)
            for i, w in enumerate(class_weights_list)
        })

    # ── Tokenizer + model ──
    print(f"\n[Loading] tokenizer …")
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
    except Exception as e:
        print(f"[WARN] Could not load {model_name}: {e}")
        print(f"       Falling back to {FALLBACK_MODEL}")
        model_name = FALLBACK_MODEL
        tokenizer  = AutoTokenizer.from_pretrained(model_name)

    print(f"[Loading] model …")
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        num_labels=len(LABEL2ID),
        id2label=ID2LABEL,
        label2id=LABEL2ID,
        ignore_mismatched_sizes=True,
    )

    # ── Datasets ──
    train_ds = CVEDataset(train_data, tokenizer, max_len)
    val_ds   = CVEDataset(val_data,   tokenizer, max_len)
    test_ds  = CVEDataset(test_data,  tokenizer, max_len)

    # ── Training arguments ──
    out_dir.mkdir(parents=True, exist_ok=True)
    training_args = TrainingArguments(
        output_dir                  = str(out_dir),
        num_train_epochs            = epochs,
        per_device_train_batch_size = batch_size,
        per_device_eval_batch_size  = batch_size * 2,
        learning_rate               = lr,
        weight_decay                = weight_decay,
        warmup_ratio                = 0.1,
        # HuggingFace ≥4.46 uses eval_strategy; earlier versions use evaluation_strategy
        eval_strategy               = "epoch",
        save_strategy               = "epoch",
        load_best_model_at_end      = True,
        metric_for_best_model       = "macro_f1",
        greater_is_better           = True,
        logging_steps               = 50,
        report_to                   = "none",
        seed                        = 42,
        fp16                        = torch.cuda.is_available(),
    )

    # ── Trainer (weighted or standard) ──
    if use_class_weights and class_weights_list:
        TrainerClass = make_weighted_trainer(class_weights_list)
    else:
        from transformers import Trainer as TrainerClass

    trainer = TrainerClass(
        model           = model,
        args            = training_args,
        train_dataset   = train_ds,
        eval_dataset    = val_ds,
        compute_metrics = make_compute_metrics(),
        callbacks       = [EarlyStoppingCallback(early_stopping_patience=2)],
    )

    # ── Train ──
    print(f"\n{'='*60}")
    print(f"  Fine-tuning {model_name} for CVE Severity Classification")
    print(f"  Epochs={epochs}  LR={lr}  BatchSize={batch_size}")
    print(f"{'='*60}")
    t0 = time.time()
    trainer.train()
    elapsed = time.time() - t0
    print(f"\n[Done] Training: {elapsed:.0f}s ({elapsed/60:.1f} min)")

    # ── Evaluate on test set ──
    print("\n[Eval] Held-out test set …")
    pred_out = trainer.predict(test_ds)
    preds    = np.argmax(pred_out.predictions, axis=-1)
    labels   = pred_out.label_ids

    target_names = [ID2LABEL[i] for i in range(len(LABEL2ID))]
    report_str   = classification_report(
        labels, preds, target_names=target_names, digits=4, zero_division=0
    )
    print("\n" + report_str)

    acc = float(accuracy_score(labels, preds))
    f1  = float(f1_score(labels, preds, average="macro", zero_division=0))

    # ── Save model + metadata ──
    trainer.save_model(str(out_dir))
    tokenizer.save_pretrained(str(out_dir))
    print(f"[Saved] Model → {out_dir}")

    meta = {
        "base_model":       model_name,
        "num_labels":       len(LABEL2ID),
        "label2id":         LABEL2ID,
        "id2label":         {str(k): v for k, v in ID2LABEL.items()},
        "max_length":       max_len,
        "train_samples":    len(train_data),
        "val_samples":      len(val_data),
        "test_samples":     len(test_data),
        "test_accuracy":    round(acc, 4),
        "test_macro_f1":    round(f1, 4),
        "epochs":           epochs,
        "learning_rate":    lr,
        "batch_size":       batch_size,
        "class_weights":    (
            {ID2LABEL[i]: round(w, 4) for i, w in enumerate(class_weights_list)}
            if class_weights_list else None
        ),
        "device":           device,
        "training_time_s":  round(elapsed, 1),
        "classification_report": report_str,
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[Saved] Metadata → {meta_path}")

    print(f"\n{'='*60}")
    print(f"  Test Accuracy : {acc*100:.2f}%")
    print(f"  Test Macro-F1 : {f1*100:.2f}%")
    print(f"{'='*60}")

    return acc, f1


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Fine-tune SecBERT/DistilBERT for CVE severity classification"
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=(
            f"HuggingFace model ID (default: {DEFAULT_MODEL}). "
            f"Alternatives: distilbert-base-uncased, bert-base-uncased"
        ),
    )
    parser.add_argument(
        "--dataset", default=str(DEFAULT_DATASET),
        help="Path to training CSV (default: data/training/cve_severity_train.csv)",
    )
    parser.add_argument("--epochs",     type=int,   default=3,    help="Training epochs (default 3)")
    parser.add_argument("--batch",      type=int,   default=16,   help="Batch size (default 16)")
    parser.add_argument("--lr",         type=float, default=2e-5, help="Learning rate (default 2e-5)")
    parser.add_argument("--max-len",    type=int,   default=256,  help="Max token length (default 256)")
    parser.add_argument(
        "--no-class-weights", action="store_true",
        help="Disable class-weighted loss (not recommended for imbalanced data)",
    )
    args = parser.parse_args()

    # ── Dependency check ──
    print("=" * 60)
    print("  CVE Severity — BERT Fine-tuning")
    print("=" * 60)
    try:
        import torch
        import transformers
        from sklearn.utils.class_weight import compute_class_weight
        print(f"[OK] PyTorch        {torch.__version__}")
        print(f"[OK] Transformers   {transformers.__version__}")
    except ImportError as e:
        print(f"\n[ERR] Missing package: {e}")
        print("      pip install torch transformers scikit-learn accelerate")
        sys.exit(1)

    # ── Dataset ──
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"\n[ERR] Dataset not found: {dataset_path}")
        print("      Run first: python untils/build_training_data.py")
        sys.exit(1)

    print(f"\n[1/3] Loading dataset: {dataset_path}")
    records, skipped = load_dataset(dataset_path)
    counts = Counter(lbl for _, lbl in records)
    print(f"      Loaded: {len(records):,}  Skipped: {skipped}")
    for i, name in ID2LABEL.items():
        print(f"        {name:<10}: {counts.get(i, 0):>7,}")

    if len(records) < 200:
        print("\n[WARN] Very small dataset. Run build_training_data.py first.")

    # ── Fine-tune ──
    print(f"\n[2/3] Fine-tuning {args.model} …")
    acc, f1 = train(
        records            = records,
        model_name         = args.model,
        out_dir            = DEFAULT_OUT_DIR,
        meta_path          = DEFAULT_META,
        max_len            = args.max_len,
        batch_size         = args.batch,
        epochs             = args.epochs,
        lr                 = args.lr,
        use_class_weights  = not args.no_class_weights,
    )

    print(f"\n[3/3] Done!")
    print(f"      Model saved: {DEFAULT_OUT_DIR}/")
    print(f"      Start app:   python backend/app.py")
    print(f"      Evaluate:    python untils/evaluate_models.py")


if __name__ == "__main__":
    main()
