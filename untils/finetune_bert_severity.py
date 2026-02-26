#!/usr/bin/env python3
# untils/finetune_bert_severity.py

"""
Fine-tune DistilBERT / SecBERT for CVE Severity Classification
================================================================

Task:   4-class text classification
        Input:  CVE description (+ optional CVSS vector string)
        Output: CRITICAL / HIGH / MEDIUM / LOW

Dataset: data/training/cve_severity_train.csv
         (built by: python untils/build_training_data.py)

Model choices (edit MODEL_NAME below):
  - "distilbert-base-uncased"       ~250MB  fast, good baseline
  - "jackaduma/SecBERT"             ~440MB  cybersecurity-domain (recommended)
  - "bert-base-uncased"             ~440MB  standard BERT

Output:
  - models/bert_severity/           fine-tuned model directory
  - models/bert_severity_meta.json  label map + eval metrics

Usage:
    # Step 1 - build dataset (if not done already)
    python untils/build_training_data.py

    # Step 2 - fine-tune
    python untils/finetune_bert_severity.py

    # Step 3 - app.py will auto-load the model on startup

Academic reference:
    Sanh et al. (2020). "DistilBERT, a distilled version of BERT:
    smaller, faster, cheaper and lighter." arXiv:1910.01108

    Devlin et al. (2019). "BERT: Pre-training of Deep Bidirectional
    Transformers for Language Understanding." NAACL 2019.
"""

import csv
import json
import sys
import time
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── Configuration ──────────────────────────────────────────────────────────────
MODEL_NAME   = "distilbert-base-uncased"   # change to "jackaduma/SecBERT" for SecBERT
DATASET_PATH = ROOT / "data" / "training" / "cve_severity_train.csv"
OUTPUT_DIR   = ROOT / "models" / "bert_severity"
META_PATH    = ROOT / "models" / "bert_severity_meta.json"

# Training hyperparameters
MAX_LEN      = 256        # token limit per CVE description
BATCH_SIZE   = 16         # reduce to 8 if GPU/CPU memory is limited
EPOCHS       = 3
LR           = 2e-5
WEIGHT_DECAY = 0.01
TEST_SIZE    = 0.15       # 15% test set
VAL_SIZE     = 0.10       # 10% validation set
SEED         = 42

LABEL2ID = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ID2LABEL = {v: k for k, v in LABEL2ID.items()}


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_dataset(path: Path):
    """Load CSV dataset, return list of (text, label_id) tuples."""
    records = []
    skipped = 0
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            desc   = (row.get("description") or "").strip()
            sev    = (row.get("severity")    or "").upper().strip()
            vector = (row.get("vector_string") or "").strip()

            if not desc or sev not in LABEL2ID:
                skipped += 1
                continue

            # Concatenate description + CVSS vector tokens
            # This gives the model both semantic and structural signal
            text = desc
            if vector:
                # Convert "AV:N/AC:L/PR:N" → "AV_N AC_L PR_N" (already tokenized)
                vtokens = " ".join(
                    f"{p.split(':')[0]}_{p.split(':')[1]}"
                    for p in vector.split("/") if ":" in p
                )
                text = f"{desc} [SEP] {vtokens}"

            records.append((text, LABEL2ID[sev]))

    return records, skipped


def stratified_split(records, test_size=0.15, val_size=0.10, seed=42):
    """Split into train/val/test maintaining class balance."""
    import random
    random.seed(seed)

    # Group by label
    by_label = {}
    for text, lbl in records:
        by_label.setdefault(lbl, []).append((text, lbl))

    train, val, test = [], [], []
    for lbl, items in by_label.items():
        random.shuffle(items)
        n = len(items)
        n_test = max(1, int(n * test_size))
        n_val  = max(1, int(n * val_size))
        test  += items[:n_test]
        val   += items[n_test:n_test + n_val]
        train += items[n_test + n_val:]

    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)
    return train, val, test


# ── PyTorch Dataset ────────────────────────────────────────────────────────────

class CVEDataset:
    def __init__(self, records, tokenizer, max_len):
        self.records   = records
        self.tokenizer = tokenizer
        self.max_len   = max_len

    def __len__(self):
        return len(self.records)

    def __getitem__(self, idx):
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
            "labels":         __import__("torch").tensor(label, dtype=__import__("torch").long),
        }


# ── Training & Evaluation ──────────────────────────────────────────────────────

def compute_metrics(eval_pred):
    """HuggingFace Trainer metric function."""
    import numpy as np
    from sklearn.metrics import accuracy_score, f1_score, classification_report

    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)

    acc = accuracy_score(labels, preds)
    f1  = f1_score(labels, preds, average="macro", zero_division=0)

    return {"accuracy": acc, "macro_f1": f1}


def train(records):
    """Full training pipeline."""
    import torch
    from transformers import (
        AutoTokenizer, AutoModelForSequenceClassification,
        TrainingArguments, Trainer, EarlyStoppingCallback,
    )
    from sklearn.metrics import classification_report
    import numpy as np

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"\n[Train] Device: {device.upper()}")
    print(f"[Train] Base model: {MODEL_NAME}")

    # ── Split dataset ──
    train_data, val_data, test_data = stratified_split(
        records, test_size=TEST_SIZE, val_size=VAL_SIZE, seed=SEED
    )
    print(f"[Train] Split: train={len(train_data)}, val={len(val_data)}, test={len(test_data)}")

    # ── Tokenizer ──
    print(f"[Train] Loading tokenizer …")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    train_ds = CVEDataset(train_data, tokenizer, MAX_LEN)
    val_ds   = CVEDataset(val_data,   tokenizer, MAX_LEN)
    test_ds  = CVEDataset(test_data,  tokenizer, MAX_LEN)

    # ── Model ──
    print(f"[Train] Loading model …")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=len(LABEL2ID),
        id2label=ID2LABEL,
        label2id=LABEL2ID,
        ignore_mismatched_sizes=True,
    )

    # ── Training arguments ──
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE * 2,
        learning_rate=LR,
        weight_decay=WEIGHT_DECAY,
        warmup_ratio=0.1,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        logging_steps=50,
        report_to="none",       # disable wandb/tensorboard
        seed=SEED,
        fp16=torch.cuda.is_available(),
    )

    # ── Trainer ──
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    # ── Train ──
    print(f"\n{'='*60}")
    print(f"  Training {MODEL_NAME} for CVE Severity Classification")
    print(f"{'='*60}")
    t0 = time.time()
    trainer.train()
    elapsed = time.time() - t0
    print(f"\n[Train] Training complete in {elapsed:.1f}s ({elapsed/60:.1f}m)")

    # ── Final evaluation on test set ──
    print("\n[Eval] Evaluating on held-out test set …")
    pred_output = trainer.predict(test_ds)
    preds  = np.argmax(pred_output.predictions, axis=-1)
    labels = pred_output.label_ids

    report_str = classification_report(
        labels, preds,
        target_names=[ID2LABEL[i] for i in range(len(LABEL2ID))],
        digits=4,
    )
    print("\n" + report_str)

    # Compute summary metrics
    from sklearn.metrics import accuracy_score, f1_score
    acc = float(accuracy_score(labels, preds))
    f1  = float(f1_score(labels, preds, average="macro", zero_division=0))

    # ── Save fine-tuned model ──
    trainer.save_model(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))
    print(f"[Save] Model saved → {OUTPUT_DIR}")

    # ── Save metadata ──
    meta = {
        "base_model":    MODEL_NAME,
        "num_labels":    len(LABEL2ID),
        "label2id":      LABEL2ID,
        "id2label":      {str(k): v for k, v in ID2LABEL.items()},
        "max_length":    MAX_LEN,
        "train_samples": len(train_data),
        "val_samples":   len(val_data),
        "test_samples":  len(test_data),
        "test_accuracy": round(acc, 4),
        "test_macro_f1": round(f1, 4),
        "epochs":        EPOCHS,
        "learning_rate": LR,
        "batch_size":    BATCH_SIZE,
        "device":        device,
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[Save] Metadata saved → {META_PATH}")

    # ── Summary ──
    print(f"\n{'='*60}")
    print(f"  RESULTS")
    print(f"{'='*60}")
    print(f"  Test Accuracy : {acc*100:.2f}%")
    print(f"  Test Macro-F1 : {f1*100:.2f}%")
    print(f"  Model saved   : {OUTPUT_DIR}/")
    print(f"{'='*60}")

    return acc, f1


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  CVE Severity — DistilBERT/SecBERT Fine-tuning")
    print("=" * 60)

    # Check prerequisites
    try:
        import torch
        import transformers
        from sklearn.metrics import accuracy_score
        print(f"[OK] PyTorch {torch.__version__}")
        print(f"[OK] Transformers {transformers.__version__}")
    except ImportError as e:
        print(f"[ERR] Missing package: {e}")
        print("      pip install torch transformers scikit-learn")
        sys.exit(1)

    # Check dataset
    if not DATASET_PATH.exists():
        print(f"\n[ERR] Dataset not found: {DATASET_PATH}")
        print("      Run first: python untils/build_training_data.py")
        sys.exit(1)

    # Load dataset
    print(f"\n[1/3] Loading dataset: {DATASET_PATH}")
    records, skipped = load_dataset(DATASET_PATH)
    counts = Counter(lbl for _, lbl in records)
    print(f"      Total: {len(records):,} records  (skipped {skipped})")
    for lbl_id, lbl_name in ID2LABEL.items():
        print(f"      {lbl_name:10s}: {counts.get(lbl_id, 0):>6,}")

    if len(records) < 100:
        print("\n[WARN] Very small dataset — run build_training_data.py to collect more CVEs")

    # Train
    print(f"\n[2/3] Fine-tuning {MODEL_NAME} …")
    acc, f1 = train(records)

    print(f"\n[3/3] Done!")
    print(f"      Start the app: python backend/app.py")
    print(f"      The fine-tuned model will be loaded automatically.")


if __name__ == "__main__":
    main()
