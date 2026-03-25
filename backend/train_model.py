#!/usr/bin/env python3
# backend/train_model.py

"""
XGBoost PE Malware Classifier — Training Script

Generates a synthetic training dataset that mimics real-world PE feature
distributions (benign vs malicious), then trains an XGBoost classifier.

Synthetic data is based on published research characterizing PE malware:
  - High-entropy sections → packing / obfuscation
  - Missing security mitigations → common in malware
  - Specific API co-occurrence patterns → process injection, C2
  - Network + injection together → strong malware signal

Usage:
    python train_model.py [--samples N] [--output ml_model.pkl]

To train on REAL labeled data, provide a CSV with columns matching
FEATURE_NAMES in ml_classifier.py plus a "label" column (0=benign, 1=malware).
    python train_model.py --csv path/to/data.csv
"""

import argparse
import pickle
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report
import xgboost as xgb

from ml_classifier import FEATURE_NAMES, MODEL_PATH

SEED = 42
rng  = np.random.default_rng(SEED)


# ─── Synthetic Dataset Generator ─────────────────────────────────────────────

def _clip(arr, lo=0.0, hi=None):
    if hi is not None:
        return np.clip(arr, lo, hi)
    return np.maximum(arr, lo)


def generate_benign_samples(n: int) -> np.ndarray:
    """
    Simulate feature vectors for BENIGN PE files (legitimate software).

    Benign characteristics (from empirical PE studies):
      - Low to moderate entropy (no packing)
      - Most security mitigations enabled (modern compilers default)
      - Few or no suspicious API categories
      - Normal section counts, sizes
      - Occasional URLs (update servers), no IPs
      - Compile timestamp looks real and recent
    """
    X = np.zeros((n, len(FEATURE_NAMES)), dtype=np.float32)
    idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

    # File size: 50 KB – 50 MB, log-normal
    X[:, idx["file_size_kb"]]       = _clip(rng.lognormal(7.0, 1.5, n), 10, 100_000)
    X[:, idx["is_dll"]]             = (rng.random(n) < 0.35).astype(np.float32)
    X[:, idx["is_64bit"]]           = (rng.random(n) < 0.65).astype(np.float32)
    X[:, idx["has_valid_timestamp"]]= (rng.random(n) < 0.90).astype(np.float32)
    X[:, idx["binary_age_days"]]    = _clip(rng.lognormal(7.5, 1.0, n), 0, 5000)

    # Sections: 3-8, low entropy
    X[:, idx["section_count"]]      = _clip(rng.integers(3, 9, n).astype(np.float32))
    X[:, idx["mean_entropy"]]       = _clip(rng.normal(4.5, 0.9, n), 0, 8)
    X[:, idx["max_entropy"]]        = _clip(X[:, idx["mean_entropy"]] + rng.uniform(0.3, 1.5, n), 0, 8)
    X[:, idx["high_entropy_sections"]] = (rng.random(n) < 0.05).astype(np.float32)
    X[:, idx["exec_sections"]]      = _clip(rng.integers(1, 4, n).astype(np.float32))
    X[:, idx["writable_exec_sections"]] = (rng.random(n) < 0.03).astype(np.float32)
    X[:, idx["has_suspicious_section_names"]] = (rng.random(n) < 0.02).astype(np.float32)

    # Imports: many, mostly legitimate
    X[:, idx["import_count"]]       = _clip(rng.normal(120, 60, n), 5, 1000)
    X[:, idx["dll_import_count"]]   = _clip(rng.normal(8, 3, n), 1, 30)

    # Suspicious API categories: rarely more than 1-2
    for cat in ["has_process_injection","has_keylogging","has_persistence",
                "has_privilege_escalation","has_anti_analysis","has_shellcode"]:
        X[:, idx[cat]] = (rng.random(n) < 0.04).astype(np.float32)
    X[:, idx["has_network"]]        = (rng.random(n) < 0.30).astype(np.float32)
    X[:, idx["has_file_ops"]]       = (rng.random(n) < 0.55).astype(np.float32)
    X[:, idx["has_crypto"]]         = (rng.random(n) < 0.15).astype(np.float32)
    X[:, idx["has_execution"]]      = (rng.random(n) < 0.20).astype(np.float32)
    cat_cols = [idx[c] for c in ["has_process_injection","has_network","has_keylogging",
                "has_persistence","has_privilege_escalation","has_anti_analysis",
                "has_shellcode","has_file_ops","has_crypto","has_execution"]]
    X[:, idx["suspicious_category_count"]] = X[:, cat_cols].sum(axis=1)

    X[:, idx["export_count"]]       = _clip(rng.lognormal(0.5, 1.5, n), 0, 500)
    X[:, idx["url_count"]]          = _clip(rng.integers(0, 4, n).astype(np.float32))
    X[:, idx["ip_count"]]           = (rng.random(n) < 0.05).astype(np.float32)
    X[:, idx["suspicious_cmd_count"]] = (rng.random(n) < 0.05).astype(np.float32)
    X[:, idx["registry_key_count"]] = _clip(rng.integers(0, 6, n).astype(np.float32))
    X[:, idx["has_base64_strings"]] = (rng.random(n) < 0.08).astype(np.float32)

    # Security mitigations: mostly enabled for modern software
    X[:, idx["has_aslr"]]          = (rng.random(n) < 0.85).astype(np.float32)
    X[:, idx["has_dep"]]           = (rng.random(n) < 0.82).astype(np.float32)
    X[:, idx["has_gs"]]            = (rng.random(n) < 0.80).astype(np.float32)
    X[:, idx["has_cfg"]]           = (rng.random(n) < 0.45).astype(np.float32)
    X[:, idx["has_seh"]]           = (rng.random(n) < 0.65).astype(np.float32)
    X[:, idx["has_authenticode"]]  = (rng.random(n) < 0.60).astype(np.float32)
    mit_cols = [idx[c] for c in ["has_aslr","has_dep","has_gs","has_cfg","has_seh","has_authenticode"]]
    X[:, idx["mitigation_score"]]  = X[:, mit_cols].sum(axis=1)

    # Composite
    X[:, idx["network_plus_injection"]] = (
        X[:, idx["has_network"]] * X[:, idx["has_process_injection"]]
    )
    X[:, idx["high_entropy_no_mitigations"]] = (
        (X[:, idx["max_entropy"]] > 7.0) & (X[:, idx["mitigation_score"]] == 0)
    ).astype(np.float32)
    X[:, idx["many_suspicious_few_imports"]] = (
        (X[:, idx["suspicious_category_count"]] >= 3) &
        (X[:, idx["import_count"]] < 20)
    ).astype(np.float32)

    return X


def generate_malware_samples(n: int) -> np.ndarray:
    """
    Simulate feature vectors for MALWARE PE files.

    Malware characteristics (from empirical PE studies):
      - Packed/obfuscated → high section entropy
      - Missing security mitigations (hand-assembled, old compilers)
      - Multiple suspicious API categories co-occurring
      - Network + process injection = classic RAT / backdoor
      - Small import tables (API hashing) or very large (bundled)
      - Embedded IPs, suspicious commands, encoded strings
    """
    X = np.zeros((n, len(FEATURE_NAMES)), dtype=np.float32)
    idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

    # File size: smaller than benign on average (droppers, shellcode loaders)
    X[:, idx["file_size_kb"]]       = _clip(rng.lognormal(5.5, 1.8, n), 1, 50_000)
    X[:, idx["is_dll"]]             = (rng.random(n) < 0.25).astype(np.float32)
    X[:, idx["is_64bit"]]           = (rng.random(n) < 0.45).astype(np.float32)
    X[:, idx["has_valid_timestamp"]]= (rng.random(n) < 0.40).astype(np.float32)
    X[:, idx["binary_age_days"]]    = _clip(rng.lognormal(6.0, 2.0, n), 0, 8000)

    # Sections: packing → often 2-3 sections, very high entropy
    X[:, idx["section_count"]]      = _clip(rng.integers(2, 7, n).astype(np.float32))
    X[:, idx["mean_entropy"]]       = _clip(rng.normal(6.8, 0.8, n), 0, 8)
    X[:, idx["max_entropy"]]        = _clip(rng.normal(7.4, 0.5, n), 0, 8)
    # ~60% of malware has at least one high-entropy section
    X[:, idx["high_entropy_sections"]] = _clip(
        rng.choice([0, 1, 2, 3], n, p=[0.30, 0.40, 0.20, 0.10]).astype(np.float32)
    )
    X[:, idx["exec_sections"]]      = _clip(rng.integers(1, 5, n).astype(np.float32))
    X[:, idx["writable_exec_sections"]] = (rng.random(n) < 0.35).astype(np.float32)
    X[:, idx["has_suspicious_section_names"]] = (rng.random(n) < 0.30).astype(np.float32)

    # Imports: API hashing → small tables; or bloated with legitimate DLLs to hide
    import_style = rng.choice([0, 1, 2], n, p=[0.40, 0.35, 0.25])
    import_counts = np.where(
        import_style == 0, _clip(rng.normal(15, 10, n), 1, 50),      # API hashing
        np.where(
            import_style == 1, _clip(rng.normal(80, 40, n), 10, 400), # normal
            _clip(rng.normal(300, 100, n), 100, 1000)                  # bloated
        )
    )
    X[:, idx["import_count"]]       = import_counts.astype(np.float32)
    X[:, idx["dll_import_count"]]   = _clip(rng.normal(5, 3, n), 1, 20)

    # Suspicious API categories: multiple categories co-occurring
    X[:, idx["has_process_injection"]] = (rng.random(n) < 0.65).astype(np.float32)
    X[:, idx["has_network"]]           = (rng.random(n) < 0.55).astype(np.float32)
    X[:, idx["has_keylogging"]]        = (rng.random(n) < 0.35).astype(np.float32)
    X[:, idx["has_persistence"]]       = (rng.random(n) < 0.60).astype(np.float32)
    X[:, idx["has_privilege_escalation"]] = (rng.random(n) < 0.45).astype(np.float32)
    X[:, idx["has_anti_analysis"]]     = (rng.random(n) < 0.50).astype(np.float32)
    X[:, idx["has_shellcode"]]         = (rng.random(n) < 0.55).astype(np.float32)
    X[:, idx["has_file_ops"]]          = (rng.random(n) < 0.50).astype(np.float32)
    X[:, idx["has_crypto"]]            = (rng.random(n) < 0.45).astype(np.float32)
    X[:, idx["has_execution"]]         = (rng.random(n) < 0.60).astype(np.float32)
    cat_cols = [idx[c] for c in ["has_process_injection","has_network","has_keylogging",
                "has_persistence","has_privilege_escalation","has_anti_analysis",
                "has_shellcode","has_file_ops","has_crypto","has_execution"]]
    X[:, idx["suspicious_category_count"]] = X[:, cat_cols].sum(axis=1)

    X[:, idx["export_count"]]           = (rng.random(n) < 0.20).astype(np.float32) * \
                                          _clip(rng.integers(1, 20, n), 0)
    X[:, idx["url_count"]]              = _clip(rng.integers(0, 6, n).astype(np.float32))
    X[:, idx["ip_count"]]               = _clip(rng.integers(0, 5, n).astype(np.float32))
    X[:, idx["suspicious_cmd_count"]]   = _clip(rng.integers(0, 8, n).astype(np.float32))
    X[:, idx["registry_key_count"]]     = _clip(rng.integers(0, 10, n).astype(np.float32))
    X[:, idx["has_base64_strings"]]     = (rng.random(n) < 0.40).astype(np.float32)

    # Security mitigations: mostly absent in malware
    X[:, idx["has_aslr"]]          = (rng.random(n) < 0.20).astype(np.float32)
    X[:, idx["has_dep"]]           = (rng.random(n) < 0.18).astype(np.float32)
    X[:, idx["has_gs"]]            = (rng.random(n) < 0.12).astype(np.float32)
    X[:, idx["has_cfg"]]           = (rng.random(n) < 0.05).astype(np.float32)
    X[:, idx["has_seh"]]           = (rng.random(n) < 0.15).astype(np.float32)
    X[:, idx["has_authenticode"]]  = (rng.random(n) < 0.08).astype(np.float32)
    mit_cols = [idx[c] for c in ["has_aslr","has_dep","has_gs","has_cfg","has_seh","has_authenticode"]]
    X[:, idx["mitigation_score"]]  = X[:, mit_cols].sum(axis=1)

    # Composite — these will be very strong signals for malware
    X[:, idx["network_plus_injection"]] = (
        X[:, idx["has_network"]] * X[:, idx["has_process_injection"]]
    )
    X[:, idx["high_entropy_no_mitigations"]] = (
        (X[:, idx["max_entropy"]] > 7.0) & (X[:, idx["mitigation_score"]] == 0)
    ).astype(np.float32)
    X[:, idx["many_suspicious_few_imports"]] = (
        (X[:, idx["suspicious_category_count"]] >= 3) &
        (X[:, idx["import_count"]] < 20)
    ).astype(np.float32)

    return X


# ─── Training ─────────────────────────────────────────────────────────────────

def train(n_benign: int = 5000, n_malware: int = 5000, csv_path: str = None,
          output: Path = MODEL_PATH):
    """Train XGBoost classifier and save to output path."""

    print("=" * 60)
    print("XGBoost PE Malware Classifier — Training")
    print("=" * 60)

    if csv_path:
        # ── Real labeled data ──────────────────────────────────────────
        import pandas as pd
        df = pd.read_csv(csv_path)
        missing = set(FEATURE_NAMES) - set(df.columns)
        if missing:
            raise ValueError(f"CSV missing features: {missing}")
        if "label" not in df.columns:
            raise ValueError("CSV must have a 'label' column (0=benign, 1=malware)")
        X = df[FEATURE_NAMES].values.astype(np.float32)
        y = df["label"].values.astype(np.int32)
        print(f"Loaded CSV: {len(df)} samples  "
              f"({(y==0).sum()} benign, {(y==1).sum()} malware)")
    else:
        # ── Synthetic data ─────────────────────────────────────────────
        print(f"Generating synthetic dataset: {n_benign} benign + {n_malware} malware")
        X_benign  = generate_benign_samples(n_benign)
        X_malware = generate_malware_samples(n_malware)
        X = np.vstack([X_benign, X_malware])
        y = np.array([0]*n_benign + [1]*n_malware, dtype=np.int32)
        print(f"Feature matrix: {X.shape}")

    # ── Train / Validation split ───────────────────────────────────────
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )
    print(f"Train: {len(X_train)}  |  Val: {len(X_val)}")

    # ── XGBoost hyperparameters ────────────────────────────────────────
    # Tuned for PE feature data: moderate depth, strong regularization
    params = dict(
        n_estimators      = 400,
        max_depth         = 5,
        learning_rate     = 0.05,
        subsample         = 0.8,
        colsample_bytree  = 0.8,
        min_child_weight  = 3,
        gamma             = 0.1,
        reg_alpha         = 0.05,  # L1
        reg_lambda        = 1.0,   # L2
        scale_pos_weight  = n_benign / max(1, n_malware),  # class balance
        use_label_encoder = False,
        eval_metric       = "auc",
        random_state      = SEED,
    )

    print("\nHyperparameters:")
    for k, v in params.items():
        print(f"  {k:<22} = {v}")

    print("\nTraining XGBoost...")
    model = xgb.XGBClassifier(**params)
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=50,
    )

    # ── Evaluation ────────────────────────────────────────────────────
    y_prob = model.predict_proba(X_val)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)
    auc    = roc_auc_score(y_val, y_prob)

    print(f"\n{'='*60}")
    print(f"Validation AUC:  {auc:.4f}")
    print(f"\nClassification Report (threshold=0.5):")
    print(classification_report(y_val, y_pred, target_names=["Benign", "Malware"]))

    # ── Feature importance ─────────────────────────────────────────────
    imps = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("Top 15 Most Important Features:")
    for i, (feat, imp) in enumerate(imps[:15], 1):
        bar = "█" * int(imp * 200)
        print(f"  {i:>2}. {feat:<35} {imp:.4f}  {bar}")

    # ── Save model ─────────────────────────────────────────────────────
    bundle = {
        "model": model,
        "meta": {
            "feature_names": FEATURE_NAMES,
            "train_samples":  len(X_train),
            "val_samples":    len(X_val),
            "val_auc":        round(auc, 4),
            "n_benign":       n_benign,
            "n_malware":      n_malware,
            "data_source":    csv_path or "synthetic",
            "xgboost_version": xgb.__version__,
        }
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "wb") as f:
        pickle.dump(bundle, f)

    print(f"\n✓ Model saved → {output}")
    print(f"  AUC={auc:.4f} | {len(X_train)} training samples | {len(FEATURE_NAMES)} features")
    return auc


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train XGBoost PE malware classifier")
    parser.add_argument("--samples",  type=int,  default=5000, help="Samples per class (synthetic mode)")
    parser.add_argument("--csv",      type=str,  default=None, help="Path to real labeled CSV")
    parser.add_argument("--output",   type=str,  default=str(MODEL_PATH))
    args = parser.parse_args()

    train(
        n_benign  = args.samples,
        n_malware = args.samples,
        csv_path  = args.csv,
        output    = Path(args.output),
    )
