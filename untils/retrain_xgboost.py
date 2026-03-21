#!/usr/bin/env python3
"""
Retrain XGBoost Severity Classifier with proper train/test split.
Output:
  models/xgboost_severity.pkl
  models/xgboost_severity_report.txt
"""

import sys
import time
import pickle
import numpy as np
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.append(str(ROOT / "backend"))

MODEL_PATH = ROOT / "models" / "xgboost_severity.pkl"
DATA_CSV   = ROOT / "data" / "training" / "cve_severity_train.csv"
REPORT_OUT = ROOT / "models" / "xgboost_severity_report.txt"

LABELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

_CVSS_ENCODINGS = {
    "AV": {"N": 3, "A": 2, "L": 1, "P": 0},
    "AC": {"L": 1, "H": 0},
    "PR": {"N": 2, "L": 1, "H": 0},
    "UI": {"N": 1, "R": 0},
    "S":  {"C": 1, "U": 0},
    "C":  {"H": 2, "M": 1, "L": 0, "N": 0},
    "I":  {"H": 2, "M": 1, "L": 0, "N": 0},
    "A":  {"H": 2, "M": 1, "L": 0, "N": 0},
}

def parse_cvss(vs: str) -> list:
    feats = {k: 0 for k in _CVSS_ENCODINGS}
    for part in (vs or "").split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            if k in _CVSS_ENCODINGS:
                feats[k] = _CVSS_ENCODINGS[k].get(v, 0)
    return [feats[k] for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")]


def main():
    import pandas as pd
    import scipy.sparse as sp
    import xgboost as xgb
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report, f1_score
    import time as _time

    print("[*] Loading dataset ...")
    df = pd.read_csv(DATA_CSV)
    df = df.dropna(subset=["description", "severity"])
    df = df[df["severity"].isin(LABELS)]
    df = df[df["description"].str.len() > 20]
    if "cve_id" in df.columns:
        df = df.drop_duplicates(subset=["cve_id"])
    else:
        df = df.drop_duplicates(subset=["description"])

    print(f"[+] Total unique samples: {len(df):,}")

    # Proper train/test split BEFORE fitting anything
    df_train, df_test = train_test_split(
        df, test_size=0.2, random_state=42, stratify=df["severity"]
    )
    print(f"[+] Train: {len(df_train):,} | Test: {len(df_test):,}")

    desc_train = df_train["description"].tolist()
    vs_train   = df_train.get("vector_string", pd.Series([""] * len(df_train))).fillna("").tolist()
    y_train_raw = df_train["severity"].tolist()

    desc_test  = df_test["description"].tolist()
    vs_test    = df_test.get("vector_string", pd.Series([""] * len(df_test))).fillna("").tolist()
    y_test_raw  = df_test["severity"].tolist()

    # TF-IDF fit ONLY on train
    print("[*] Fitting TF-IDF on train set ...")
    vectorizer = TfidfVectorizer(max_features=5_000, ngram_range=(1, 2), sublinear_tf=True, min_df=2)
    X_text_train = vectorizer.fit_transform(desc_train)
    X_text_test  = vectorizer.transform(desc_test)

    X_cvss_train = np.array([parse_cvss(v) for v in vs_train])
    X_cvss_test  = np.array([parse_cvss(v) for v in vs_test])

    X_train = sp.hstack([X_text_train, sp.csr_matrix(X_cvss_train)])
    X_test  = sp.hstack([X_text_test,  sp.csr_matrix(X_cvss_test)])

    le = LabelEncoder()
    y_train = le.fit_transform(y_train_raw)
    y_test  = le.transform(y_test_raw)
    classes = list(le.classes_)

    # Train XGBoost
    print("[*] Training XGBoost ...")
    t0 = _time.time()
    clf = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    clf.fit(X_train, y_train)
    train_time = _time.time() - t0
    print(f"[+] Training done in {train_time:.1f}s")

    # Evaluate on held-out test set
    print("[*] Evaluating on test set ...")
    t0 = _time.time()
    y_pred = clf.predict(X_test)
    infer_ms = (_time.time() - t0) / len(y_test) * 1000

    y_pred_labels = [classes[p] for p in y_pred]
    acc    = accuracy_score(y_test_raw, y_pred_labels)
    macro_f1 = f1_score(y_test_raw, y_pred_labels, average="macro")
    report = classification_report(y_test_raw, y_pred_labels, digits=4)

    # Save model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({
            "model":      clf,
            "vectorizer": vectorizer,
            "classes":    classes,
            "classifier": "XGBoost",
        }, f)
    print(f"[+] Model saved -> {MODEL_PATH}")

    # Write report
    lines = []
    lines.append("XGBoost CVE Severity Classifier - Training Report")
    lines.append("=" * 52)
    lines.append(f"Classifier       : XGBoost {xgb.__version__}")
    lines.append(f"Features         : TF-IDF (5,000) + CVSS vector (8 features)")
    lines.append(f"Dataset          : {DATA_CSV.name}")
    lines.append(f"Total samples    : {len(df):,} (after deduplication)")
    lines.append(f"Training samples : {len(df_train):,}")
    lines.append(f"Test samples     : {len(df_test):,}")
    lines.append(f"Training time    : {train_time:.1f}s")
    lines.append("")
    lines.append(f"Hyperparameters:")
    lines.append(f"  n_estimators   : 200")
    lines.append(f"  max_depth      : 6")
    lines.append(f"  learning_rate  : 0.1")
    lines.append(f"  subsample      : 0.8")
    lines.append(f"  colsample_bytree: 0.8")
    lines.append("")
    lines.append(f"Test accuracy    : {acc:.4f} ({acc*100:.2f}%)")
    lines.append(f"Test macro-F1    : {macro_f1:.4f} ({macro_f1*100:.2f}%)")
    lines.append(f"Inference speed  : {infer_ms:.2f} ms/sample")
    lines.append("")
    lines.append("Classification Report:")
    lines.append(report)
    lines.append(f"Model saved to   : models/xgboost_severity.pkl")

    output = "\n".join(lines)
    print("\n" + output)

    with open(REPORT_OUT, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"\n[+] Report saved -> {REPORT_OUT}")


if __name__ == "__main__":
    main()
