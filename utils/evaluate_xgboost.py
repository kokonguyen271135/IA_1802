#!/usr/bin/env python3
"""
Evaluate XGBoost/RandomForest Severity Classifier using cross-validation.
Output: models/xgboost_severity_report.txt
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

def parse_cvss_features(vector_string: str) -> list:
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
    feats = {k: 0 for k in _CVSS_ENCODINGS}
    if vector_string:
        for part in vector_string.split("/"):
            if ":" not in part:
                continue
            key, val = part.split(":", 1)
            if key in _CVSS_ENCODINGS:
                feats[key] = _CVSS_ENCODINGS[key].get(val, 0)
    return [feats[k] for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")]


def main():
    import pandas as pd
    import scipy.sparse as sp
    from sklearn.model_selection import cross_validate, StratifiedKFold, train_test_split
    from sklearn.metrics import classification_report
    from sklearn.base import clone

    print("[*] Loading model ...")
    if not MODEL_PATH.exists():
        print(f"[!] Model not found: {MODEL_PATH}")
        sys.exit(1)

    with open(MODEL_PATH, "rb") as f:
        data = pickle.load(f)

    model      = data["model"]
    vectorizer = data["vectorizer"]
    classes    = data["classes"]
    clf_name   = data.get("classifier", "XGBoost")

    print(f"[+] Loaded: {clf_name}, classes={classes}")

    print("[*] Loading dataset ...")
    df = pd.read_csv(DATA_CSV)
    df = df.dropna(subset=["description", "severity"])
    df = df[df["severity"].isin(LABELS)]
    df = df[df["description"].str.len() > 20]
    if "cve_id" in df.columns:
        df = df.drop_duplicates(subset=["cve_id"])
    else:
        df = df.drop_duplicates(subset=["description"])

    print(f"[+] Dataset: {len(df):,} unique samples")

    descriptions_all   = df["description"].tolist()
    vector_strings_all = df.get("vector_string", pd.Series([""] * len(df))).fillna("").tolist()
    y_all              = df["severity"].tolist()

    print("[*] Building features ...")
    X_text_all = vectorizer.transform(descriptions_all)
    X_cvss_all = np.array([parse_cvss_features(vs) for vs in vector_strings_all])
    X_all      = sp.hstack([X_text_all, sp.csr_matrix(X_cvss_all)])

    # 5-fold cross-validation
    print("[*] Running 5-fold cross-validation (this may take ~2 min) ...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    clf_clone = clone(model)

    cv_results = cross_validate(
        clf_clone, X_all, y_all,
        cv=cv,
        scoring=["accuracy", "f1_macro"],
        n_jobs=-1,
    )

    cv_acc   = cv_results["test_accuracy"]
    cv_f1    = cv_results["test_f1_macro"]
    mean_acc = cv_acc.mean()
    std_acc  = cv_acc.std()
    mean_f1  = cv_f1.mean()

    # Inference speed on 20% held-out
    _, df_test = train_test_split(df, test_size=0.2, random_state=42, stratify=df["severity"])
    desc_test = df_test["description"].tolist()
    vs_test   = df_test.get("vector_string", pd.Series([""] * len(df_test))).fillna("").tolist()
    y_true    = df_test["severity"].tolist()

    X_text_t = vectorizer.transform(desc_test)
    X_cvss_t = np.array([parse_cvss_features(vs) for vs in vs_test])
    X_t      = sp.hstack([X_text_t, sp.csr_matrix(X_cvss_t)])

    print("[*] Measuring inference speed ...")
    t0         = time.time()
    y_pred_raw = model.predict(X_t)
    elapsed_ms = (time.time() - t0) / len(y_true) * 1000

    if hasattr(y_pred_raw[0], 'item'):
        y_pred = [classes[int(p)] for p in y_pred_raw]
    else:
        y_pred = list(y_pred_raw)

    report = classification_report(y_true, y_pred, digits=4, target_names=sorted(set(y_true)))

    lines = []
    lines.append(f"{clf_name} CVE Severity Classifier - Evaluation Report")
    lines.append("=" * 58)
    lines.append(f"Classifier       : {clf_name}")
    if clf_name == "RandomForest":
        lines.append(f"  Note: XGBoost not installed at train time, fell back to RandomForest")
    lines.append(f"Features         : TF-IDF (5,000 features) + CVSS vector (8 features)")
    lines.append(f"Dataset          : {DATA_CSV.name}")
    lines.append(f"Total samples    : {len(df):,} (after deduplication)")
    lines.append(f"Evaluation       : 5-fold stratified cross-validation")
    lines.append("")
    lines.append(f"CV Accuracy      : {mean_acc:.4f} +/- {std_acc:.4f}  ({mean_acc*100:.2f}%)")
    lines.append(f"CV Macro-F1      : {mean_f1:.4f} ({mean_f1*100:.2f}%)")
    lines.append(f"Per-fold accuracy: " + "  ".join(f"{a:.4f}" for a in cv_acc))
    lines.append(f"Inference speed  : {elapsed_ms:.2f} ms/sample")
    lines.append("")
    lines.append("Classification Report (20% held-out split for reference):")
    lines.append(report)

    output = "\n".join(lines)
    print("\n" + output)

    with open(REPORT_OUT, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"\n[+] Report saved -> {REPORT_OUT}")


if __name__ == "__main__":
    main()
