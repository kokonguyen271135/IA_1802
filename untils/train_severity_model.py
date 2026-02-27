# untils/train_severity_model.py

"""
Train CVE Severity Classifier.

Input:  data/training/cve_severity_train.csv
Output: models/severity_clf.pkl   (scikit-learn Pipeline: TF-IDF + Logistic Regression)
        models/severity_report.txt (accuracy + classification report)

Model predicts CRITICAL / HIGH / MEDIUM / LOW from CVE description text.
"""

import sys
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline

ROOT       = Path(__file__).parent.parent
TRAIN_CSV  = ROOT / "data/training/cve_severity_train.csv"
MODEL_PATH = ROOT / "models/severity_clf.pkl"
REPORT_PATH = ROOT / "models/severity_report.txt"
LABELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def build_text_feature(df: pd.DataFrame) -> pd.Series:
    """
    Combine description + CVSS vector string tokens for richer features.
    e.g. "AV:N AC:L PR:N" tells the model about network-accessible, low-complexity attacks.
    """
    texts = []
    for _, row in df.iterrows():
        desc   = str(row.get("description",   "") or "")
        vector = str(row.get("vector_string", "") or "")
        # Tokenize CVSS vector: "CVSS:3.1/AV:N/AC:L/PR:N/..." → "AV N AC L PR N ..."
        vector_tokens = (
            vector.replace("CVSS:3.1", "")
                  .replace("CVSS:3.0", "")
                  .replace("CVSS:2.0", "")
                  .replace("/", " ")
                  .replace(":", " ")
        )
        texts.append(f"{desc} {vector_tokens}".strip())
    return pd.Series(texts)


def main():
    print("=" * 60)
    print("TRAIN CVE SEVERITY CLASSIFIER")
    print("=" * 60)

    # ── Load data ─────────────────────────────────────────────
    if not TRAIN_CSV.exists():
        print(f"\n[ERROR] Training data not found: {TRAIN_CSV}")
        print("Run first: python untils/build_training_data.py")
        sys.exit(1)

    df = pd.read_csv(TRAIN_CSV)
    df = df.dropna(subset=["description", "severity"])
    df = df[df["severity"].isin(LABELS)]
    df = df[df["description"].str.len() > 20]   # drop very short descriptions

    print(f"\nLoaded {len(df):,} records (raw, including oversampled duplicates)")

    # ── Deduplicate BEFORE splitting ───────────────────────────
    # build_training_data.py oversamples minority classes by duplicating records.
    # If we split AFTER, duplicate samples land in both train AND test → data leakage
    # (inflated accuracy, near-zero CV variance, recall=1.00 on minority classes).
    # Fix: deduplicate by cve_id (or description) first, then split.
    before = len(df)
    if "cve_id" in df.columns:
        df = df.drop_duplicates(subset=["cve_id"])
    else:
        df = df.drop_duplicates(subset=["description"])
    removed = before - len(df)
    if removed:
        print(f"  Removed {removed:,} duplicate records (oversampling artifacts)")

    print(f"  Unique records for training: {len(df):,}")

    # Class distribution (natural, after deduplication)
    print("\nClass distribution (natural — after dedup):")
    for label in LABELS:
        n   = (df["severity"] == label).sum()
        pct = n / len(df) * 100
        bar = "█" * int(pct / 2)
        print(f"  {label:10s}: {n:>6,}  ({pct:5.1f}%)  {bar}")

    if len(df) < 100:
        print("\n[WARNING] Very few training samples. Run build_training_data.py to collect more.")

    # ── Features ──────────────────────────────────────────────
    X = build_text_feature(df)
    y = df["severity"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train):,}   Test: {len(X_test):,}")

    # ── Pipeline ──────────────────────────────────────────────
    clf = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=50_000,
            ngram_range=(1, 2),       # unigrams + bigrams
            sublinear_tf=True,        # apply 1+log(tf)
            min_df=2,
            analyzer="word",
        )),
        ("lr", LogisticRegression(
            max_iter=1000,
            C=5.0,
            class_weight="balanced",  # compensate for class imbalance
            solver="lbfgs",
            random_state=42,
        )),
    ])

    print("\nTraining TF-IDF + Logistic Regression pipeline...")
    clf.fit(X_train, y_train)

    # ── Evaluate ──────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    acc    = (y_pred == y_test).mean()
    report = classification_report(y_test, y_pred, labels=LABELS, zero_division=0)

    print(f"\nTest accuracy: {acc:.4f}  ({acc*100:.1f}%)")
    print("\nClassification Report:")
    print(report)

    # Cross-validation on full deduplicated dataset
    # Note: CV is stratified on natural (imbalanced) class distribution
    from sklearn.model_selection import StratifiedKFold
    print("Cross-validation (5-fold, stratified, on deduplicated data):")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv  = cross_val_score(clf, X, y, cv=skf, scoring="accuracy", n_jobs=-1)
    print(f"  Mean accuracy: {cv.mean():.4f} ± {cv.std():.4f}")
    print(f"  Per-fold:      {[round(s,4) for s in cv]}")

    # ── Save ──────────────────────────────────────────────────
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"\nModel saved → {MODEL_PATH}")

    report_text = (
        f"CVE Severity Classifier - Training Report\n"
        f"==========================================\n"
        f"Unique records   : {len(df):,}  (after deduplication — no data leakage)\n"
        f"Training samples : {len(X_train):,}\n"
        f"Test samples     : {len(X_test):,}\n"
        f"Test accuracy    : {acc:.4f} ({acc*100:.1f}%)\n"
        f"CV accuracy      : {cv.mean():.4f} ± {cv.std():.4f}  (5-fold stratified)\n\n"
        f"Model: TF-IDF (max_features=50k, ngram=(1,2)) + "
        f"LogisticRegression (C=5, class_weight=balanced)\n\n"
        f"Classification Report:\n{report}\n"
    )
    REPORT_PATH.write_text(report_text, encoding="utf-8")
    print(f"Report saved → {REPORT_PATH}")
    print("\nNext step: python untils/build_cpe_index.py")


if __name__ == "__main__":
    main()
