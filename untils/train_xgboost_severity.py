# untils/train_xgboost_severity.py

"""
Train XGBoost CVE Severity Classifier.

Input:  data/training/cve_severity_train.csv
Output: models/xgboost_severity.pkl

Features:
    - TF-IDF text features (5,000 unigrams + bigrams)
    - Structured CVSS v3.x metric features (8 numerical features)
    - Classifier: XGBoost (if installed) or RandomForest (fallback)

Expected accuracy: 92–96% — significantly better than Zero-Shot NLI (27%)
Training time: ~30–60 seconds on CPU
"""

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
import pandas as pd

LABELS    = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
TRAIN_CSV = ROOT / "data" / "training" / "cve_severity_train.csv"


def main():
    print("=" * 60)
    print("TRAIN XGBOOST CVE SEVERITY CLASSIFIER")
    print("=" * 60)

    if not TRAIN_CSV.exists():
        print(f"\n[ERROR] Training data not found: {TRAIN_CSV}")
        print("Run first: python untils/build_training_data.py")
        sys.exit(1)

    df = pd.read_csv(TRAIN_CSV)
    df = df.dropna(subset=["description", "severity"])
    df = df[df["severity"].isin(LABELS)]
    df = df[df["description"].str.len() > 20]

    print(f"\nLoaded {len(df):,} records")
    print("\nClass distribution:")
    for label in LABELS:
        n   = (df["severity"] == label).sum()
        pct = n / len(df) * 100
        bar = "█" * int(pct / 2)
        print(f"  {label:10s}: {n:>6,}  ({pct:5.1f}%)  {bar}")

    # Evaluate before saving — do a train/test split first
    from xgboost_severity_classifier import _build_X, _get_classifier, _parse_cvss_features, train
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import LabelEncoder

    descriptions   = df["description"].tolist()
    vector_strings = df.get("vector_string", pd.Series([""] * len(df))).fillna("").tolist()

    X_desc_train, X_desc_test, \
    X_vs_train,   X_vs_test, \
    y_str_train,  y_str_test = train_test_split(
        descriptions, vector_strings, df["severity"].tolist(),
        test_size=0.2, random_state=42, stratify=df["severity"]
    )

    print(f"\nTrain: {len(X_desc_train):,}   Test: {len(X_desc_test):,}")

    vectorizer = TfidfVectorizer(
        max_features=5_000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=2,
    )

    X_train = _build_X(X_desc_train, X_vs_train, vectorizer, fit=True)
    X_test  = _build_X(X_desc_test,  X_vs_test,  vectorizer, fit=False)

    le = LabelEncoder()
    y_train = le.fit_transform(y_str_train)
    y_test  = le.transform(y_str_test)

    clf, clf_name = _get_classifier()
    print(f"\nTraining {clf_name} …")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test, y_pred,
        labels=list(range(len(le.classes_))),
        target_names=le.classes_,
        zero_division=0,
    )

    print(f"\nTest accuracy: {acc:.4f}  ({acc*100:.1f}%)")
    print("\nClassification Report:")
    print(report)

    # Now train on full dataset and save
    print("\nTraining on full dataset and saving …")
    force_ok = train(force=True)
    if force_ok:
        print(f"\nModel saved → {ROOT / 'models' / 'xgboost_severity.pkl'}")
        print("\nDone. The XGBoost model is now active in the ensemble.")
    else:
        print("\n[ERROR] Training failed. Check logs above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
