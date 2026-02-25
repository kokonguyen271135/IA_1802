# untils/build_training_data.py

"""
Build CVE Severity training dataset.

Sources:
  1. Existing NVD cache  (data/cache/nvd/*.json)
  2. NVD API keyword search for common software products

Output: data/training/cve_severity_train.csv
Columns: cve_id, description, cvss_score, severity, vector_string
"""

import csv
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

import requests

ROOT = Path(__file__).parent.parent

# Keywords queried against NVD API to collect training samples
SEARCH_KEYWORDS = [
    "apache", "nginx", "tomcat", "iis",
    "mysql", "postgresql", "mongodb", "redis", "sqlite",
    "openssl", "openssh", "python", "php", "java", "node",
    "linux kernel", "windows", "android",
    "wordpress", "drupal", "joomla",
    "chrome", "firefox", "safari", "edge",
    "cisco ios", "juniper", "vmware",
    "docker", "kubernetes",
    "log4j", "spring", "struts",
    "adobe acrobat", "adobe reader",
    "winrar", "7-zip", "curl",
    "oracle database", "microsoft exchange",
    "zoom", "slack",
]

NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
OUTPUT_FILE = ROOT / "data/training/cve_severity_train.csv"
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ── helpers ──────────────────────────────────────────────────────────────────

def _parse_vuln(vuln: dict) -> dict | None:
    """Extract (cve_id, description, cvss_score, severity, vector_string)."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    # English description
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "").strip()
            break
    if not desc:
        return None

    # CVSS metrics (v3.1 → v3.0 → v2)
    metrics = cve.get("metrics", {})
    score, severity, vector = 0.0, "NONE", ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m  = metrics[key][0]
            cd = m.get("cvssData", {})
            score  = float(cd.get("baseScore", 0))
            vector = cd.get("vectorString", "")
            if key in ("cvssMetricV31", "cvssMetricV30"):
                severity = cd.get("baseSeverity", "NONE").upper()
            else:
                severity = (
                    "HIGH" if score >= 7.0 else
                    "MEDIUM" if score >= 4.0 else
                    "LOW"  if score > 0 else "NONE"
                )
            break

    if severity not in VALID_SEVERITIES:
        return None

    return {
        "cve_id":        cve_id,
        "description":   desc,
        "cvss_score":    score,
        "severity":      severity,
        "vector_string": vector,
    }


def load_from_cache(cache_dir: Path) -> dict:
    """Load CVE records from existing JSON cache files."""
    records: dict[str, dict] = {}
    for f in sorted(cache_dir.glob("*.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
            desc  = (d.get("description") or "").strip()
            sev   = (d.get("severity")    or "").upper()
            score = float(d.get("cvss_score") or 0)
            vec   = d.get("vector_string", "")
            cid   = d.get("cve_id", f.stem)
            if desc and sev in VALID_SEVERITIES:
                records[cid] = {
                    "cve_id": cid, "description": desc,
                    "cvss_score": score, "severity": sev, "vector_string": vec,
                }
        except Exception:
            pass
    print(f"  Cache: {len(records)} valid records")
    return records


def fetch_keyword(keyword: str, api_key: str, max_results: int = 200) -> list:
    """Query NVD API with keywordSearch and return parsed CVE records."""
    delay   = 0.6 if api_key else 6.0
    headers = {"apiKey": api_key} if api_key else {}
    records: list[dict] = []
    start = 0

    while len(records) < max_results:
        params = {
            "keywordSearch":  keyword,
            "resultsPerPage": min(max_results - len(records), 2000),
            "startIndex":     start,
        }
        try:
            time.sleep(delay)
            r = requests.get(NVD_BASE, params=params, headers=headers, timeout=30)
            r.raise_for_status()
            data  = r.json()
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            for v in vulns:
                p = _parse_vuln(v)
                if p:
                    records.append(p)
            start += len(vulns)
            if start >= total:
                break
        except Exception as exc:
            print(f"    Warning ({keyword}): {exc}")
            break

    return records


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("BUILD CVE SEVERITY TRAINING DATASET")
    print("=" * 60)

    api_key = os.getenv("NVD_API_KEY", "0716c34c-ae5d-4cca-a01d-ef86173b304d")

    all_records: dict[str, dict] = {}
    
    # Step 1: existing cache
    cache_dir = ROOT / "data/cache/nvd"
    print(f"\n[1/2] Reading cache ({cache_dir.name})...")
    all_records.update(load_from_cache(cache_dir))

    # Step 2: NVD API keyword search
    print(f"\n[2/2] Querying NVD API ({len(SEARCH_KEYWORDS)} keywords)...")
    for kw in SEARCH_KEYWORDS:
        before   = len(all_records)
        fetched  = fetch_keyword(kw, api_key, max_results=200)
        for r in fetched:
            all_records.setdefault(r["cve_id"], r)
        added = len(all_records) - before
        print(f"  {kw:25s}  +{added:4d}  (total {len(all_records):,})")

    records = list(all_records.values())

    # Summary
    counts = Counter(r["severity"] for r in records)
    print(f"\nDataset summary: {len(records):,} records")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"  {s:10s}: {counts.get(s, 0):>6,}")

    # Save
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    fields = ["cve_id", "description", "cvss_score", "severity", "vector_string"]
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(records)

    print(f"\nSaved -> {OUTPUT_FILE}")
    print("\nNext step: python untils/train_severity_model.py")


if __name__ == "__main__":
    main()
