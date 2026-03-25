# backend/ml_classifier.py

"""
XGBoost-based PE Malware Classifier

Converts PE static analysis output into a fixed-dimension feature vector,
then uses a trained XGBoost model to predict P(malicious).

Feature vector is derived entirely from PEStaticAnalyzer output — no raw
bytes, no API calls, no internet. Fully offline.

Outputs:
  - probability: float [0, 1]  (probability of being malicious)
  - verdict: CLEAN / SUSPICIOUS / MALICIOUS
  - top_features: which features contributed most (XGBoost SHAP-style)
  - feature_vector: dict of all extracted features (for transparency)
"""

import os
import pickle
import math
from datetime import datetime, timezone
from pathlib import Path

MODEL_PATH = Path(__file__).parent / "ml_model.pkl"

# ─── Feature names (must match train_model.py EXACTLY) ───────────────────────
FEATURE_NAMES = [
    # ── File / PE header ──────────────────────────────────────────────────
    "file_size_kb",          # file size in KB
    "is_dll",                # 1 if DLL
    "is_64bit",              # 1 if x64
    "binary_age_days",       # days since compilation timestamp (0 if unknown)
    "has_valid_timestamp",   # 1 if timestamp looks real (not 0, not far future)
    # ── Sections ─────────────────────────────────────────────────────────
    "section_count",         # number of PE sections
    "mean_entropy",          # mean entropy across all sections
    "max_entropy",           # max entropy (packing / encryption indicator)
    "high_entropy_sections", # count of sections with entropy > 7.0
    "exec_sections",         # count of executable sections
    "writable_exec_sections",# count of W+X sections (exploit-friendly)
    "has_suspicious_section_names", # UPX0, .rsrc with high entropy, etc.
    # ── Imports ───────────────────────────────────────────────────────────
    "import_count",          # total number of imported functions
    "dll_import_count",      # number of DLLs imported
    # suspicious API category flags (1 if ANY api in that category is present)
    "has_process_injection", # VirtualAllocEx, WriteProcessMemory, etc.
    "has_network",           # Winsock, WinInet, WinHTTP
    "has_keylogging",        # GetAsyncKeyState, SetWindowsHookEx
    "has_persistence",       # RegSetValue, CreateService, schtasks
    "has_privilege_escalation",# AdjustTokenPrivileges, etc.
    "has_anti_analysis",     # IsDebuggerPresent, CheckRemoteDebuggerPresent
    "has_shellcode",         # VirtualAlloc + CreateThread pattern
    "has_file_ops",          # file read/write operations
    "has_crypto",            # CryptEncrypt, BCryptEncrypt
    "has_execution",         # ShellExecute, WinExec, CreateProcess
    "suspicious_category_count", # total distinct suspicious categories
    # ── Exports ───────────────────────────────────────────────────────────
    "export_count",          # number of exported functions
    # ── Strings ───────────────────────────────────────────────────────────
    "url_count",             # embedded URLs
    "ip_count",              # embedded IP addresses
    "suspicious_cmd_count",  # cmd.exe /c, powershell, etc.
    "registry_key_count",    # embedded registry key paths
    "has_base64_strings",    # long base64-looking strings
    # ── Security mitigations (absence = higher risk) ──────────────────────
    "has_aslr",              # /DYNAMICBASE
    "has_dep",               # /NXCOMPAT
    "has_gs",                # /GS stack canary
    "has_cfg",               # Control Flow Guard
    "has_seh",               # Safe SEH
    "has_authenticode",      # signed binary
    "mitigation_score",      # sum of 6 mitigation flags (0-6)
    # ── Composite risk signals ────────────────────────────────────────────
    "network_plus_injection",# has both network AND process injection (C2 pattern)
    "high_entropy_no_mitigations", # packed/obfuscated AND no security flags
    "many_suspicious_few_imports", # suspicious categories >> actual imports
]

SUSPICIOUS_SECTION_NAMES = {
    'upx0', 'upx1', 'upx2', '.aspack', '.adata', '.boot',
    '.ccg', 'nspack', 'pec2', '.petite',
}


# ─── Feature Extraction ──────────────────────────────────────────────────────

def extract_features(static_result: dict) -> dict:
    """
    Convert PEStaticAnalyzer output → fixed-dimension feature dict.

    All values are numeric (int or float). Missing data defaults to 0.
    """
    fv = {name: 0.0 for name in FEATURE_NAMES}

    # ── File info ────────────────────────────────────────────────────────
    fi = static_result.get("file_info") or {}
    fv["file_size_kb"] = (fi.get("size") or 0) / 1024.0

    # ── PE header ────────────────────────────────────────────────────────
    pe = static_result.get("pe_info") or {}
    fv["is_dll"]   = 1.0 if pe.get("characteristics_flags", {}).get("IS_DLL") else 0.0
    fv["is_64bit"] = 1.0 if pe.get("machine") in ("AMD64", "x64", "IA64") else 0.0

    ts = pe.get("compilation_timestamp")
    if ts:
        try:
            ts_val = int(ts) if isinstance(ts, (int, float)) else 0
            if 0 < ts_val < 2_000_000_000:
                fv["has_valid_timestamp"] = 1.0
                dt = datetime.fromtimestamp(ts_val, tz=timezone.utc)
                fv["binary_age_days"] = max(
                    0.0, (datetime.now(tz=timezone.utc) - dt).days
                )
        except Exception:
            pass

    # ── Sections ─────────────────────────────────────────────────────────
    sections = static_result.get("sections") or []
    fv["section_count"] = len(sections)

    entropies = []
    for sec in sections:
        ent = sec.get("entropy") or 0.0
        entropies.append(ent)
        chars = sec.get("characteristics") or 0
        is_exec     = bool(chars & 0x20000000)
        is_writable = bool(chars & 0x80000000)
        if is_exec:
            fv["exec_sections"] += 1
        if is_exec and is_writable:
            fv["writable_exec_sections"] += 1
        if ent > 7.0:
            fv["high_entropy_sections"] += 1
        name = (sec.get("name") or "").strip().lower().rstrip('\x00')
        if name in SUSPICIOUS_SECTION_NAMES:
            fv["has_suspicious_section_names"] = 1.0

    if entropies:
        fv["mean_entropy"] = sum(entropies) / len(entropies)
        fv["max_entropy"]  = max(entropies)

    # ── Imports ───────────────────────────────────────────────────────────
    imp = static_result.get("imports") or {}
    fv["import_count"]    = imp.get("count") or 0
    fv["dll_import_count"] = len(imp.get("all") or {})

    by_cat = imp.get("by_category") or {}
    CATEGORY_MAP = {
        "Process Injection":     "has_process_injection",
        "Network Activity":      "has_network",
        "Keylogging":            "has_keylogging",
        "Persistence":           "has_persistence",
        "Privilege Escalation":  "has_privilege_escalation",
        "Anti-Analysis":         "has_anti_analysis",
        "Shellcode Execution":   "has_shellcode",
        "File Operations":       "has_file_ops",
        "Cryptographic":         "has_crypto",
        "Process Execution":     "has_execution",
    }
    cat_count = 0
    for cat, feat in CATEGORY_MAP.items():
        if by_cat.get(cat):
            fv[feat]  = 1.0
            cat_count += 1
    fv["suspicious_category_count"] = cat_count

    # ── Exports ───────────────────────────────────────────────────────────
    exp = static_result.get("exports") or {}
    fv["export_count"] = exp.get("count") or 0

    # ── Strings ───────────────────────────────────────────────────────────
    strs = static_result.get("strings") or {}
    fv["url_count"]          = len(strs.get("URLs") or [])
    fv["ip_count"]           = len(strs.get("IP Addresses") or [])
    fv["suspicious_cmd_count"] = len(strs.get("Suspicious Commands") or [])
    fv["registry_key_count"] = len(strs.get("Registry Keys") or [])

    # Check for long base64-looking strings (>40 chars, alphanum only)
    import re
    all_str_lists = list(strs.values())
    b64_re = re.compile(r'^[A-Za-z0-9+/=]{40,}$')
    for lst in all_str_lists:
        for s in (lst or []):
            if isinstance(s, str) and b64_re.match(s):
                fv["has_base64_strings"] = 1.0
                break

    # ── Security mitigations ──────────────────────────────────────────────
    mit = static_result.get("security_mitigations") or {}
    mit_flags = {
        "has_aslr":         mit.get("aslr")          or mit.get("ASLR"),
        "has_dep":          mit.get("dep")           or mit.get("DEP") or mit.get("nx"),
        "has_gs":           mit.get("gs")            or mit.get("GS") or mit.get("stack_canary"),
        "has_cfg":          mit.get("cfg")           or mit.get("CFG"),
        "has_seh":          mit.get("seh")           or mit.get("SEH") or mit.get("safe_seh"),
        "has_authenticode": mit.get("authenticode")  or mit.get("signed"),
    }
    score = 0
    for feat, val in mit_flags.items():
        if val:
            fv[feat] = 1.0
            score += 1
    fv["mitigation_score"] = float(score)

    # ── Composite signals ─────────────────────────────────────────────────
    fv["network_plus_injection"] = (
        1.0 if fv["has_network"] and fv["has_process_injection"] else 0.0
    )
    fv["high_entropy_no_mitigations"] = (
        1.0 if fv["max_entropy"] > 7.0 and fv["mitigation_score"] == 0 else 0.0
    )
    imp_c = max(1, fv["import_count"])
    fv["many_suspicious_few_imports"] = (
        1.0 if fv["suspicious_category_count"] >= 3 and imp_c < 20 else 0.0
    )

    return fv


def features_to_vector(fv: dict) -> list:
    """Return feature values in canonical FEATURE_NAMES order."""
    return [fv.get(n, 0.0) for n in FEATURE_NAMES]


# ─── Classifier ──────────────────────────────────────────────────────────────

class PEMalwareClassifier:
    """
    Wraps a trained XGBoost model for PE malware classification.

    Usage:
        clf = PEMalwareClassifier()
        if clf.is_loaded():
            result = clf.predict(static_result)
    """

    VERDICT_THRESHOLDS = {
        "MALICIOUS":  0.70,
        "SUSPICIOUS": 0.40,
        "CLEAN":      0.0,
    }

    def __init__(self):
        self._model   = None
        self._meta    = {}
        self._loaded  = False
        self._load_error = ""
        self._try_load()

    def _try_load(self):
        if not MODEL_PATH.exists():
            self._load_error = f"Model file not found: {MODEL_PATH}"
            return
        try:
            with open(MODEL_PATH, "rb") as f:
                bundle = pickle.load(f)
            self._model  = bundle["model"]
            self._meta   = bundle.get("meta", {})
            self._loaded = True
            print(f"[ML] XGBoost model loaded — trained on {self._meta.get('train_samples','?')} samples, "
                  f"val_auc={self._meta.get('val_auc','?'):.3f}" if isinstance(self._meta.get('val_auc'), float)
                  else f"[ML] XGBoost model loaded ({self._meta.get('train_samples','?')} samples)")
        except Exception as exc:
            self._load_error = str(exc)

    def is_loaded(self) -> bool:
        return self._loaded

    def predict(self, static_result: dict) -> dict:
        """
        Run XGBoost prediction on a static analysis result.

        Returns:
          {
            "success": bool,
            "probability": float,        # P(malicious) in [0, 1]
            "verdict": str,              # CLEAN / SUSPICIOUS / MALICIOUS
            "top_features": [            # most contributing features
                {"feature": str, "value": float, "importance": float}, ...
            ],
            "feature_vector": dict,      # all extracted features (transparent)
            "model_info": dict,          # training metadata
          }
        """
        if not self._loaded:
            return {"success": False, "error": self._load_error}

        try:
            import numpy as np

            fv  = extract_features(static_result)
            vec = features_to_vector(fv)
            X   = np.array([vec], dtype=np.float32)

            prob = float(self._model.predict_proba(X)[0][1])

            # Verdict
            if prob >= self.VERDICT_THRESHOLDS["MALICIOUS"]:
                verdict = "MALICIOUS"
            elif prob >= self.VERDICT_THRESHOLDS["SUSPICIOUS"]:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"

            # Top contributing features using XGBoost feature importances
            importances = self._model.feature_importances_   # shape: (n_features,)
            scored = sorted(
                zip(FEATURE_NAMES, vec, importances),
                key=lambda x: x[2],
                reverse=True,
            )
            top_features = [
                {"feature": name, "value": round(val, 4), "importance": round(imp, 4)}
                for name, val, imp in scored[:8]
                if imp > 0
            ]

            return {
                "success":      True,
                "probability":  round(prob, 4),
                "verdict":      verdict,
                "top_features": top_features,
                "feature_vector": {k: round(v, 4) for k, v in fv.items()},
                "model_info":   self._meta,
            }

        except Exception as exc:
            return {"success": False, "error": str(exc)}


# Module-level singleton
_clf_instance = None

def get_classifier() -> PEMalwareClassifier:
    global _clf_instance
    if _clf_instance is None:
        _clf_instance = PEMalwareClassifier()
    return _clf_instance
