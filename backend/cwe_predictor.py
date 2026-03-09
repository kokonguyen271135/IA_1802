# backend/cwe_predictor.py

"""
Hướng 3 — CWE Prediction từ PE Static Features
================================================

Vấn đề giải quyết
-----------------
Khi phân tích một file PE (exe/dll) mà **không xác định được CPE** (không biết
phần mềm đó là gì), hệ thống sẽ không có gì để tra NVD theo CPE.

Hướng 3 giải quyết bằng cách:
  1. Nhìn vào *hành vi* của file (import APIs, section entropy, strings)
  2. Ánh xạ hành vi → CWE categories (Common Weakness Enumeration)
  3. Tra NVD API theo CWE → lấy các CVE liên quan đến loại lỗ hổng đó
  4. Trả về danh sách CVE có thể áp dụng cho file này

Ví dụ minh họa
--------------
  File PE có:
    - VirtualAllocEx, WriteProcessMemory, CreateRemoteThread  → Process Injection
    - ShellExecute, CreateProcess                              → Code Execution
    - Entropy section = 7.8                                    → Packed/Encrypted
  ↓
  Predicted CWEs:
    - CWE-94  (Code Injection)           confidence=0.95
    - CWE-78  (OS Command Injection)     confidence=0.85
    - CWE-506 (Embedded Malicious Code)  confidence=0.75
  ↓
  Query NVD: ?cweId=CWE-94 → 50 CVEs, ?cweId=CWE-78 → 50 CVEs
  ↓
  Trả về top CVEs phù hợp nhất với hành vi file

Cách dùng
---------
    from cwe_predictor import CWEPredictor
    predictor = CWEPredictor(nvd_api)
    result = predictor.predict_and_fetch(pe_analysis)
    # result = {
    #   'predicted_cwes': [...],
    #   'cve_results': [...],
    #   'method': 'cwe_behavior_prediction',
    # }
"""

from __future__ import annotations

# ── CWE catalog ───────────────────────────────────────────────────────────────
# id → (name, short_description, severity_weight)
CWE_CATALOG: dict[str, tuple[str, str, float]] = {
    "CWE-78":  (
        "OS Command Injection",
        "The software constructs an OS command using externally-influenced input "
        "that has not been properly neutralized.",
        0.95,
    ),
    "CWE-77":  (
        "Command Injection",
        "The software constructs a command using externally-influenced input "
        "without proper neutralization.",
        0.90,
    ),
    "CWE-94":  (
        "Code Injection",
        "The software allows an attacker to inject code that is then executed, "
        "changing the course of execution.",
        0.95,
    ),
    "CWE-269": (
        "Improper Privilege Management",
        "The software does not properly assign, modify, track, or check "
        "privileges for an actor.",
        0.85,
    ),
    "CWE-264": (
        "Permissions, Privileges, and Access Controls",
        "Weaknesses in this category are related to the management of "
        "permissions, privileges, and access controls.",
        0.80,
    ),
    "CWE-200": (
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "The product exposes sensitive information to an actor that is not "
        "explicitly authorized to have access.",
        0.75,
    ),
    "CWE-319": (
        "Cleartext Transmission of Sensitive Information",
        "The software transmits sensitive or security-critical data in cleartext "
        "in a communication channel.",
        0.70,
    ),
    "CWE-918": (
        "Server-Side Request Forgery (SSRF)",
        "The server receives a URL from an upstream component and retrieves the "
        "contents without verifying the URL points to a valid destination.",
        0.80,
    ),
    "CWE-311": (
        "Missing Encryption of Sensitive Data",
        "The software does not encrypt sensitive or critical data.",
        0.65,
    ),
    "CWE-327": (
        "Use of a Broken or Risky Cryptographic Algorithm",
        "The use of a broken or risky cryptographic algorithm introduces "
        "weaknesses into the software.",
        0.70,
    ),
    "CWE-506": (
        "Embedded Malicious Code",
        "The software contains code that appears to be malicious in nature, "
        "such as a Trojan horse.",
        1.00,
    ),
    "CWE-732": (
        "Incorrect Permission Assignment for Critical Resource",
        "The software specifies permissions for a security-critical resource "
        "in a way that allows that resource to be read or modified by unintended actors.",
        0.75,
    ),
    "CWE-284": (
        "Improper Access Control",
        "The software does not restrict or incorrectly restricts access to "
        "a resource from an unauthorized actor.",
        0.80,
    ),
    "CWE-426": (
        "Untrusted Search Path",
        "The application searches for critical resources using an externally-supplied "
        "search path that can point to resources that are not under the application's control.",
        0.65,
    ),
    "CWE-494": (
        "Download of Code Without Integrity Check",
        "The product downloads source code or an executable from a remote location "
        "and executes the code without sufficiently verifying the origin and integrity.",
        0.80,
    ),
    "CWE-693": (
        "Protection Mechanism Failure",
        "The product does not use or incorrectly uses a protection mechanism "
        "that provides sufficient defense against directed attacks against the product.",
        0.60,
    ),
    "CWE-119": (
        "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "The software performs operations on a memory buffer, but it can read "
        "from or write to a memory location that is outside of the intended boundary.",
        0.90,
    ),
    "CWE-362": (
        "Concurrent Execution using Shared Resource with Improper Synchronization",
        "The program contains a code sequence that can run concurrently with other "
        "code, and the code sequence requires temporary, exclusive access to a shared resource.",
        0.70,
    ),
}


# ── Behavioral API category → CWE mappings ────────────────────────────────────
# Each entry: (cwe_id, base_confidence)
# Confidence is scaled further by number of matching APIs found
BEHAVIOR_TO_CWE: dict[str, list[tuple[str, float]]] = {
    "Process Injection": [
        ("CWE-94",  0.95),
        ("CWE-78",  0.80),
        ("CWE-269", 0.70),
        ("CWE-506", 0.60),
    ],
    "Anti-Debugging": [
        ("CWE-693", 0.80),
        ("CWE-200", 0.50),
    ],
    "Network Communication": [
        ("CWE-319", 0.70),
        ("CWE-918", 0.65),
        ("CWE-200", 0.55),
        ("CWE-494", 0.50),
    ],
    "Code Execution": [
        ("CWE-78",  0.95),
        ("CWE-77",  0.90),
        ("CWE-94",  0.85),
    ],
    "Keylogging": [
        ("CWE-200", 0.90),
        ("CWE-311", 0.60),
    ],
    "Registry Manipulation": [
        ("CWE-732", 0.80),
        ("CWE-269", 0.65),
        ("CWE-284", 0.55),
    ],
    "Cryptography": [
        ("CWE-327", 0.70),
        ("CWE-311", 0.65),
        ("CWE-506", 0.55),   # ransomware pattern
    ],
    "Privilege Escalation": [
        ("CWE-269", 0.95),
        ("CWE-264", 0.85),
        ("CWE-284", 0.70),
    ],
    "Service Manipulation": [
        ("CWE-284", 0.80),
        ("CWE-269", 0.70),
        ("CWE-732", 0.60),
    ],
    "Dynamic Loading": [
        ("CWE-426", 0.85),
        ("CWE-494", 0.70),
        ("CWE-94",  0.55),
    ],
}

# String pattern category → CWE hints
STRING_TO_CWE: dict[str, list[tuple[str, float]]] = {
    "Suspicious Commands": [
        ("CWE-78", 0.85),
        ("CWE-77", 0.80),
    ],
    "IP Addresses": [
        ("CWE-918", 0.60),
        ("CWE-200", 0.50),
    ],
    "URLs": [
        ("CWE-494", 0.55),
        ("CWE-918", 0.50),
        ("CWE-319", 0.45),
    ],
    "Potential Base64": [
        ("CWE-506", 0.60),
        ("CWE-94",  0.50),
    ],
}


# ── Core prediction function ──────────────────────────────────────────────────

def predict_cwe(analysis: dict, top_k: int = 5) -> list[dict]:
    """
    Predict probable CWE categories from PE static analysis output.

    Parameters
    ----------
    analysis : dict
        Full output of PEStaticAnalyzer.analyze() — contains imports,
        sections, strings, pe_info, risk fields.
    top_k : int
        Maximum number of CWE predictions to return.

    Returns
    -------
    list of dicts sorted by confidence DESC:
        [{
            'cwe_id':      str,   # e.g. "CWE-94"
            'name':        str,   # e.g. "Code Injection"
            'description': str,   # short human-readable description
            'confidence':  float, # 0.0–1.0
            'label':       str,   # "HIGH" / "MEDIUM" / "LOW"
            'triggered_by': [str] # what triggered this prediction
        }]
    """
    scores: dict[str, float]       = {}  # cwe_id → max accumulated confidence
    triggered: dict[str, list[str]] = {}

    def _add(cwe_id: str, conf: float, reason: str) -> None:
        scores[cwe_id] = max(scores.get(cwe_id, 0.0), conf)
        triggered.setdefault(cwe_id, []).append(reason)

    # ── 1. Import behavior categories ─────────────────────────────────────────
    by_category = analysis.get("imports", {}).get("by_category", {})
    for cat, entries in by_category.items():
        if not entries:
            continue
        mappings = BEHAVIOR_TO_CWE.get(cat, [])
        # More APIs in this category → slightly higher confidence (caps at 1.0)
        scale = min(1.0, 0.70 + len(entries) * 0.04)
        for cwe_id, base_conf in mappings:
            _add(cwe_id, min(1.0, base_conf * scale),
                 f"API category '{cat}' ({len(entries)} function(s) matched)")

    # ── 2. String patterns ────────────────────────────────────────────────────
    strings = analysis.get("strings", {})
    for str_cat, cwe_list in STRING_TO_CWE.items():
        if strings.get(str_cat):
            count = len(strings[str_cat])
            for cwe_id, base_conf in cwe_list:
                # More occurrences → slightly more confident
                conf = min(1.0, base_conf + min(count - 1, 5) * 0.02)
                _add(cwe_id, conf,
                     f"String pattern '{str_cat}' ({count} occurrence(s))")

    # ── 3. High-entropy sections → packing / embedded malicious code ──────────
    high_entropy = [s for s in analysis.get("sections", []) if s.get("high_entropy")]
    if high_entropy:
        n    = len(high_entropy)
        conf = min(0.95, 0.60 + n * 0.10)
        _add("CWE-506", conf,
             f"{n} high-entropy section(s) found — possible packing or encryption")

    # ── 4. PE characteristics ─────────────────────────────────────────────────
    pe_info = analysis.get("pe_info") or {}
    if pe_info.get("has_tls"):
        _add("CWE-693", 0.55,
             "TLS callbacks present — possible anti-debug / code execution hooking")

    # ── 5. Risk score bonus ───────────────────────────────────────────────────
    risk = analysis.get("risk", {})
    risk_level = risk.get("level", "CLEAN")
    if risk_level == "CRITICAL" and scores:
        # Boost all scores slightly for high-risk files
        for cwe_id in list(scores):
            scores[cwe_id] = min(1.0, scores[cwe_id] * 1.10)

    # ── 6. Build result ───────────────────────────────────────────────────────
    results = []
    for cwe_id, conf in sorted(scores.items(), key=lambda x: -x[1])[:top_k]:
        meta = CWE_CATALOG.get(cwe_id)
        results.append({
            "cwe_id":       cwe_id,
            "name":         meta[0] if meta else cwe_id,
            "description":  meta[1] if meta else "",
            "confidence":   round(conf, 3),
            "label":        _conf_label(conf),
            "triggered_by": triggered.get(cwe_id, []),
        })

    return results


def _conf_label(conf: float) -> str:
    if conf >= 0.80:
        return "HIGH"
    if conf >= 0.55:
        return "MEDIUM"
    return "LOW"


# ── CWEPredictor class — wraps prediction + NVD lookup ───────────────────────

class CWEPredictor:
    """
    Hướng 3 core class: predict CWE from PE features, then fetch CVEs.

    Hoạt động như fallback khi:
      - Không xác định được CPE của file
      - CPE có nhưng NVD trả về 0 CVE (file quá obscure)

    Ví dụ dùng trong app.py::

        predictor = CWEPredictor(nvd_api)
        if not cves:
            result['cwe_analysis'] = predictor.predict_and_fetch(pe_analysis)
    """

    def __init__(self, nvd_api, max_cves_per_cwe: int = 20, top_cwes: int = 3):
        """
        Parameters
        ----------
        nvd_api           : NVDAPIv2 instance
        max_cves_per_cwe  : max CVEs fetched per CWE query
        top_cwes          : how many top CWEs to query NVD for
        """
        self.nvd_api          = nvd_api
        self.max_cves_per_cwe = max_cves_per_cwe
        self.top_cwes         = top_cwes

    def predict_and_fetch(self, analysis: dict) -> dict:
        """
        Main Hướng 3 entry point.

        Parameters
        ----------
        analysis : dict
            Output of PEStaticAnalyzer.analyze()

        Returns
        -------
        {
            'predicted_cwes': list,    # ranked CWE predictions
            'cve_results':    list,    # CVEs from NVD matching those CWEs
            'total_cves':     int,
            'method':         str,     # always 'cwe_behavior_prediction'
            'summary':        str,     # human-readable explanation
        }
        """
        print("[CWE] Running CWE behavior prediction (Hướng 3) …")

        # Step 1: Predict CWEs from static features
        predicted = predict_cwe(analysis, top_k=self.top_cwes + 2)

        if not predicted:
            return {
                "predicted_cwes": [],
                "cve_results":    [],
                "total_cves":     0,
                "method":         "cwe_behavior_prediction",
                "summary":        "No behavioral indicators detected — cannot predict CWE.",
            }

        # Log predictions
        print(f"[CWE] Predicted {len(predicted)} CWE(s):")
        for p in predicted:
            print(f"      {p['cwe_id']} ({p['label']}, conf={p['confidence']:.2f}): {p['name']}")

        # Step 2: Query NVD for top-K CWEs
        all_cves: list[dict] = []
        seen_ids: set[str]   = set()

        for pred in predicted[:self.top_cwes]:
            cwe_id = pred["cwe_id"]
            print(f"[CWE] Querying NVD for {cwe_id} …")
            cves = self.nvd_api.search_by_cwe(cwe_id,
                                               max_results=self.max_cves_per_cwe)
            for cve in cves:
                cid = cve.get("cve_id", "")
                if cid and cid not in seen_ids:
                    seen_ids.add(cid)
                    cve["matched_cwe"]             = cwe_id
                    cve["matched_cwe_name"]        = pred["name"]
                    cve["matched_cwe_confidence"]  = pred["confidence"]
                    all_cves.append(cve)

        # Step 3: Sort — first by CWE confidence, then by CVSS score
        all_cves.sort(
            key=lambda c: (
                c.get("matched_cwe_confidence", 0),
                c.get("cvss_score", 0),
            ),
            reverse=True,
        )

        # Step 4: Build human-readable summary
        top_cwe_names = ", ".join(
            f"{p['cwe_id']} ({p['name']})" for p in predicted[:3]
        )
        risk_level = analysis.get("risk", {}).get("level", "UNKNOWN")
        summary = (
            f"No CPE identified. Based on behavioral analysis (risk level: {risk_level}), "
            f"this binary exhibits characteristics associated with: {top_cwe_names}. "
            f"Showing {len(all_cves)} CVEs matching these weakness categories."
        )

        print(f"[CWE] Done — {len(all_cves)} unique CVEs from {len(predicted[:self.top_cwes])} CWE queries")

        return {
            "predicted_cwes": predicted,
            "cve_results":    all_cves[:50],
            "total_cves":     len(all_cves),
            "method":         "cwe_behavior_prediction",
            "summary":        summary,
        }
