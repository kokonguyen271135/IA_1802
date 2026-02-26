# backend/contextual_scorer.py

"""
Contextual CVE Relevance Scorer

Given a PE static analysis result (imports, strings, sections, entropy)
and a list of CVEs, computes HOW RELEVANT each CVE is to THIS SPECIFIC FILE.

This is the core AI value: the same CVE can be HIGH relevance for one file
and MINIMAL for another, based on the file's actual capabilities.

NVD cannot do this — it doesn't know which file you're analysing.

Public API
----------
score_cves(pe_analysis: dict, cves: list[dict]) -> list[dict]
    Adds a 'contextual_relevance' field to each CVE and re-sorts
    the list by contextual risk (highest first).

build_file_profile(pe_analysis: dict) -> dict
    Summarise the file's capabilities into a profile used for scoring.
    Exposed so callers can include it in the API response.
"""

import re

# ── CVE description keyword → suspicious API categories ──────────────────────
# Maps what a CVE describes → what PE capabilities would make it exploitable
KEYWORD_CATEGORY_MAP = {
    # Memory / code execution
    "remote code execution":  ["Code Execution", "Process Injection", "Network Communication"],
    "code execution":         ["Code Execution", "Process Injection"],
    "arbitrary code":         ["Code Execution", "Process Injection"],
    "buffer overflow":        ["Process Injection"],
    "heap overflow":          ["Process Injection"],
    "stack overflow":         ["Process Injection"],
    "memory corruption":      ["Process Injection"],
    "use after free":         ["Process Injection"],
    "out-of-bounds write":    ["Process Injection"],
    "out-of-bounds read":     ["Process Injection"],
    "type confusion":         ["Process Injection"],
    # Injection
    "dll injection":          ["Process Injection", "Dynamic Loading"],
    "dll hijacking":          ["Dynamic Loading"],
    "dll side-loading":       ["Dynamic Loading"],
    "process injection":      ["Process Injection"],
    "shellcode":              ["Process Injection", "Code Execution"],
    # Network
    "network":                ["Network Communication"],
    "remote":                 ["Network Communication"],
    "http":                   ["Network Communication"],
    "ftp":                    ["Network Communication"],
    "c2":                     ["Network Communication"],
    "command and control":    ["Network Communication"],
    "backdoor":               ["Network Communication", "Code Execution"],
    # Privilege
    "privilege escalation":   ["Privilege Escalation"],
    "elevation of privilege": ["Privilege Escalation"],
    "token impersonation":    ["Privilege Escalation"],
    # Crypto / ransomware
    "encrypt":                ["Cryptography"],
    "decrypt":                ["Cryptography"],
    "ransomware":             ["Cryptography", "Network Communication"],
    # Keylog / spy
    "keylog":                 ["Keylogging"],
    "credential":             ["Keylogging", "Registry Manipulation"],
    "password":               ["Keylogging"],
    # Registry
    "registry":               ["Registry Manipulation"],
    "persistence":            ["Registry Manipulation", "Service Manipulation"],
    # Service
    "service":                ["Service Manipulation"],
    # Anti-analysis
    "anti-debug":             ["Anti-Debugging"],
    "sandbox":                ["Anti-Debugging"],
    "evasion":                ["Anti-Debugging"],
    # Files / paths
    "path traversal":         [],          # depends on strings
    "directory traversal":    [],
    "arbitrary file":         [],
}

# CVSS attack vector codes → whether the file needs network capability
AV_NETWORK_CODES = {"N"}          # AV:N  requires network reachability
AV_LOCAL_CODES   = {"L", "P"}     # AV:L / AV:P  local / physical

# CWE IDs → categories that are relevant
CWE_CATEGORY_MAP = {
    "CWE-78":  ["Code Execution"],           # OS Command Injection
    "CWE-94":  ["Code Execution"],           # Code Injection
    "CWE-95":  ["Code Execution"],
    "CWE-119": ["Process Injection"],        # Buffer Errors
    "CWE-120": ["Process Injection"],
    "CWE-121": ["Process Injection"],
    "CWE-122": ["Process Injection"],
    "CWE-125": ["Process Injection"],
    "CWE-190": ["Process Injection"],        # Integer Overflow
    "CWE-416": ["Process Injection"],        # Use After Free
    "CWE-269": ["Privilege Escalation"],     # Improper Privilege Management
    "CWE-287": ["Privilege Escalation"],     # Improper Authentication
    "CWE-798": ["Registry Manipulation"],    # Hard-coded credentials
    "CWE-311": ["Cryptography"],             # Missing Encryption
    "CWE-326": ["Cryptography"],
    "CWE-327": ["Cryptography"],
}


# ── Public API ────────────────────────────────────────────────────────────────

def build_file_profile(pe_analysis: dict) -> dict:
    """
    Extract a concise capability profile from PEStaticAnalyzer output.

    Returns
    -------
    {
        present_categories: set[str],   # suspicious import categories found
        has_network:        bool,
        has_execution:      bool,
        has_injection:      bool,
        has_crypto:         bool,
        has_privilege:      bool,
        has_anti_debug:     bool,
        high_entropy:       bool,       # any section > 7.0
        embedded_urls:      int,
        embedded_ips:       int,
        suspicious_cmds:    int,
        risk_score:         int,        # 0-100 from static analyzer
    }
    """
    imports      = pe_analysis.get("imports", {})
    by_cat       = imports.get("by_category", {})
    present_cats = set(by_cat.keys())

    strings       = pe_analysis.get("strings", {})
    sections      = pe_analysis.get("sections", [])
    file_risk     = pe_analysis.get("risk", {})

    return {
        "present_categories": present_cats,
        "has_network":     "Network Communication" in present_cats,
        "has_execution":   "Code Execution" in present_cats,
        "has_injection":   "Process Injection" in present_cats,
        "has_crypto":      "Cryptography" in present_cats,
        "has_privilege":   "Privilege Escalation" in present_cats,
        "has_anti_debug":  "Anti-Debugging" in present_cats,
        "has_keylog":      "Keylogging" in present_cats,
        "has_registry":    "Registry Manipulation" in present_cats,
        "has_service":     "Service Manipulation" in present_cats,
        "has_dynload":     "Dynamic Loading" in present_cats,
        "high_entropy":    any(s.get("high_entropy") for s in sections),
        "embedded_urls":   len(strings.get("URLs", [])),
        "embedded_ips":    len(strings.get("IP Addresses", [])),
        "suspicious_cmds": len(strings.get("Suspicious Commands", [])),
        "risk_score":      file_risk.get("score", 0),
    }


def score_cves(pe_analysis: dict, cves: list) -> list:
    """
    Add 'contextual_relevance' to each CVE and re-sort by contextual risk.

    Each CVE gains:
        contextual_relevance: {
            score:   float,   # 0.0 – 1.0
            label:   str,     # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "MINIMAL"
            reasons: list[str],
        }
    """
    if not cves or not pe_analysis:
        return cves

    profile = build_file_profile(pe_analysis)

    scored = []
    for cve in cves:
        relevance = _score_single_cve(cve, profile)
        cve_copy  = dict(cve)
        cve_copy["contextual_relevance"] = relevance
        scored.append(cve_copy)

    # Sort: contextual score DESC, then CVSS score DESC
    scored.sort(
        key=lambda c: (
            -c["contextual_relevance"]["score"],
            -float(c.get("cvss_score") or 0),
        )
    )
    return scored


# ── Internal scoring ──────────────────────────────────────────────────────────

def _score_single_cve(cve: dict, profile: dict) -> dict:
    """Compute contextual relevance for one CVE against the file profile."""
    reasons: list[str] = []
    score = 0.0                   # accumulate then clamp to [0, 1]

    desc        = (cve.get("description") or "").lower()
    vector_str  = (cve.get("vector_string") or "").upper()
    cvss_score  = float(cve.get("cvss_score") or 0)
    weaknesses  = cve.get("weaknesses", [])   # list of CWE strings

    # ── 1. Base weight from CVSS score ────────────────────────────────────
    # Higher CVSS = higher baseline importance
    base = (cvss_score / 10.0) * 0.25        # max 0.25 contribution
    score += base

    # ── 2. Attack vector alignment ────────────────────────────────────────
    av_match = re.search(r"AV:([A-Z])", vector_str)
    av_code  = av_match.group(1) if av_match else "L"

    if av_code in AV_NETWORK_CODES:
        if profile["has_network"]:
            score += 0.20
            reasons.append("Network attack vector — file has network communication APIs")
        else:
            score -= 0.10          # network CVE but file has no network capability
            reasons.append("Network attack vector but file has no network APIs (lower relevance)")
    elif av_code in AV_LOCAL_CODES:
        score += 0.10              # local execution is always possible
        reasons.append("Local attack vector — applies when file is executed")

    # ── 3. Description keyword → category match ───────────────────────────
    matched_cats: set[str] = set()
    for keyword, cats in KEYWORD_CATEGORY_MAP.items():
        if keyword in desc:
            for cat in cats:
                if cat in profile["present_categories"] and cat not in matched_cats:
                    matched_cats.add(cat)
                    score += 0.15
                    api_count = len(profile.get("present_categories", {}))  # noqa
                    reasons.append(
                        f'CVE involves "{keyword}" — file has {cat} APIs'
                    )

    # ── 4. CWE alignment ─────────────────────────────────────────────────
    for weakness in weaknesses:
        wid = str(weakness).strip()
        if wid in CWE_CATEGORY_MAP:
            for cat in CWE_CATEGORY_MAP[wid]:
                if cat in profile["present_categories"] and cat not in matched_cats:
                    matched_cats.add(cat)
                    score += 0.12
                    reasons.append(f"{wid} weakness matches file's {cat} capability")

    # ── 5. High-entropy bonus (packed/obfuscated file) ────────────────────
    if profile["high_entropy"]:
        score += 0.08
        reasons.append("File has high-entropy sections (possibly packed) — harder to analyse")

    # ── 6. Embedded network indicators ───────────────────────────────────
    if profile["embedded_ips"] > 0 and av_code in AV_NETWORK_CODES:
        score += 0.05
        reasons.append(f"File contains {profile['embedded_ips']} embedded IP address(es)")
    if profile["embedded_urls"] > 0 and av_code in AV_NETWORK_CODES:
        score += 0.05
        reasons.append(f"File contains {profile['embedded_urls']} embedded URL(s)")
    if profile["suspicious_cmds"] > 0:
        score += 0.07
        reasons.append(
            f"File contains {profile['suspicious_cmds']} suspicious command string(s)"
        )

    # ── 7. Anti-debug / evasion bonus ────────────────────────────────────
    if profile["has_anti_debug"] and "evasion" in desc:
        score += 0.06
        reasons.append("File has anti-debugging APIs matching CVE evasion technique")

    # ── 8. File overall risk amplifier ───────────────────────────────────
    # A very suspicious file (risk_score > 50) amplifies all CVE relevance
    file_risk = profile.get("risk_score", 0)
    if file_risk >= 70:
        score *= 1.25
        reasons.append(f"File static risk is CRITICAL ({file_risk}/100) — amplifying CVE relevance")
    elif file_risk >= 40:
        score *= 1.10

    # ── Clamp and label ───────────────────────────────────────────────────
    score = min(max(score, 0.0), 1.0)

    if score >= 0.75:
        label = "CRITICAL"
    elif score >= 0.55:
        label = "HIGH"
    elif score >= 0.35:
        label = "MEDIUM"
    elif score >= 0.15:
        label = "LOW"
    else:
        label = "MINIMAL"

    if not reasons:
        reasons.append("Limited overlap between file capabilities and this CVE type")

    return {
        "score":   round(score, 3),
        "label":   label,
        "reasons": reasons[:5],          # top 5 reasons
    }
