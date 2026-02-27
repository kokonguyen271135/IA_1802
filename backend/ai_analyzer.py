# backend/ai_analyzer.py

"""
AI-powered analysis module using Claude API.

Two capabilities:
  1. AI CPE Matching   - Maps software metadata → NVD CPE vendor/product
                         (used when standard pattern matching is uncertain)
  2. AI Severity Context - Provides a contextual risk narrative for discovered CVEs
"""

import json
import os
import re

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

# ─── Model selection ────────────────────────────────────────────────────────
CPE_MODEL      = "claude-haiku-4-5-20251001"   # fast + cheap for CPE lookup
SEVERITY_MODEL = "claude-sonnet-4-6"            # stronger reasoning for risk analysis


# ─── Helpers ────────────────────────────────────────────────────────────────

def is_available() -> bool:
    """Return True if the anthropic package is installed and an API key is set."""
    return ANTHROPIC_AVAILABLE and bool(os.getenv("ANTHROPIC_API_KEY"))


def _client():
    if not ANTHROPIC_AVAILABLE:
        raise ImportError(
            "anthropic package not installed. Run: pip install anthropic>=0.40.0"
        )
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY environment variable is not set."
        )
    return anthropic.Anthropic(api_key=api_key)


def _extract_json(text: str) -> dict | None:
    """Extract the first JSON object from a Claude response string."""
    match = re.search(r"\{[\s\S]+\}", text)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            return None
    return None


# ─── 1. AI CPE Matching ─────────────────────────────────────────────────────

def ai_match_cpe(
    product_name: str,
    company_name: str,
    filename: str,
    version: str = "",
) -> dict:
    """
    Use Claude to identify the NVD CPE vendor/product for a given executable.

    Called when the rule-based extractor falls back to a generic match
    (extraction_method in ['generic_fallback', 'filename_pattern']).

    Returns:
        {
            "success": bool,
            "vendor": str,          # NVD CPE vendor id  (e.g. "rarlab")
            "product": str,         # NVD CPE product id (e.g. "winrar")
            "confidence": str,      # "high" | "medium" | "low"
            "reasoning": str,       # one-sentence explanation
        }
        or {"success": False, "error": str}
    """
    if not is_available():
        return {"success": False, "error": "AI not available (missing package or API key)"}

    if not any([product_name, company_name, filename]):
        return {"success": False, "error": "No software information provided"}

    prompt = f"""You are a cybersecurity expert specializing in NVD CPE (Common Platform Enumeration) identification.

Software information extracted from a Windows executable:
- Product Name : {product_name or "(not available)"}
- Company/Vendor: {company_name or "(not available)"}
- Filename      : {filename or "(not available)"}
- Version       : {version or "(not available)"}

Task: Identify the correct NVD CPE vendor and product identifiers so we can look up CVEs.

CPE identifiers are lowercase with underscores replacing spaces:
  WinRAR / RarLab              → vendor: "rarlab",     product: "winrar"
  Apache HTTP Server           → vendor: "apache",     product: "http_server"
  OpenSSL                      → vendor: "openssl",    product: "openssl"
  Microsoft Windows 10         → vendor: "microsoft",  product: "windows_10"
  7-Zip / Igor Pavlov          → vendor: "7-zip",      product: "7-zip"
  Oracle Java / JRE            → vendor: "oracle",     product: "jre"
  Python Software Foundation   → vendor: "python",     product: "python"
  Node.js Foundation           → vendor: "nodejs",     product: "node.js"
  nginx                        → vendor: "nginx",      product: "nginx"
  MySQL                        → vendor: "mysql",      product: "mysql"

Respond with ONLY valid JSON (no markdown fences, no extra text):
{{
  "vendor": "nvd_vendor_id",
  "product": "nvd_product_id",
  "confidence": "high|medium|low",
  "reasoning": "one sentence"
}}"""

    try:
        msg = _client().messages.create(
            model=CPE_MODEL,
            max_tokens=256,
            messages=[{"role": "user", "content": prompt}],
        )
        result = _extract_json(msg.content[0].text.strip())
        if result:
            result["success"] = True
            return result
        return {"success": False, "error": "Could not parse AI response"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ─── 2. AI Severity Context ──────────────────────────────────────────────────

def ai_analyze_severity(
    software_info: dict,
    cves: list,
    stats: dict,
) -> dict:
    """
    Use Claude to produce a contextual risk narrative for a set of CVEs.

    Args:
        software_info: {"name": ..., "vendor": ..., "product": ..., "version": ...}
        cves:          list of CVE dicts returned by NVDAPIv2
        stats:         {total_cves, by_severity, avg_cvss, max_cvss}

    Returns:
        {
            "success": bool,
            "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
            "risk_summary": str,         # 2-3 sentence human-readable summary
            "top_threats": [str, ...],   # up to 3 specific threat descriptions
            "recommendations": [str, ...],  # up to 3 actionable steps
            "key_attack_vectors": [str, ...],  # e.g. ["Network", "Local"]
            "cves_analyzed": int,
        }
        or {"success": False, "error": str}
    """
    if not is_available():
        return {"success": False, "error": "AI not available (missing package or API key)"}

    if not cves:
        return {"success": False, "error": "No CVEs to analyze"}

    # Send top-10 by CVSS to keep the prompt compact
    top_cves = sorted(cves, key=lambda x: x.get("cvss_score", 0), reverse=True)[:10]
    cve_summary = [
        {
            "id":          c.get("cve_id", ""),
            "score":       c.get("cvss_score", 0),
            "severity":    c.get("severity", "UNKNOWN"),
            "vector":      c.get("vector_string", ""),
            "description": (c.get("description") or "")[:300],
            "weaknesses":  (c.get("weaknesses") or [])[:3],
            "published":   (c.get("published") or "")[:10],
        }
        for c in top_cves
    ]

    sw_name = (
        software_info.get("name")
        or f"{software_info.get('vendor', '')} {software_info.get('product', '')}".strip()
        or "Unknown software"
    )

    prompt = f"""You are a senior cybersecurity analyst. Analyze the vulnerability data below and produce a concise risk assessment.

Software : {sw_name} {software_info.get('version', '')}
Total CVEs: {stats.get('total_cves', len(cves))}
Severity breakdown: {stats.get('by_severity', {})}
CVSS stats: avg={stats.get('avg_cvss', 0):.1f}, max={stats.get('max_cvss', 0):.1f}

Top {len(top_cves)} CVEs (by CVSS score):
{json.dumps(cve_summary, indent=2)}

Produce a JSON response with:
- overall_risk      : "CRITICAL", "HIGH", "MEDIUM", or "LOW"
- risk_summary      : 2-3 sentences describing the overall vulnerability landscape
- top_threats       : list of up to 3 most impactful threat descriptions (each ≤ 120 chars)
- recommendations   : list of up to 3 concrete remediation actions (each ≤ 120 chars)
- key_attack_vectors: list of unique attack vectors present (e.g. ["Network", "Local"])

Respond with ONLY valid JSON:
{{
  "overall_risk": "HIGH",
  "risk_summary": "...",
  "top_threats": ["...", "..."],
  "recommendations": ["...", "..."],
  "key_attack_vectors": ["Network"]
}}"""

    try:
        msg = _client().messages.create(
            model=SEVERITY_MODEL,
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
        result = _extract_json(msg.content[0].text.strip())
        if result:
            result["success"] = True
            result["cves_analyzed"] = len(top_cves)
            return result
        return {"success": False, "error": "Could not parse AI response"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ─── 3. AI Static Behavior Analysis ─────────────────────────────────────────

def ai_analyze_static_behavior(static_result: dict) -> dict:
    """
    Analyze PE static analysis findings using AI to produce a vulnerability
    assessment when no CVEs are available from NVD.

    Args:
        static_result: Full output from PEStaticAnalyzer.analyze()

    Returns:
        {
            "success": bool,
            "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|CLEAN",
            "vulnerability_types": [str, ...],  # potential CWE/vuln types
            "behavioral_summary": str,           # what this binary likely does
            "attack_techniques": [str, ...],     # MITRE ATT&CK techniques
            "recommendations": [str, ...],
            "cwe_suggestions": [str, ...],       # CWE IDs relevant to findings
        }
        or {"success": False, "error": str}
    """
    if not is_available():
        return {"success": False, "error": "AI not available (missing package or API key)"}

    # Extract key findings from static analysis
    imports = static_result.get("imports", {})
    by_category = imports.get("by_category", {})
    suspicious_apis = imports.get("suspicious", [])
    sections = static_result.get("sections", [])
    strings = static_result.get("strings", {})
    components = static_result.get("components", [])
    risk = static_result.get("risk", {})

    # Build concise findings summary for the prompt
    high_entropy_sections = [s["name"] for s in sections if s.get("high_entropy")]
    detected_categories = list(by_category.keys())
    sample_apis = [a["function"] for a in suspicious_apis[:20]]
    embedded_urls = strings.get("URLs", [])[:5]
    embedded_ips = strings.get("IP Addresses", [])[:5]
    suspicious_cmds = strings.get("Suspicious Commands", [])[:5]

    component_list = [
        f"{c['name']} {c.get('version', '')} (CPE vendor: {c.get('cpe_vendor', 'unknown')})"
        for c in components
    ] if components else []

    prompt = f"""You are a senior malware analyst and vulnerability researcher.
Analyze the following Windows PE binary static analysis findings and assess what vulnerabilities or security risks this binary introduces.

=== STATIC ANALYSIS FINDINGS ===

Risk Score: {risk.get('score', 0)}/100 ({risk.get('level', 'UNKNOWN')})
Risk Factors: {risk.get('factors', [])}

Suspicious API Categories Detected: {detected_categories}
Sample Suspicious APIs: {sample_apis}

High-Entropy Sections (possible packing/encryption): {high_entropy_sections if high_entropy_sections else 'None'}

Embedded Components/Libraries: {component_list if component_list else 'None detected'}

Embedded URLs: {embedded_urls if embedded_urls else 'None'}
Embedded IP Addresses: {embedded_ips if embedded_ips else 'None'}
Suspicious Command Strings: {suspicious_cmds if suspicious_cmds else 'None'}

=== TASK ===
Based on these findings, provide:
1. What vulnerability types (by CWE) are relevant to this binary's behavior?
2. What malicious techniques (MITRE ATT&CK) does this binary likely implement?
3. A behavioral summary of what this binary is likely doing.
4. Security recommendations.

Respond with ONLY valid JSON:
{{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|CLEAN",
  "behavioral_summary": "2-3 sentences describing what this binary likely does based on its API usage and characteristics",
  "vulnerability_types": ["e.g. Buffer Overflow (CWE-120)", "Privilege Escalation (CWE-269)"],
  "attack_techniques": ["e.g. T1055 - Process Injection", "T1056 - Input Capture"],
  "cwe_suggestions": ["CWE-120", "CWE-269"],
  "recommendations": ["Isolate and sandbox this binary", "Block network communication", "Investigate process tree"]
}}"""

    try:
        msg = _client().messages.create(
            model=SEVERITY_MODEL,
            max_tokens=700,
            messages=[{"role": "user", "content": prompt}],
        )
        result = _extract_json(msg.content[0].text.strip())
        if result:
            result["success"] = True
            return result
        return {"success": False, "error": "Could not parse AI response"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}
