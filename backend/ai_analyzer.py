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
