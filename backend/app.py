"""
Software Vulnerability Assessment Tool
Flask Web Server

Thesis: Research and Development of a Software Vulnerability Assessment Tool
        combining AI and the CVE database

API Endpoints:
  POST /api/analyze          - Analyze a file (PE binary OR package manifest)
  POST /api/analyze-packages - Analyze package manifest (alias, same as /api/analyze)
  POST /api/search           - Search by software name + version
  POST /api/query-cpe        - Query CVEs by CPE string
  POST /api/export-all       - Export ALL CVEs for a CPE (no limit)
  GET  /api/status           - System status & enabled features
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename
from pathlib import Path
import sys
import os
import re


def _ensure_utf8_stdio():
    """Avoid Windows console crashes when logging Vietnamese text."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_ensure_utf8_stdio()

# ── Path setup ───────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / 'ai'))

# ── Core modules ─────────────────────────────────────────────────────────────
from cpe_extractor       import CPEExtractor
from nvd_api_v2          import NVDAPIv2
from static_analyzer     import PEStaticAnalyzer
from package_analyzer    import PackageAnalyzer, PackageAnalyzer as _PKG
from cpe_semantic_matcher import (
    match_best as sem_match_best, is_available as sem_available,
)
from cwe_predictor import CWEPredictor

# ── Unified AI pipeline (replaces individual model imports) ──────────────────
from ai.severity_pipeline import (
    enrich_cves   as ai_enrich_severity,
    is_available  as severity_pipeline_available,
    get_status    as severity_status,
)
from ai.relevance_scorer import (
    score_cves              as ai_score_relevance,
    get_profile_text        as ai_profile_text,
    is_semantic_available   as secbert_available,
)
from ai.ember_behavioral_scorer import (
    score_file  as ember_score_file,
    is_available as ember_available,
    get_status  as ember_status,
)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder='../frontend/templates',
    static_folder='../frontend/static',
)
CORS(app)

app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1 GB

UPLOAD_DIR = BASE_DIR.parent / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_DIR)

# ── Globals ───────────────────────────────────────────────────────────────────
nvd_api       = None
cpe_extractor = None

pe_analyzer   = None
pkg_analyzer  = None
cwe_predictor = None


# ── Initialization ────────────────────────────────────────────────────────────

def init_app():
    global nvd_api, cpe_extractor, pe_analyzer, pkg_analyzer, cwe_predictor

    print("=" * 70)
    print("[*] SOFTWARE VULNERABILITY ASSESSMENT TOOL")
    print("    AI + CVE Database Edition")
    print("=" * 70)

    # NVD API key — set via NVD_API_KEY environment variable (see .env.example)
    api_key = os.getenv('NVD_API_KEY')

    if not api_key:
        print("[!] WARNING: NVD_API_KEY env var not set — queries will be slow (5 req/30s)")
        print("[!]          Set it in a .env file or export NVD_API_KEY=<your-key>")

    nvd_api       = NVDAPIv2(api_key)
    cpe_extractor = CPEExtractor()
    pe_analyzer   = PEStaticAnalyzer()
    pkg_analyzer  = PackageAnalyzer()
    cwe_predictor = CWEPredictor(nvd_api)

    print("[+] NVD API v2 initialized")
    print("[+] CPE Extractor initialized")
    print("[+] PE Static Analyzer initialized")
    print("[+] Package Analyzer initialized")
    print("[+] CWE Predictor initialized (Track 3)")
    print(f"    Supported: {', '.join(PackageAnalyzer.supported_filenames()[:8])} ...")

    print()
    print("[*] AI Feature Status:")

    if sem_available(): 
        print("[+] Semantic CPE Matcher (FAISS): ENABLED")
    else:
        print("[i] Semantic CPE Matcher: DISABLED (run: python untils/build_cpe_index.py)")

    sv = severity_status()
    if sv['available']:
        active = [k for k, v in sv.items() if v and k != 'available']
        print(f"[+] Severity Pipeline: ENABLED ({', '.join(active)})")
    else:
        print("[i] Severity Pipeline: DISABLED (no models trained)")

    if secbert_available():
        print("[+] SecBERT Semantic Relevance: ENABLED")
    else:
        print("[i] SecBERT Semantic Relevance: DISABLED (pip install transformers torch)")

    es = ember_status()
    if es['available']:
        print("[+] EMBER Behavioral Scorer (XGBoost, 600K PE samples): ENABLED")
    else:
        print(f"[i] EMBER Behavioral Scorer: DISABLED ({es.get('error', 'model not found')})")

    print()


init_app()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ── /api/analyze ─────────────────────────────────────────────────────────────

@app.route('/api/analyze', methods=['POST'])
@app.route('/api/analyze-packages', methods=['POST'])
def analyze_file():
    """
    Universal file analysis endpoint.
    Accepts:
      - PE binary (.exe / .dll / .sys) → static analysis + CVE lookup
      - Package manifest (requirements.txt, package.json, pom.xml, etc.)
                         → dependency extraction + CVE per package
    """
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    filepath = Path(app.config['UPLOAD_FOLDER']) / filename

    try:
        file.save(str(filepath))

        ext = filepath.suffix.lower()

        # ── Route to appropriate handler ──────────────────────────────────
        if ext in ('.exe', '.dll', '.sys', '.ocx', '.drv'):
            return _analyze_pe(filepath, filename)
        elif PackageAnalyzer.is_package_file(filename):
            return _analyze_package_manifest(filepath, filename)
        else:
            # Attempt PE first, then package manifest
            try:
                import pefile
                pefile.PE(str(filepath), fast_load=True).close()
                return _analyze_pe(filepath, filename)
            except Exception:
                # Try as package manifest
                if pkg_analyzer.detect_ecosystem(filepath):
                    return _analyze_package_manifest(filepath, filename)
                return jsonify({
                    'success': False,
                    'error':   (
                        f'Unsupported file type: {ext or filename}. '
                        'Upload a PE binary (.exe/.dll/.sys) or a package manifest '
                        '(requirements.txt, package.json, pom.xml, etc.)'
                    ),
                }), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

    finally:
        try:
            filepath.unlink(missing_ok=True)
        except Exception:
            pass


def _normalize_confidence_label(score: float) -> str:
    if score >= 0.80:
        return 'high'
    if score >= 0.62:
        return 'medium'
    return 'low'


def _score_extractor_candidate(cpe_info: dict, filename: str) -> dict:
    method = cpe_info.get('extraction_method', '') or ''
    vendor = (cpe_info.get('vendor') or '').strip().lower()
    product = (cpe_info.get('product') or '').strip().lower()
    version = (cpe_info.get('version') or '').strip()
    cpe = cpe_info.get('cpe')
    file_meta = cpe_info.get('file_info') or {}
    product_name = str(file_meta.get('ProductName') or '').strip()
    company_name = str(file_meta.get('CompanyName') or '').strip()

    score = 0.0
    reasons = []
    generic_vendors = {'', 'unknown', 'microsoft_corporation'}

    if cpe:
        if method == 'pe_version_info':
            score = 0.78
            reasons.append('PE version info matched a known product pattern')
        elif method == 'manual_input':
            score = 0.72
            reasons.append('User-provided software name matched a known product pattern')
        elif method == 'filename_pattern':
            score = 0.54
            reasons.append('Filename matched a known product pattern')
        else:
            score = 0.40
            reasons.append(f'Resolution came from {method or "an unspecified source"}')

    if version:
        score += 0.05
        reasons.append('Version string was extracted')

    if product_name and _text_looks_like_target(product_name, product.replace('_', ' ')):
        score += 0.07
        reasons.append('ProductName aligns with the resolved product')

    if company_name:
        company_compact = _compact_software_text(company_name)
        vendor_compact = _compact_software_text(vendor.replace('_', ' '))
        if vendor_compact and vendor_compact in company_compact:
            score += 0.05
            reasons.append('CompanyName aligns with the resolved vendor')

    if vendor in generic_vendors:
        score -= 0.12
        reasons.append('Vendor is generic or unresolved')

    if method == 'filename_pattern' and not version:
        score -= 0.08
        reasons.append('Filename-only resolution did not contain a reliable version')

    score = max(0.0, min(score, 0.99))
    return {
        'source': 'extractor',
        'candidate_cpe': cpe,
        'vendor': vendor,
        'product': product,
        'version': version,
        'score': round(score, 3),
        'confidence': _normalize_confidence_label(score),
        'accepted': bool(cpe and score >= 0.62),
        'reasons': reasons,
        'method': method,
    }


def _score_semantic_candidate(query_name: str, sem_cpe_result: dict | None, version: str) -> dict | None:
    if not sem_cpe_result:
        return None

    vendor = (sem_cpe_result.get('vendor') or '').strip().lower()
    product = (sem_cpe_result.get('product') or '').strip().lower()
    score = float(sem_cpe_result.get('score') or 0.0)
    confidence = sem_cpe_result.get('confidence') or _normalize_confidence_label(score)
    reasons = [f'Semantic matcher returned {confidence} confidence ({score:.3f})']

    if version:
        score += 0.03
        reasons.append('Version string was available for the semantic candidate')

    score = max(0.0, min(score, 0.99))
    candidate_cpe = cpe_extractor._build_cpe(vendor, product, version or '')
    return {
        'source': 'semantic',
        'candidate_cpe': candidate_cpe,
        'vendor': vendor,
        'product': product,
        'version': version,
        'score': round(score, 3),
        'confidence': _normalize_confidence_label(score),
        'accepted': bool(candidate_cpe and score >= 0.62),
        'reasons': reasons,
        'method': 'semantic_faiss',
        'raw_result': sem_cpe_result,
    }


def _score_component_candidate(components: list | None, filename: str, product_hint: str = '') -> dict | None:
    if not components:
        return None

    filename_base = Path(str(filename or '')).stem or str(filename or '')
    filename_text = _normalize_software_text(filename_base)
    best = None

    for comp in components:
        vendor = (comp.get('cpe_vendor') or '').strip().lower()
        product = (comp.get('cpe_product') or '').strip().lower()
        version = (comp.get('version') or '').strip()
        name = (comp.get('name') or '').strip()
        source = comp.get('source') or 'component'
        if not vendor or not product:
            continue

        score = 0.34
        reasons = ['Embedded component metadata was detected inside the binary']

        if version:
            score += 0.08
            reasons.append('Component version string was extracted')

        if _text_looks_like_target(filename_text, name) or _text_looks_like_target(filename_text, product.replace('_', ' ')):
            score += 0.34
            reasons.append('Filename strongly aligns with the detected component')

        if product_hint and (
            product == product_hint
            or _text_looks_like_target(name, product_hint.replace('_', ' '))
            or _text_looks_like_target(product.replace('_', ' '), product_hint.replace('_', ' '))
        ):
            score += 0.10
            reasons.append('Component agrees with the extractor product hint')

        if source == 'string_scan':
            score += 0.05
            reasons.append('Component came from version-bearing strings')

        if not (_text_looks_like_target(filename_text, name) or _text_looks_like_target(filename_text, product.replace('_', ' '))):
            score -= 0.12
            reasons.append('Component does not look like the primary filename target')

        score = max(0.0, min(score, 0.95))
        candidate = {
            'source': 'component',
            'candidate_cpe': cpe_extractor._build_cpe(vendor, product, version or ''),
            'vendor': vendor,
            'product': product,
            'version': version,
            'score': round(score, 3),
            'confidence': _normalize_confidence_label(score),
            'accepted': bool(score >= 0.62),
            'reasons': reasons,
            'method': f'embedded_component:{source}',
            'raw_result': comp,
        }
        if best is None or candidate['score'] > best['score']:
            best = candidate

    return best


def _resolve_cpe(cpe_info: dict, filename: str, components: list | None = None) -> dict:
    """
    Attempt to resolve a CPE using extractor + FAISS fallback with confidence gating.
    Returns a dict containing the accepted CPE (if any) plus resolution metadata.
    """
    cpe     = cpe_info.get('cpe')
    vendor  = cpe_info.get('vendor', '')
    product = cpe_info.get('product', '')
    version = cpe_info.get('version', '')
    extraction_method = cpe_info.get('extraction_method', '')

    extractor_candidate = _score_extractor_candidate(cpe_info, filename)
    sem_cpe_result = None
    semantic_candidate = None
    component_candidate = _score_component_candidate(components, filename, extractor_candidate.get('product', ''))

    # Use FAISS when: explicit fallback modes OR pe_version_info gave unknown/generic vendor
    _generic_vendors = {'unknown', 'microsoft_corporation', ''}
    needs_sem = (
        extraction_method in ('generic_fallback',)
        or (extraction_method == 'filename_pattern' and vendor in _generic_vendors)
        or (extraction_method == 'pe_version_info' and vendor in _generic_vendors)
        or not cpe
    )

    file_meta  = cpe_info.get('file_info', {})
    query_name = (
        file_meta.get('ProductName') or product or filename or ''
    ).strip()

    if sem_available() and query_name and (needs_sem or extractor_candidate['score'] < 0.70):
        sem_cpe_result = sem_match_best(query_name, min_score=0.50)
        semantic_candidate = _score_semantic_candidate(query_name, sem_cpe_result, version)

    chosen = extractor_candidate
    if component_candidate and component_candidate['score'] > chosen['score'] + 0.06:
        chosen = component_candidate
    if semantic_candidate and semantic_candidate['score'] > chosen['score'] + 0.04:
        chosen = semantic_candidate
    if (
        component_candidate
        and component_candidate.get('accepted')
        and component_candidate.get('version')
        and (
            not chosen.get('version')
            or chosen.get('candidate_cpe', '').endswith(':-:*:*:*:*:*:*:*')
        )
        and component_candidate.get('product') == chosen.get('product')
    ):
        chosen = component_candidate

    accepted = chosen['accepted']
    error = ''
    if not accepted:
        error = (
            f'Could not confirm software identity with enough confidence '
            f'({chosen["confidence"]}, score={chosen["score"]:.2f}).'
        )

    return {
        'cpe': chosen['candidate_cpe'] if accepted else None,
        'vendor': chosen['vendor'] if accepted else '',
        'product': chosen['product'] if accepted else '',
        'version': chosen['version'],
        'ai_cpe': None,
        'sem_cpe': sem_cpe_result,
        'resolution': {
            'accepted': accepted,
            'source': chosen['source'],
            'method': chosen['method'],
            'confidence': chosen['confidence'],
            'confidence_score': chosen['score'],
            'reasons': chosen['reasons'],
            'candidate_cpe': chosen['candidate_cpe'],
            'candidate_vendor': chosen['vendor'],
            'candidate_product': chosen['product'],
            'query_name': query_name,
            'error': error,
        },
    }


def _filter_cves_for_target(cves: list, target_cpe: str | None, source_label: str = 'NVD') -> list:
    """
    Remove CVEs that do not actually affect the queried vendor/product/version.

    virtualMatchString and keyword fallback are intentionally broad, so this
    secondary filter keeps the demo focused on "version currently being used".
    """
    if not cves or not target_cpe:
        return cves

    try:
        filtered = nvd_api.filter_cves_for_target(cves, target_cpe)
        removed = len(cves) - len(filtered)
        if removed > 0:
            print(f"[{source_label}] Filtered out {removed} non-applicable CVEs using CPE/version match")
        return filtered
    except Exception as ex:
        print(f"[{source_label}] Applicability filter failed (non-fatal): {ex}")

    return cves


def _normalize_software_text(text: str) -> str:
    if not text:
        return ''
    text = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', str(text))
    text = re.sub(r'[^a-z0-9]+', ' ', text.lower())
    return ' '.join(text.split())


def _compact_software_text(text: str) -> str:
    return _normalize_software_text(text).replace(' ', '')


def _text_looks_like_target(text: str, software_name: str) -> bool:
    query = _normalize_software_text(software_name)
    hay   = _normalize_software_text(text)
    query_compact = _compact_software_text(software_name)
    hay_compact   = _compact_software_text(text)
    if not query or not hay:
        return False

    if len(query) <= 3:
        return (
            query == hay
            or query_compact == hay_compact
            or f' {query} ' in f' {hay} '
        )

    if query in hay or hay in query or query_compact == hay_compact:
        return True

    q_tokens = [tok for tok in query.split() if len(tok) >= 4]
    if not q_tokens:
        return False
    hay_tokens = set(hay.split())
    return all(tok in hay_tokens for tok in q_tokens)


def _rule_query_match_score(rule: dict, software_name: str) -> int:
    query   = _normalize_software_text(software_name)
    q_comp  = _compact_software_text(software_name)
    vendor  = _normalize_software_text(rule.get('vendor', ''))
    v_comp  = _compact_software_text(rule.get('vendor', ''))
    product = _normalize_software_text(rule.get('product', ''))
    p_comp  = _compact_software_text(rule.get('product', ''))
    if not query or not (vendor or product):
        return 0

    score = 0
    if product == query or p_comp == q_comp:
        score += 2
    elif query in product or product in query or (q_comp and (q_comp in p_comp or p_comp in q_comp)):
        score += 1

    if vendor == query or v_comp == q_comp:
        score += 2
    elif query in vendor or vendor in query or (q_comp and (q_comp in v_comp or v_comp in q_comp)):
        score += 1

    if score == 0:
        combined = ' '.join(filter(None, [vendor, product]))
        if _text_looks_like_target(combined, software_name):
            score = 1

    return score


def _filter_keyword_only_cves(cves: list, software_name: str, version: str = '') -> list:
    """
    Clean up keyword-only search results when no CPE was resolved.

    We prefer CVEs whose affected CPE family lexically matches the queried
    software name. When a version is supplied, keep only rules whose affected
    range still covers that version. This removes collisions such as:
      - Obsidian desktop app vs Plesk Obsidian
      - HxD vs Microsoft hxds.dll
      - qBittorrent vs libtorrent / unrelated helper tools
    """
    if not cves or not software_name:
        return cves

    filtered = []
    annotated = []
    best_family_score = 0

    for cve in cves:
        rules = cve.get('affected_products') or []
        scored_rules = []
        for rule in rules:
            score = _rule_query_match_score(rule, software_name)
            if score > 0:
                scored_rules.append((rule, score))

        max_score = max((score for _, score in scored_rules), default=0)
        if max_score > best_family_score:
            best_family_score = max_score
        annotated.append((cve, scored_rules, max_score))

    for cve, scored_rules, max_score in annotated:
        if scored_rules:
            if best_family_score >= 4 and max_score < best_family_score:
                continue

            matched_rules = [rule for rule, score in scored_rules if score == max_score]
            if version and nvd_api is not None:
                version_matched = False
                for rule in matched_rules:
                    try:
                        if nvd_api._version_matches_rule(version, rule):
                            version_matched = True
                            break
                    except Exception:
                        continue
                if not version_matched:
                    continue
            filtered.append(cve)
            continue

        # Fallback only when the CVE title/summary clearly starts with the
        # queried product name and there were no usable CPE rules.
        if best_family_score >= 4:
            continue

        desc = _normalize_software_text(cve.get('description', ''))
        query = _normalize_software_text(software_name)
        if (
            desc.startswith(query)
            or desc.startswith(f'in {query} ')
            or desc.startswith(f'a vulnerability identified in the {query}')
        ):
            filtered.append(cve)

    removed = len(cves) - len(filtered)
    if removed > 0:
        print(f"[SEARCH] Keyword-only lexical/version filter removed {removed} CVEs for {software_name!r}")
    return filtered


def _keyword_results_look_too_broad(cves: list, target_cpe: str | None, software_name: str, version: str = '') -> bool:
    """
    Guardrail for pure keyword-search fallback when no CPE was resolved.

    If NVD returns a very large candidate set for a broad query such as
    "Client" or "Archive Manager", the top few results are often unrelated.
    In that case we prefer asking for a more specific product name/version
    instead of showing misleading CVEs.
    """
    if target_cpe or not cves:
        return False

    total_results = cves[0].get('search_total_results') or len(cves)
    if total_results <= 20:
        return False

    query = f"{software_name} {version}".strip() if version else software_name
    print(
        f"[SEARCH] Rejecting broad keyword-only result set for {query!r}: "
        f"{total_results} NVD matches without a resolved CPE"
    )
    return True


def _compute_ai_risk_score(cves: list, ember_result: dict | None = None) -> dict | None:
    """
    AI Risk Score — driven entirely by EMBER XGBoost behavioral scoring.
    EMBER probability (0→1) maps directly to score (0→100).
    CVE info appended as context factors only.
    """
    if not ember_result and not cves:
        return None

    factors = []

    # ── EMBER is the primary source — map probability 0→1 to score 0→100 ──────
    if ember_result and ember_result.get('available') and ember_result.get('probability') is not None:
        prob  = ember_result['probability']
        score = min(100, round(prob * 100))
        label = ember_result.get('label', '')
        lvl   = ember_result.get('level', '')
        factors.append(f"EMBER auxiliary binary signal: {prob:.1%} → {label}")
        factors.append(f"Model: XGBoost trained on EMBER 2017 (600K  samples, AUC=0.9994)")
    elif cves:
        # Fallback when EMBER is unavailable — use CVSS
        cvss_scores = [c.get('cvss_score') or 0 for c in cves]
        avg_cvss    = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        score = min(100, round((avg_cvss / 10) * 100))
        factors.append(f"Average CVSS score: {avg_cvss:.1f} (EMBER not available)")
    else:
        return None

    # ── CVE context (supplementary info, does not affect the score) ──────────
    if cves:
        for lbl in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            count = sum(
                1 for c in cves
                if isinstance(c.get('relevance'), dict)
                and c['relevance'].get('label') == lbl
            )
            if count:
                factors.append(f"{count} CVE(s) with {lbl} relevance")

    if score >= 70:
        level = 'CRITICAL'
    elif score >= 40:
        level = 'HIGH'
    elif score >= 20:
        level = 'MEDIUM'
    elif score > 0:
        level = 'LOW'
    else:
        level = 'CLEAN'

    return {'score': score, 'level': level, 'factors': factors, 'method': 'ember_ml'}


def _enrich_cves(cves: list, software_analysis: dict | None = None) -> list:
    """Apply unified AI severity + relevance scoring to a CVE list.

    When SecBERT is available, CVEs scored LOW or MINIMAL relevance are filtered out —
    they are semantically unrelated to the file and would mislead the user.
    When only CVSS-only fallback is used, no filtering is applied.
    """
    if not cves:
        return cves

    # Unified severity ensemble
    cves = ai_enrich_severity(cves)

    # Relevance scoring (only when we have a software context)
    if software_analysis:
        cves = ai_score_relevance(software_analysis, cves)

        # Filter low-relevance CVEs when SecBERT semantic scoring is active
        _LOW_LABELS = {'LOW', 'MINIMAL'}
        filtered = [
            c for c in cves
            if c.get('relevance', {}).get('method') != 'secbert'
            or c.get('relevance', {}).get('label') not in _LOW_LABELS
        ]
        # Only apply filter if it doesn't wipe everything out
        if filtered:
            cves = filtered

    return cves


def _analyze_pe(filepath: Path, filename: str):
    """Full PE binary static analysis + CVE lookup."""

    print(f"\n[PE] Analyzing: {filename}")

    # ── 1. Static analysis ────────────────────────────────────────────────────
    result = pe_analyzer.analyze(filepath)
    result.update({
        'analysis_type': 'binary',
        'cpe':           None,
        'cpe_info':      {},
        'vulnerabilities': [],
        'cve_statistics': {},
        'behavioral_cve_suggestions': [],
        'behavioral_cve_statistics': {},
    })

    # ── 1b. EMBER ML behavioral scoring ──────────────────────────────────────
    try:
        ember_result = ember_score_file(str(filepath))
        result['ember_behavioral'] = ember_result
        if ember_result.get('available') and ember_result.get('probability') is not None:
            print(f"[PE] EMBER score: {ember_result['probability']:.1%} "
                  f"→ {ember_result['label']} ({ember_result['level']})")
        elif ember_result.get('error'):
            print(f"[PE] EMBER error: {ember_result['error']}")
    except Exception as _ember_ex:
        print(f"[PE] EMBER scorer failed (non-fatal): {_ember_ex}")
        ember_result = {'available': False, 'probability': None, 'error': str(_ember_ex)}

    # ── 2. CPE extraction ─────────────────────────────────────────────────────
    try:
        cpe_info = cpe_extractor.extract_from_file(filepath)
        resolved_cpe = _resolve_cpe(cpe_info, filename, result.get('components', []))
        cpe = resolved_cpe['cpe']
        vendor = resolved_cpe['vendor']
        product = resolved_cpe['product']
        version = resolved_cpe['version']
        ai_cpe = resolved_cpe['ai_cpe']
        sem_cpe = resolved_cpe['sem_cpe']
        resolution_meta = resolved_cpe['resolution']

        result['ai_cpe']  = ai_cpe
        result['sem_cpe'] = sem_cpe
        result['cpe']     = cpe
        result['cpe_info'] = {
            'vendor':   vendor or resolution_meta.get('candidate_vendor', ''),
            'product':  product or resolution_meta.get('candidate_product', ''),
            'version':  version,
            'extraction_method': cpe_info.get('extraction_method', ''),
            'confidence': resolution_meta.get('confidence', 'low'),
            'confidence_score': resolution_meta.get('confidence_score', 0.0),
            'resolution_source': resolution_meta.get('source', ''),
            'candidate_cpe': resolution_meta.get('candidate_cpe'),
            'accepted': resolution_meta.get('accepted', False),
            'reasons': resolution_meta.get('reasons', []),
        }
        if not resolution_meta.get('accepted', False):
            result['cpe_info']['error'] = resolution_meta.get('error') or \
                'Software identity could not be resolved with enough confidence.'

        # ── 3. CVE lookup ─────────────────────────────────────────────────────
        if cpe:
            print(f"[PE] Querying NVD: {cpe}")
            cves = nvd_api.search_by_cpe(cpe, max_results=50)
            # Keyword fallback: if CPE returned 0 results (vendor mismatch),
            # retry with the keyword "product version"
            if not cves and product and version:
                kw = f"{product} {version}".strip()
                print(f"[PE] CPE returned 0 CVEs — retrying with keyword: {kw!r}")
                cves = nvd_api.search_by_keyword(kw, max_results=50)
            elif not cves and product:
                print(f"[PE] CPE returned 0 CVEs — retrying with keyword: {product!r}")
                cves = nvd_api.search_by_keyword(product, max_results=50)
            cves = _filter_cves_for_target(cves, cpe, source_label='PE')
            stats = _calc_stats(cves)
            print(f"[PE] Found {len(cves)} CVEs")

            cves = _enrich_cves(cves, result)
            result['behavior_profile_text'] = ai_profile_text(result)

            result['vulnerabilities'] = cves[:50]
            result['cve_statistics']  = stats

            # AI-based risk score: EMBER ML + CVE relevance combined
            ai_risk = _compute_ai_risk_score(cves, ember_result)
            if ai_risk:
                result['ai_risk'] = ai_risk

            # Embedded component CVEs
            component_cves = _lookup_component_cves(result.get('components', []))
            if component_cves:
                existing_ids = {c.get('cve_id') for c in cves}
                new_cves = [c for c in component_cves if c.get('cve_id') not in existing_ids]
                result['component_vulnerabilities'] = new_cves[:50]
                result['component_cve_count']       = len(component_cves)

        else:
            print(f"[PE] No CPE resolved — skipping CVE lookup")
            # No CVE but still have an EMBER score → compute ai_risk from EMBER
            ai_risk = _compute_ai_risk_score([], ember_result)
            if ai_risk:
                result['ai_risk'] = ai_risk

    except Exception as e:
        print(f"[PE] CPE/CVE step error: {e}")
        result['cpe_error'] = str(e)

    # ── Track 3: CWE Behavior Prediction ─────────────────────────────────────
    # Gate: only run when the file shows actual signs of being dangerous.
    # Condition: EMBER >= 50% OR a strong enough behavior combo.
    # Do not skip just because a CPE exists; prediction runs independently of CPE.
    try:
        _ember_prob   = (ember_result.get('probability') or 0.0)
        _suspicious   = result.get('imports', {}).get('suspicious', [])
        # Only count suspicious APIs with HIGH or CRITICAL risk — MEDIUM is too common
        # The correct key is 'function' (from static_analyzer), not 'api'
        _high_risk    = [s for s in _suspicious if s.get('function') and s.get('risk') in ('HIGH', 'CRITICAL')]
        _ember_sus    = _ember_prob >= 0.50
        _strong_behavior = False
        if cwe_predictor is not None:
            try:
                _strong_behavior = cwe_predictor._has_strong_behavioral_evidence(result)
            except Exception as _behavior_ex:
                print(f"[PE] Strong behavior gate failed (non-fatal): {_behavior_ex}")

        if _suspicious:
            print(f"[PE] Suspicious APIs: {[(s.get('function'), s.get('risk')) for s in _suspicious]}")
        if not _ember_sus and not _strong_behavior:
            print(f"[PE] Skipping CWE prediction — EMBER={_ember_prob:.1%} BENIGN/low-signal, "
                  f"strong_behavior={_strong_behavior}, high_risk_apis={len(_high_risk)}, "
                  f"total_suspicious={len(_suspicious)}")
        else:
            print(f"[PE] Running CWE behavior prediction "
                  f"(EMBER={_ember_prob:.1%}, suspicious_apis={len(_high_risk)}, "
                  f"strong_behavior={_strong_behavior})")
            cwe_result = cwe_predictor.predict_and_fetch(result)
            cwe_result['advisory_only'] = True
            cwe_result['match_scope'] = 'behavioral_hint_only'
            result['cwe_analysis'] = cwe_result

            if cwe_result.get('cve_results'):
                cwe_cves = cwe_result['cve_results']
                print(f"[PE][CWE] Raw CVEs from Track 3: {len(cwe_cves)}")

                cwe_cves = _enrich_cves(cwe_cves, result)
                print(f"[PE][CWE] After enrich: {len(cwe_cves)}")

                # Select: sort by relevance score DESC, keep top 10
                cwe_cves.sort(
                    key=lambda c: (
                        c.get('relevance', {}).get('score', 0.0),
                        c.get('cvss_score') or 0.0,
                    ),
                    reverse=True,
                )
                cwe_cves = cwe_cves[:10]
                print(f"[PE][CWE] After top-10 selection: {len(cwe_cves)}")

                result['behavioral_cve_suggestions'] = cwe_cves
                result['behavioral_cve_statistics'] = _calc_stats(cwe_cves)
                result['cwe_analysis']['behavioral_cve_count'] = len(cwe_cves)
                print(
                    f"[PE][CWE] Stored {len(cwe_cves)} behavioral CVE suggestion(s) "
                    f"as advisory-only output (not merged into confirmed matches)"
                )
    except Exception as e:
        import traceback
        print(f"[PE] CWE prediction error: {e}")
        print(traceback.format_exc())

    # ── Rule-based recommendations ────────────────────────────────────────────
    pe_cves  = result.get('vulnerabilities', [])
    pe_stats = result.get('cve_statistics') or _calc_stats(pe_cves)
    result['cve_statistics'] = pe_stats
    # Only use the software name when the CPE is clearly identified.
    # Track 3 (behavioral, no CPE) → leave name empty to avoid confusion
    _cpe_info   = result.get('cpe_info') or {}
    _identified = (
        _cpe_info.get('product') and
        _cpe_info.get('vendor') and
        _cpe_info.get('vendor').lower() not in ('unknown', 'n/a', '') and
        _cpe_info.get('product').lower() not in ('unknown', 'n/a', '')
    )
    _pe_sw = _cpe_info.get('product') if _identified else ''
    result['ai_analysis'] = _generate_recommendations(
        pe_cves, pe_stats, context='file',
        software_name=_pe_sw,
        ember_result=result.get('ember_behavioral'),
        behavioral={
            'ember_result':   result.get('ember_behavioral'),
            'suspicious_apis': result.get('imports', {}).get('suspicious', []),
            'imports_by_category': result.get('imports', {}).get('by_category', {}),
            'strings':        result.get('strings', {}),
            'static_risk':    result.get('risk'),
            'ai_risk':        result.get('ai_risk'),
            'cwe_analysis':   result.get('cwe_analysis'),
        },
    )

    print(f"[PE] Done — Risk: {result.get('risk', {}).get('level', '?')} | "
          f"CVEs: {len(pe_cves)}")

    return jsonify(result)


def _lookup_component_cves(components: list) -> list:
    """Query NVD CVEs for all embedded components."""
    found = []
    for comp in components:
        vendor  = comp.get('cpe_vendor', '')
        product = comp.get('cpe_product', '')
        version = comp.get('version', '')
        if vendor and product:
            comp_cpe = cpe_extractor._build_cpe(vendor, product, version)
            if comp_cpe:
                cves = nvd_api.search_by_cpe(comp_cpe, max_results=20)
                cves = _filter_cves_for_target(cves, comp_cpe, source_label='COMP')
                for cv in cves:
                    cv['source_component']         = comp['name']
                    cv['source_component_version'] = version
                found.extend(cves)
    return found


def _analyze_package_manifest(filepath: Path, filename: str):
    """Parse package manifest → per-package CVE lookup."""

    print(f"\n[PKG] Analyzing: {filename}")

    parse_result = pkg_analyzer.analyze(filepath)
    if not parse_result.get('success'):
        return jsonify({
            'success': False,
            'error':   parse_result.get('error', 'Parse failed'),
        }), 400

    ecosystem = parse_result['ecosystem']
    packages  = parse_result['packages']
    print(f"[PKG] Ecosystem: {ecosystem} | Packages: {len(packages)}")

    results_per_pkg = []
    all_cves        = []
    total_unique_ids: set[str] = set()

    for pkg in packages:
        name    = pkg.get('name', '')
        version = pkg.get('version', '')
        hints   = pkg.get('cpe_hints')

        if not name:
            continue

        # ── Resolve CPE ────────────────────────────────────────────────────
        cpe = None
        cpe_vendor  = ''
        cpe_product = ''

        # Use known CPE hints first
        if hints:
            cpe_vendor  = hints['vendor']
            cpe_product = hints['product']
            cpe         = cpe_extractor._build_cpe(cpe_vendor, cpe_product, version)

        # Fallback: FAISS semantic
        if not cpe and sem_available():
            query = f"{name} {version}".strip()
            sem_r = sem_match_best(query, min_score=0.50)
            if sem_r and sem_r.get('confidence') in ('high', 'medium'):
                cpe_vendor  = sem_r['vendor']
                cpe_product = sem_r['product']
                cpe         = cpe_extractor._build_cpe(cpe_vendor, cpe_product, version)

        # ── Query NVD ──────────────────────────────────────────────────────
        cves = []
        if cpe:
            cves = nvd_api.search_by_cpe(cpe, max_results=20)
            # Keyword fallback when CPE yields 0
            if not cves:
                kw = f"{name} {version}".strip()
                cves = nvd_api.search_by_keyword(kw, max_results=10)
            cves = _filter_cves_for_target(cves, cpe, source_label='PKG')

        cves = ai_enrich_severity(cves)
        stats = _calc_stats(cves)

        pkg_result = {
            'name':         name,
            'version':      version,
            'ecosystem':    ecosystem,
            'cpe':          cpe,
            'cpe_vendor':   cpe_vendor,
            'cpe_product':  cpe_product,
            'cves':         cves[:20],
            'cve_count':    len(cves),
            'statistics':   stats,
        }
        results_per_pkg.append(pkg_result)

        # Accumulate for global stats
        for cv in cves:
            cid = cv.get('cve_id', '')
            if cid and cid not in total_unique_ids:
                total_unique_ids.add(cid)
                cv['source_package'] = name
                all_cves.append(cv)

    total_stats = _calc_stats(all_cves)

    ai_analysis = _generate_recommendations(all_cves, total_stats, context='file',
                                             software_name=filename)
    print(f"[PKG] Done — {len(packages)} packages | {len(all_cves)} unique CVEs")

    return jsonify({
        'success':         True,
        'analysis_type':   'packages',
        'filename':        filename,
        'ecosystem':       ecosystem,
        'packages':        results_per_pkg,
        'total_packages':  len(packages),
        'total_unique_cves': len(all_cves),
        'all_cves':        all_cves[:100],
        'statistics':      total_stats,
        'ai_analysis':     ai_analysis,
    })


# ── /api/search ───────────────────────────────────────────────────────────────

@app.route('/api/search', methods=['POST'])
def search_by_name():
    """Search vulnerabilities by software name + version."""
    data = request.get_json()
    if not data or 'software_name' not in data:
        return jsonify({'success': False, 'error': 'software_name is required'}), 400

    software_name = data['software_name']
    version       = data.get('version', '')

    try:
        cpe_info = cpe_extractor.extract_from_software_name(software_name, version)
        resolved_cpe = _resolve_cpe(cpe_info, software_name)
        cpe = resolved_cpe['cpe']
        vendor = resolved_cpe['vendor']
        product = resolved_cpe['product']
        version = resolved_cpe['version']
        ai_cpe = resolved_cpe['ai_cpe']
        sem_cpe = resolved_cpe['sem_cpe']
        resolution_meta = resolved_cpe['resolution']

        max_results = data.get('max_results', None)

        # Query NVD by CPE if resolved, else go straight to keyword search
        cves        = []
        data_source = 'NVD (keyword search)'
        if cpe:
            cves        = nvd_api.search_by_cpe(cpe, max_results=max_results)
            data_source = 'NVD (CPE query)'

        # Keyword fallback: CPE resolved but 0 results, OR CPE not resolved at all
        if not cves:
            kw          = f"{software_name} {version}".strip() if version else software_name
            cves        = nvd_api.search_by_keyword(kw, max_results=max_results or 50)
            data_source = 'NVD (keyword search)'
            if not cves and version:
                print(f"[SEARCH] Keyword '{kw}' returned 0 CVEs — retrying with name only: {software_name!r}")
                cves = nvd_api.search_by_keyword(software_name, max_results=max_results or 50)

        cves = _filter_cves_for_target(cves, cpe, source_label='SEARCH')
        if not cpe:
            cves = _filter_keyword_only_cves(cves, software_name, version)

        if _keyword_results_look_too_broad(cves, cpe, software_name, version):
            return jsonify({
                'success': False,
                'error': (
                    'Search term is too broad or ambiguous, so NVD results are likely to include unrelated CVEs. '
                    'Please enter a more specific product name and/or add a version/vendor.'
                ),
            })

        if not cves and not cpe:
            err = resolution_meta.get('error') or 'Could not resolve CPE or find CVEs for this software'
            return jsonify({'success': False, 'error': err})

        stats = _calc_stats(cves)
        cves  = ai_enrich_severity(cves)

        ai_analysis = _generate_recommendations(cves, stats, context='search',
                                                 software_name=f"{software_name} {version}".strip())

        return jsonify({
            'success':      True,
            'analysis_type': 'search',
            'software_info': {
                'name':    software_name,
                'version': version,
                'vendor':  vendor or resolution_meta.get('candidate_vendor', ''),
                'product': product or resolution_meta.get('candidate_product', ''),
            },
            'cpe':           cpe,
            'total_cves':    stats['total_cves'],
            'vulnerabilities': cves[:50],
            'statistics':    stats,
            'data_source':   data_source,
            'ai_cpe':        ai_cpe,
            'sem_cpe':       sem_cpe,
            'cpe_resolution': resolution_meta,
            'ai_analysis':   ai_analysis,
            'note':          f"Showing first 50 of {stats['total_cves']} CVEs"
                             if stats['total_cves'] > 50 else None,
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── /api/query-cpe ────────────────────────────────────────────────────────────

@app.route('/api/query-cpe', methods=['POST'])
def query_cpe():
    """Query CVEs by a CPE 2.3 string."""
    data = request.get_json()
    if not data or 'cpe' not in data:
        return jsonify({'success': False, 'error': 'cpe is required'}), 400

    cpe         = data['cpe']
    max_results = data.get('max_results', None)

    try:
        cves  = nvd_api.search_by_cpe(cpe, max_results=max_results)
        cves  = _filter_cves_for_target(cves, cpe, source_label='CPE')
        stats = _calc_stats(cves)
        cves  = ai_enrich_severity(cves)

        ai_analysis = _generate_recommendations(cves, stats, context='search',
                                                 software_name=cpe)

        return jsonify({
            'success':         True,
            'analysis_type':   'cpe_query',
            'cpe':             cpe,
            'total_cves':      stats['total_cves'],
            'vulnerabilities': cves[:100],
            'statistics':      stats,
            'data_source':     'NVD (direct CPE query)',
            'ai_analysis':     ai_analysis,
            'note':            f"Showing first 100 of {stats['total_cves']} CVEs"
                               if stats['total_cves'] > 100 else None,
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── /api/export-all ───────────────────────────────────────────────────────────

@app.route('/api/export-all', methods=['POST'])
def export_all():
    """Export ALL CVEs for a CPE (no pagination limit)."""
    data = request.get_json()
    if not data or 'cpe' not in data:
        return jsonify({'success': False, 'error': 'cpe is required'}), 400

    try:
        cves  = nvd_api.search_by_cpe(data['cpe'], max_results=None)
        stats = _calc_stats(cves)
        return jsonify({
            'success':         True,
            'cpe':             data['cpe'],
            'total_cves':      len(cves),
            'vulnerabilities': cves,
            'statistics':      stats,
            'data_source':     'NVD (complete export)',
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── /api/status ───────────────────────────────────────────────────────────────

@app.route('/api/status', methods=['GET'])
@app.route('/api/stats', methods=['GET'])
def get_status():
    sv = severity_status()
    return jsonify({
        'tool':             'Software Vulnerability Assessment Tool',
        'version':          '2.0',
        'nvd_api_key':      nvd_api.api_key is not None,
        'rate_limit':       '50 req/30s' if nvd_api.api_key else '5 req/30s',
        'sem_cpe_faiss':    sem_available(),
        'severity_pipeline': sv,
        'secbert_relevance': secbert_available(),
        'ember_behavioral':  ember_status(),
        'package_ecosystems': PackageAnalyzer.supported_filenames(),
        'features': {
            'pe_binary_analysis':          True,
            'package_manifest_analysis':   True,
            'software_name_search':        True,
            'direct_cpe_query':            True,
            'severity_ml_ensemble':        sv['available'],
            'semantic_cve_relevance':      secbert_available(),
            'cwe_behavior_prediction':     True,
            'ember_behavioral_scoring':    ember_available(),
        },
    })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _calc_stats(cves: list) -> dict:
    if not cves:
        return {
            'total_cves': 0,
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0},
            'avg_cvss': 0,
            'max_cvss': 0,
            'min_cvss': 0,
        }

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0}
    for cve in cves:
        sev = cve.get('severity', 'NONE')
        counts[sev] = counts.get(sev, 0) + 1

    scores = [c.get('cvss_score', 0) for c in cves if (c.get('cvss_score') or 0) > 0]
    return {
        'total_cves':  len(cves),
        'by_severity': counts,
        'avg_cvss':    round(sum(scores) / len(scores), 2) if scores else 0,
        'max_cvss':    round(max(scores), 2) if scores else 0,
        'min_cvss':    round(min(scores), 2) if scores else 0,
    }


def _impact_rank(label: str) -> int:
    return {
        'NONE': 0,
        'LOW': 1,
        'PARTIAL': 2,
        'LOW-MEDIUM': 2,
        'MEDIUM': 2,
        'HIGH': 3,
        'COMPLETE': 3,
    }.get((label or '').upper(), 0)


def _impact_label(rank: int) -> str:
    if rank >= 3:
        return 'HIGH'
    if rank >= 2:
        return 'MEDIUM'
    if rank >= 1:
        return 'LOW'
    return 'NONE'


def _highest_fix_target(cves: list) -> tuple[str, str]:
    """
    Return the highest suggested safe version among matched CVEs.

    The raw version is used for comparisons; the label is what we show in UI.
    """
    best_raw = ''
    best_label = ''
    for cve in cves:
        raw = cve.get('fixed_version') or cve.get('suggested_fix_version') or ''
        label = cve.get('fixed_version_label') or raw
        if not raw:
            continue
        if not best_raw:
            best_raw, best_label = raw, label
            continue
        try:
            if nvd_api and nvd_api.compare_versions(raw, best_raw) > 0:
                best_raw, best_label = raw, label
        except Exception:
            if raw > best_raw:
                best_raw, best_label = raw, label
    return best_raw, best_label


# ── Rule-based recommendation engine ─────────────────────────────────────────

def _generate_recommendations(cves: list, stats: dict, context: str = 'file',
                              behavioral: dict | None = None,
                              software_name: str = '',
                              ember_result: dict | None = None) -> dict | None:
    """
    Generate rule-based security recommendations from CVE data.
    No LLM required — pure logic from severity stats + description keywords.

    behavioral: dict with keys ember_result, suspicious_apis, imports_by_category,
                strings, static_risk, ai_risk, cwe_analysis —
                used when there are no CVEs but the file still shows dangerous signals.

    Returns a dict compatible with renderAiPanel() on the frontend.
    """
    no_cves = not cves and stats.get('total_cves', 0) == 0
    # If software_name is empty (software not yet identified), use a generic label
    sw      = software_name if software_name else 'this file'
    sw_label = f'[{software_name}]' if software_name else 'File'

    # ── Case: no CVEs but behavioral signals are present ────────────────────
    if no_cves:
        if not behavioral:
            return None

        ember   = behavioral.get('ember_result') or {}
        sus     = behavioral.get('suspicious_apis') or []
        by_cat  = behavioral.get('imports_by_category') or {}
        strings = behavioral.get('strings') or {}
        static_risk = behavioral.get('static_risk') or {}
        ai_risk = behavioral.get('ai_risk') or {}
        cwe_res = behavioral.get('cwe_analysis') or {}

        ember_prob  = ember.get('probability') or 0.0
        ember_avail = ember.get('available', False)
        high_sus    = [s for s in sus if s.get('risk') in ('HIGH', 'CRITICAL')]
        cwe_hits    = cwe_res.get('cve_results') or []
        predicted_cwes = cwe_res.get('predicted_cwes') or []
        risk_level  = ai_risk.get('level') or ember.get('level') or ''
        observed_categories = [str(cat) for cat in by_cat.keys() if cat]
        strong_behavior = False
        if cwe_predictor is not None:
            try:
                strong_behavior = cwe_predictor._has_strong_behavioral_evidence({
                    'imports': {
                        'suspicious': sus,
                        'by_category': by_cat,
                    },
                    'strings': strings,
                    'risk': static_risk,
                    'ember_behavioral': ember,
                })
            except Exception as _behavior_ex:
                print(f"[AI] Strong behavior check failed (non-fatal): {_behavior_ex}")

        # ── CLEAN: EMBER available + low probability + no dangerous APIs ────
        if ember_avail and ember_prob < 0.2 and not high_sus:
            return {
                'success':            True,
                'overall_risk':       'CLEAN',
                'risk_summary':       (
                    f'No CVE could be confirmed as directly applicable to {sw}. '
                    f'Current binary signals are not strong enough to reliably infer a weakness theme.'
                ),
                'top_threats':        [],
                'recommendations':    [
                    f'Verify the exact vendor/product/version of {sw} to prioritize CPE matching',
                    'Keep tracking official advisories and rescan once a more specific version is known',
                ],
                'key_attack_vectors': ['No confirmed CVE match'],
            }

        # ── LOW-signal: EMBER benign + no applicable CWE/CVE + no clear attack chain ─
        # Many legitimate desktop apps/installers still use common token/thread/memory APIs.
        if ember_avail and ember_prob < 0.2 and not cwe_hits and not strong_behavior:
            api_note = ''
            if high_sus:
                api_note = ' Some sensitive APIs appear in static analysis, but they are currently treated as auxiliary signals and are not enough to confirm an applicable CVE.'
            return {
                'success':            True,
                'overall_risk':       'LOW' if high_sus else 'CLEAN',
                'risk_summary':       (
                    f'No directly applicable CVE found for {sw}.{api_note}'
                ),
                'top_threats':        [],
                'recommendations':    [
                    f'Prioritize verifying ProductName/vendor/version to improve CVE matching accuracy for {sw}',
                    'Treat current PE signals only as manual review hints, not as confirmed CVE matches',
                ],
                'key_attack_vectors': ['Auxiliary binary signals only' if high_sus else 'No confirmed CVE match'],
            }

        high_sus    = [s for s in sus if s.get('risk') in ('HIGH', 'CRITICAL')]

        # Nothing to report → skip
        if not ember_prob and not high_sus and not risk_level:
            return None

        # Determine overall risk
        if risk_level == 'CRITICAL' or ember_prob >= 0.7:
            overall_risk = 'CRITICAL'
        elif risk_level == 'HIGH' or ember_prob >= 0.4:
            overall_risk = 'HIGH'
        elif risk_level == 'MEDIUM' or ember_prob >= 0.2 or high_sus:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'

        # Key weakness themes / evidence notes
        top_threats = []
        cwe_names = [c.get('name', '') for c in predicted_cwes]
        for cwe in predicted_cwes[:3]:
            cwe_id = cwe.get('cwe_id', '')
            name = cwe.get('name', '')
            if name:
                label = f'{name} ({cwe_id})' if cwe_id else name
                if label not in top_threats:
                    top_threats.append(label)

        for category in observed_categories[:3]:
            label = f'Observed binary signal category: {category}'
            if label not in top_threats:
                top_threats.append(label)

        if not top_threats:
            if high_sus:
                top_threats.append(
                    f'Observed {len(high_sus)} HIGH/CRITICAL PE API signal(s) requiring manual review'
                )
            else:
                top_threats.append('Behavioral hints are available, but there is still no confirmed CVE match')

        # Recommendations
        recs = [
            f'Prioritize verifying the exact vendor/product/version of {sw} to return to direct CPE/CVE matching',
            'Treat the behavior-derived CWEs/CVEs below only as research hints, not as confirmed applicable CVEs',
            'Use the predicted CWEs to search NVD/advisories/vendor changelogs in a more targeted way',
            'Review HIGH/CRITICAL imports and string patterns in the Technical Details section before drawing conclusions',
            'Only raise the conclusion level when additional evidence from software identity, version range, or an official advisory is available',
        ]

        # Summary
        if cwe_names:
            cwe_preview = ', '.join(cwe_names[:3])
            summary = (
                f'No direct CVE match for {sw}. '
                f'Behavioral analysis currently only hints at weakness themes such as {cwe_preview}; '
                'these results should be used only as exploratory guidance for the next CVE lookup step.'
            )
        elif high_sus:
            summary = (
                f'No direct CVE match for {sw}. '
                f'Detected {len(high_sus)} HIGH/CRITICAL PE signal(s), but they remain only auxiliary evidence.'
            )
        else:
            summary = (
                f'No direct CVE match for {sw}. '
                'Some behavioral/binary hints have been recorded to support the next manual review.'
            )

        vectors = ['Behavioral hint only', 'No confirmed software/version match']
        for category in observed_categories[:3]:
            note = f'Observed category: {category}'
            if note not in vectors:
                vectors.append(note)

        return {
            'success':            True,
            'overall_risk':       overall_risk,
            'risk_summary':       summary,
            'top_threats':        top_threats[:6],
            'recommendations':    recs[:8],
            'key_attack_vectors': vectors[:6],
        }

    # ── Compute effective severity: prefer BERT > NLI/ML > raw NVD ──────────
    _SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'NONE': 0}

    def _effective_severity(cve: dict) -> str:
        bert = (cve.get('bert_prediction') or {}).get('predicted_severity')
        if bert and bert in _SEV_RANK:
            return bert
        zs = (cve.get('zero_shot_prediction') or {}).get('predicted_severity')
        if zs and zs in _SEV_RANK:
            return zs
        ml = (cve.get('ml_prediction') or {}).get('predicted_severity')
        if ml and ml in _SEV_RANK:
            return ml
        return cve.get('severity', 'NONE') or 'NONE'

    eff_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0}
    for cve in cves:
        s = _effective_severity(cve)
        eff_counts[s] = eff_counts.get(s, 0) + 1

    sev      = eff_counts
    n_crit   = sev.get('CRITICAL', 0)
    n_high   = sev.get('HIGH', 0)
    n_medium = sev.get('MEDIUM', 0)
    n_low    = sev.get('LOW', 0)
    total    = len(cves)
    max_cvss = stats.get('max_cvss', 0)
    avg_cvss = stats.get('avg_cvss', 0)

    # ── Overall risk level ────────────────────────────────────────────────────
    if n_crit > 0 or max_cvss >= 9.0:
        overall_risk = 'CRITICAL'
    elif n_high > 0 or avg_cvss >= 7.0:
        overall_risk = 'HIGH'
    elif n_medium > 0 or avg_cvss >= 4.0:
        overall_risk = 'MEDIUM'
    elif total > 0:
        overall_risk = 'LOW'
    else:
        return None

    # ── Parse each CVE: threat type + CVSS vector components ────────────────
    THREAT_KEYWORDS = {
        'rce':                  ['remote code execution', 'arbitrary code', 'execute arbitrary'],
        'buffer_overflow':      ['buffer overflow', 'heap overflow', 'stack overflow', 'out-of-bounds write'],
        'privilege_escalation': ['privilege escalation', 'elevation of privilege', 'local privilege'],
        'auth_bypass':          ['authentication bypass', 'bypass authentication', 'improper authentication', 'unauthenticated'],
        'info_disclosure':      ['information disclosure', 'information exposure', 'sensitive information', 'data leak'],
        'dos':                  ['denial of service', 'denial-of-service', 'resource exhaustion'],
        'injection':            ['sql injection', 'command injection', 'code injection', 'ldap injection'],
        'xss':                  ['cross-site scripting', 'xss'],
        'path_traversal':       ['path traversal', 'directory traversal'],
        'use_after_free':       ['use after free', 'use-after-free', 'uaf'],
        'memory_corruption':    ['memory corruption', 'null pointer', 'integer overflow', 'integer underflow'],
        'crypto_weak':          ['weak encryption', 'cleartext', 'plaintext password', 'weak cipher', 'hardcoded'],
    }
    THREAT_LABELS = {
        'rce':                  'Remote Code Execution (RCE)',
        'buffer_overflow':      'Buffer Overflow',
        'privilege_escalation': 'Privilege Escalation',
        'auth_bypass':          'Authentication Bypass',
        'info_disclosure':      'Sensitive Information Disclosure',
        'dos':                  'Denial of Service (DoS)',
        'injection':            'Injection Attack (SQL/Command/Code)',
        'xss':                  'Cross-Site Scripting (XSS)',
        'path_traversal':       'Path Traversal / Directory Traversal',
        'use_after_free':       'Use-After-Free (UAF) Memory Bug',
        'memory_corruption':    'Memory Corruption / Integer Overflow',
        'crypto_weak':          'Weak Cryptography / Plaintext Password Storage',
    }

    def _parse_cvss_vec(vec: str) -> dict:
        """Parse a CVSS v3 vector string into a dict of components."""
        parts = {}
        for seg in vec.split('/'):
            if ':' in seg:
                k, v = seg.split(':', 1)
                parts[k] = v
        return parts

    # threat → list of (cve_id, cvss, vec_parsed, desc_snippet)
    threat_cve_map: dict[str, list] = {t: [] for t in THREAT_KEYWORDS}

    all_vecs_parsed: list[dict] = []
    for cve in cves:
        desc    = (cve.get('description') or '')
        desc_lo = desc.lower()
        cve_id  = cve.get('cve_id', '')
        cvss    = float(cve.get('cvss_score') or 0)
        vec_str = (cve.get('vector_string') or '').upper()
        vec_p   = _parse_cvss_vec(vec_str)
        all_vecs_parsed.append(vec_p)
        # snippet: first sentence of the description, up to 120 characters
        snippet = desc[:120].rsplit(' ', 1)[0] + '…' if len(desc) > 120 else desc
        for threat, keywords in THREAT_KEYWORDS.items():
            if any(kw in desc_lo for kw in keywords):
                threat_cve_map[threat].append((cve_id, cvss, vec_p, snippet))

    for t in threat_cve_map:
        threat_cve_map[t].sort(key=lambda x: x[1], reverse=True)

    detected_threats = {t for t, lst in threat_cve_map.items() if lst}

    # Aggregate CVSS component stats
    def _any_vec(key: str, val: str) -> bool:
        return any(v.get(key) == val for v in all_vecs_parsed)

    has_network_vector  = _any_vec('AV', 'N')
    has_local_vector    = _any_vec('AV', 'L')
    has_no_priv         = _any_vec('PR', 'N')   # no auth required to exploit
    has_user_interact   = _any_vec('UI', 'R')   # user click/open required
    has_no_ui           = _any_vec('UI', 'N')   # fully automated, no user interaction
    has_low_complexity  = _any_vec('AC', 'L')   # easy to exploit
    has_conf_impact     = _any_vec('C',  'H')   # severe information disclosure
    has_integ_impact    = _any_vec('I',  'H')   # severe data tampering
    has_avail_impact    = _any_vec('A',  'H')   # causes downtime

    # ── Top CVEs (most critical) ──────────────────────────────────────────────
    top_cves = sorted(cves, key=lambda c: (
        {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1}.get(_effective_severity(c), 0),
        float(c.get('cvss_score') or 0)
    ), reverse=True)[:3]

    def _cve_tag(cve: dict) -> str:
        return f"{cve.get('cve_id','')} (CVSS {cve.get('cvss_score') or 'N/A'})"

    # ── Build top threats with CVE ID + exploitation context ─────────────────
    top_threats = []
    for t in THREAT_LABELS:
        if t not in detected_threats:
            continue
        entries  = threat_cve_map[t][:2]
        cve_refs = ', '.join(f"{cid} (CVSS {sc:.1f})" for cid, sc, _, _ in entries if cid)
        # Add exploitation context from that CVE's CVSS vector
        vec_ctx  = ''
        if entries:
            vp = entries[0][2]
            if vp.get('PR') == 'N':
                vec_ctx = ' — no authentication required'
            elif vp.get('AC') == 'L':
                vec_ctx = ' — easy to exploit'
        label = THREAT_LABELS[t]
        top_threats.append(f"{label}{vec_ctx} — {cve_refs}" if cve_refs else label)

    if not top_threats:
        for cve in top_cves:
            top_threats.append(
                f"{cve.get('cve_id','')} — CVSS {cve.get('cvss_score','N/A')} "
                f"({_effective_severity(cve)})"
            )

    # ── Build recommendations — tailored per CVE + CVSS vector ──────────────
    recs = []

    # R1: Update — include the most dangerous CVE + exploitability level
    top_cve_str = ', '.join(_cve_tag(c) for c in top_cves)
    if overall_risk in ('CRITICAL', 'HIGH'):
        msg = f'Update {sw} to the latest version immediately'
        if top_cve_str:
            msg += f' — patch now: {top_cve_str}'
        if has_low_complexity and has_no_priv:
            msg += ' (no authentication required and easy to exploit automatically)'
        recs.append(msg)
    else:
        recs.append(f'Plan an update for {sw} — {top_cve_str}')

    # R2: Network — only when a network vector is actually present
    if has_network_vector:
        net_cves = [cid for cid, _, vp, _ in
                    sorted([(e[0],e[1],e[2],e[3]) for t in detected_threats
                            for e in threat_cve_map[t] if e[2].get('AV')=='N'],
                           key=lambda x: x[1], reverse=True)[:2]]
        msg = f'Isolate {sw} from the network'
        if has_no_priv and has_no_ui:
            msg += ' — vulnerability can be exploited remotely and fully automatically (PR:N, UI:N)'
        elif has_no_priv:
            msg += ' — no authentication required to attack over the network'
        if net_cves:
            msg += f' ({", ".join(net_cves)})'
        recs.append(msg)
    elif has_local_vector:
        lc = [cid for cid, _, vp, _ in
              [e for t in detected_threats for e in threat_cve_map[t]]
              if _.get('AV') == 'L'][:1] if False else []
        recs.append(f'Restrict local access to {sw} — vulnerability is exploited via local access')

    # R3: User interaction — if a user click is required
    if has_user_interact:
        ui_cves = ', '.join(
            cid for cid, sc, vp, _ in
            sorted([e for t in detected_threats for e in threat_cve_map[t]
                    if e[2].get('UI') == 'R'], key=lambda x: x[1], reverse=True)[:2]
            if cid
        )
        msg = f'Warn users not to open untrusted files/links from {sw}'
        if ui_cves:
            msg += f' ({ui_cves} require user interaction to exploit)'
        recs.append(msg)

    # R4: Privilege escalation
    if 'privilege_escalation' in detected_threats:
        pe_cid, pe_cvss, pe_vec, pe_snip = threat_cve_map['privilege_escalation'][0]
        msg = f'Run {sw} with least privilege — {pe_cid} (CVSS {pe_cvss:.1f}) enables privilege escalation'
        recs.append(msg)

    # R5: Auth bypass
    if 'auth_bypass' in detected_threats:
        ab_cid = threat_cve_map['auth_bypass'][0][0]
        recs.append(f'Review and patch the authentication mechanism of {sw} ({ab_cid}), roll out MFA where possible')

    # R6: Memory issues — specific per sub-type
    mem_types = []
    if 'buffer_overflow' in detected_threats: mem_types.append('buffer overflow')
    if 'use_after_free'  in detected_threats: mem_types.append('use-after-free')
    if 'memory_corruption' in detected_threats: mem_types.append('memory corruption')
    if mem_types:
        mem_all = sorted(
            [e for t in ['buffer_overflow','use_after_free','memory_corruption']
             for e in threat_cve_map.get(t, [])],
            key=lambda x: x[1], reverse=True
        )
        mem_cids = ', '.join(e[0] for e in mem_all[:2] if e[0])
        recs.append(
            f'Enable DEP/ASLR/Stack Canary on systems running {sw}'
            f' — detected {", ".join(mem_types)}'
            + (f' ({mem_cids})' if mem_cids else '')
        )

    # R7: Data impact — confidentiality/integrity
    if has_conf_impact or has_integ_impact:
        impacts = []
        if has_conf_impact:  impacts.append('data exposure (C:H)')
        if has_integ_impact: impacts.append('data tampering (I:H)')
        recs.append(f'Back up data related to {sw} and monitor for anomalies — risks: {", ".join(impacts)}')

    # R8: Availability — DoS or A:H
    if 'dos' in detected_threats or has_avail_impact:
        dos_cid = (threat_cve_map['dos'][0][0] if threat_cve_map.get('dos') else '')
        msg = f'Prepare failover/redundancy plans for {sw}'
        if dos_cid:
            msg += f' — {dos_cid} may cause service disruption'
        recs.append(msg)

    # R9: Crypto
    if 'crypto_weak' in detected_threats:
        cr_cid = threat_cve_map['crypto_weak'][0][0]
        recs.append(f'Replace weak cryptographic algorithms in {sw} ({cr_cid}) and check for hardcoded passwords')

    # R10: Injection / path traversal / XSS
    if 'injection' in detected_threats or 'path_traversal' in detected_threats or 'xss' in detected_threats:
        inj_types = [THREAT_LABELS[t].split('(')[0].strip()
                     for t in ['injection','path_traversal','xss'] if t in detected_threats]
        recs.append(f'Sanitize all inputs to {sw} and apply whitelist validation — detected: {", ".join(inj_types)}')

    highest_fix_raw, highest_fix_label = _highest_fix_target(cves)
    if highest_fix_label:
        recs.append(
            f'Read release notes and test module/dependency compatibility before upgrading {sw} to {highest_fix_label}'
        )

    # Always include: advisory + validation for file context
    recs.append(f'Track security advisories for {sw}: https://nvd.nist.gov/vuln/search')
    if context == 'file':
        recs.append(f'Test {sw} in a staging or isolated environment before deploying to production')

    def _is_network_cve(cve: dict) -> bool:
        attack_vector = (cve.get('attack_vector') or '').upper()
        vec = (cve.get('vector_string') or '').upper()
        return attack_vector in ('NETWORK', 'ADJACENT_NETWORK') or 'AV:N' in vec

    def _is_no_auth_cve(cve: dict) -> bool:
        privs = (cve.get('privileges_required') or '').upper()
        vec = (cve.get('vector_string') or '').upper()
        return privs in ('NONE', 'N') or 'PR:N' in vec or 'AU:N' in vec

    kev_cves = [c for c in cves if c.get('known_exploited')]
    exploit_cves = [c for c in cves if c.get('has_public_exploit')]
    remote_unauth_cves = [c for c in cves if _is_network_cve(c) and _is_no_auth_cve(c)]

    cia_conf = _impact_label(max(_impact_rank(c.get('confidentiality_impact')) for c in cves))
    cia_integ = _impact_label(max(_impact_rank(c.get('integrity_impact')) for c in cves))
    cia_avail = _impact_label(max(_impact_rank(c.get('availability_impact')) for c in cves))

    decision_reasons = []
    if kev_cves:
        decision_reasons.append(f'{len(kev_cves)} CVE already in the CISA KEV catalog (actively exploited in the wild)')
    if exploit_cves:
        decision_reasons.append(f'{len(exploit_cves)} CVE(s) have references tagged Exploit/PoC on NVD')
    if remote_unauth_cves:
        decision_reasons.append(f'{len(remote_unauth_cves)} CVE(s) exploitable over the network without authentication')
    if max_cvss >= 9.0:
        decision_reasons.append(f'At least one CVE reaches CVSS {max_cvss:.1f}')
    if cia_conf == 'HIGH' or cia_integ == 'HIGH' or cia_avail == 'HIGH':
        decision_reasons.append(
            f'High CIA impact: C={cia_conf}, I={cia_integ}, A={cia_avail}'
        )

    if kev_cves or (remote_unauth_cves and (n_crit > 0 or max_cvss >= 9.0)):
        update_action = 'UPDATE NOW'
        update_priority = 'Immediate'
    elif exploit_cves or n_crit > 0 or max_cvss >= 9.0:
        update_action = 'UPDATE SOON'
        update_priority = 'High'
    elif n_high > 0 or n_medium > 0:
        update_action = 'PLAN UPDATE'
        update_priority = 'Scheduled'
    else:
        update_action = 'MONITOR'
        update_priority = 'Routine'

    top_decision_cves = [
        {
            'cve_id': c.get('cve_id', ''),
            'severity': _effective_severity(c),
            'cvss_score': c.get('cvss_score'),
            'known_exploited': c.get('known_exploited', False),
            'has_public_exploit': c.get('has_public_exploit', False),
            'affected_range': c.get('affected_range', ''),
            'fixed_version': c.get('fixed_version', '') or c.get('suggested_fix_version', ''),
            'fixed_version_label': c.get('fixed_version_label', '') or c.get('fixed_version', '') or c.get('suggested_fix_version', ''),
        }
        for c in top_cves
    ]

    decision_summary = []
    decision_summary.append(
        f'Decision: {update_action}. Priority {update_priority.lower()} based on CVSS, exploitation status, and the impact scope of the current version.'
    )
    if avg_cvss:
        decision_summary.append(f'The average CVSS across the current CVE set is {avg_cvss:.1f}.')
    if highest_fix_label:
        decision_summary.append(f'Safe patched version to target: {highest_fix_label}.')
    if decision_reasons:
        decision_summary.append('Main reasons: ' + '; '.join(decision_reasons[:4]) + '.')

    compatibility_checks = [
        {
            'title': 'Dependency / Module Compatibility',
            'status': 'STAGING',
            'detail': (
                f'Validate plugins/modules/dependencies related to {sw} on staging before upgrading'
                + (f' to {highest_fix_label}' if highest_fix_label else '.')
            ),
        },
        {
            'title': 'Configuration Change Review',
            'status': 'REVIEW',
            'detail': 'Read release notes and advisories to catch any configuration, service, policy, port, or migration changes bundled with the patch.',
        },
        {
            'title': 'Community Regression Check',
            'status': 'WATCH',
            'detail': 'Cross-check GitHub issues, vendor forums, and the changelog to see whether the patch breaks other modules or may require a rollback.',
        },
    ]

    # ── Key attack vectors — more detail derived from CVSS ───────────────────
    vectors = []
    if has_network_vector:
        v = 'Network — Remote'
        if has_no_priv and has_no_ui:  v += ' (unauthenticated, no user action needed)'
        elif has_no_priv:              v += ' (no authentication required)'
        vectors.append(v)
    if has_local_vector:
        vectors.append('Local Access' + (' (no auth)' if has_no_priv else ''))
    if _any_vec('AV', 'A'):
        vectors.append('Adjacent Network')
    if _any_vec('AV', 'P'):
        vectors.append('Physical Access')
    for threat in ['rce', 'injection', 'privilege_escalation', 'auth_bypass']:
        if threat in detected_threats:
            vectors.append(THREAT_LABELS[threat].split('(')[0].strip())
    if not vectors:
        vectors = ['Unknown']

    # ── Risk summary ─────────────────────────────────────────────────────────
    parts = []
    if n_crit:   parts.append(f'{n_crit} CRITICAL')
    if n_high:   parts.append(f'{n_high} HIGH')
    if n_medium: parts.append(f'{n_medium} MEDIUM')
    if n_low:    parts.append(f'{n_low} LOW')
    sev_str = ', '.join(parts) if parts else f'{total} CVE'

    # Add binary-signal context if present — clarifies that the file is clean but the software has vulnerabilities
    ember_ctx = ''
    if ember_result and ember_result.get('available') and ember_result.get('probability') is not None:
        prob  = ember_result['probability']
        label = ember_result.get('label', 'BENIGN')
        if prob < 0.2:
            ember_ctx = (f' (Binary signal note: EMBER auxiliary review stayed {label} at {prob:.0%}. '
                         f'The CVEs below are still software vulnerabilities of {sw_label}, not a verdict that the file itself is malicious.)')
        elif prob >= 0.5:
            ember_ctx = f' (Binary signal note: EMBER auxiliary review is elevated at {prob:.0%}; distinguish clearly between this binary signal and the software CVE match.)'

    if overall_risk == 'CRITICAL':
        summary = (f'{sw_label} has {total} CVE(s) ({sev_str}). '
                   f'EXTREMELY DANGEROUS — do not use in production until patched.{ember_ctx}')
    elif overall_risk == 'HIGH':
        summary = (f'{sw_label} has {total} CVE(s) ({sev_str}). '
                   f'High risk level — patch as soon as possible.{ember_ctx}')
    elif overall_risk == 'MEDIUM':
        summary = (f'{sw_label} has {total} CVE(s) ({sev_str}). '
                   f'Medium risk — update and keep monitoring regularly.{ember_ctx}')
    else:
        summary = (f'{sw_label} has {total} CVE(s) ({sev_str}). '
                   f'Low risk — update on a normal schedule.{ember_ctx}')

    return {
        'success':           True,
        'overall_risk':      overall_risk,
        'risk_summary':      summary,
        'top_threats':       top_threats[:6],
        'recommendations':   recs[:8],
        'key_attack_vectors': list(dict.fromkeys(vectors))[:8],  # dedup, preserve order
        'update_decision': {
            'action': update_action,
            'priority': update_priority,
            'summary': ' '.join(decision_summary),
            'reasons': decision_reasons[:6],
            'recommended_version': highest_fix_raw,
            'recommended_version_label': highest_fix_label or highest_fix_raw,
            'avg_cvss': avg_cvss,
            'kev_count': len(kev_cves),
            'public_exploit_count': len(exploit_cves),
            'remote_no_auth_count': len(remote_unauth_cves),
            'cia': {
                'confidentiality': cia_conf,
                'integrity': cia_integ,
                'availability': cia_avail,
            },
            'top_cves': top_decision_cves[:3],
            'compatibility_checks': compatibility_checks,
            'review_checks': [
                'Review configuration changes and migration/patch scripts before deploying',
                'Validate module/plugin/dependency compatibility on staging',
                'Cross-check community feedback or issue trackers if the patch was just released',
                'Re-test core business flows after the update before promoting to production',
            ],
        },
    }


# ── Backward-compat alias (kept for any existing clients) ─────────────────────
@app.route('/api/pe-analyze', methods=['POST'])
@app.route('/api/scan', methods=['POST'])
def legacy_scan():
    """Backward-compatible alias → delegates to /api/analyze."""
    return analyze_file()


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print()
    print("Dashboard : http://localhost:5000")
    print()
    print("Endpoints :")
    print("  POST /api/analyze         - Analyze PE binary or package manifest")
    print("  POST /api/search          - Search by software name")
    print("  POST /api/query-cpe       - Query by CPE string")
    print("  POST /api/export-all      - Export ALL CVEs")
    print("  GET  /api/status          - System status")
    print()
    app.run(debug=True, host='0.0.0.0', port=5000)
