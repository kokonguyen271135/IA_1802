"""
Software Vulnerability Assessment Tool
Flask Web Server

Thesis: Nghiên cứu và Phát triển Công cụ Đánh giá Lỗ hổng Phần mềm
        kết hợp AI và Cơ sở Dữ liệu CVE

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

    # NVD API key (set here or via NVD_API_KEY env var)
    API_KEY = "c95dd30e-7d9f-48b7-b9b9-0e799b0cd859"
    api_key = API_KEY or os.getenv('NVD_API_KEY')

    if not api_key:
        print("[!] WARNING: No NVD API key — queries will be slow (5 req/30s)")

    nvd_api       = NVDAPIv2(api_key)
    cpe_extractor = CPEExtractor()
    pe_analyzer   = PEStaticAnalyzer()
    pkg_analyzer  = PackageAnalyzer()
    cwe_predictor = CWEPredictor(nvd_api)

    print("[+] NVD API v2 initialized")
    print("[+] CPE Extractor initialized")
    print("[+] PE Static Analyzer initialized")
    print("[+] Package Analyzer initialized")
    print("[+] CWE Predictor initialized (Hướng 3)")
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


def _resolve_cpe(cpe_info: dict, filename: str) -> tuple[str, str, str, str, dict, dict]:
    """
    Attempt to resolve a CPE using AI and FAISS fallback.
    Returns (cpe, vendor, product, version, ai_cpe_result, sem_cpe_result).
    """
    cpe     = cpe_info.get('cpe')
    vendor  = cpe_info.get('vendor', '')
    product = cpe_info.get('product', '')
    version = cpe_info.get('version', '')
    extraction_method = cpe_info.get('extraction_method', '')

    sem_cpe_result = None

    # Use FAISS when: explicit fallback modes OR pe_version_info gave unknown/generic vendor
    _generic_vendors = {'unknown', 'microsoft_corporation', ''}
    needs_sem = (
        extraction_method in ('generic_fallback', 'filename_pattern', 'manual_input')
        or (extraction_method == 'pe_version_info' and vendor in _generic_vendors)
        or not cpe
    )

    if needs_sem:
        file_meta  = cpe_info.get('file_info', {})
        query_name = (
            file_meta.get('ProductName') or product or filename or ''
        ).strip()

        if sem_available() and query_name:
            sem_cpe_result = sem_match_best(query_name, min_score=0.50)
            if sem_cpe_result and \
               sem_cpe_result.get('confidence') in ('high', 'medium'):
                vendor  = sem_cpe_result['vendor']
                product = sem_cpe_result['product']
                cpe     = cpe_extractor._build_cpe(vendor, product, version or '')

    return cpe, vendor, product, version, None, sem_cpe_result


def _compute_ai_risk_score(cves: list, ember_result: dict | None = None) -> dict | None:
    """
    AI Risk Score — driven entirely by EMBER XGBoost behavioral scoring.
    EMBER probability (0→1) maps directly to score (0→100).
    CVE info appended as context factors only.
    """
    if not ember_result and not cves:
        return None

    factors = []

    # ── EMBER là nguồn chính — map probability 0→1 thành score 0→100 ──────────
    if ember_result and ember_result.get('available') and ember_result.get('probability') is not None:
        prob  = ember_result['probability']
        score = min(100, round(prob * 100))
        label = ember_result.get('label', '')
        lvl   = ember_result.get('level', '')
        factors.append(f"EMBER ML: {prob:.1%} malware probability → {label}")
        factors.append(f"Model: XGBoost trained on EMBER 2017 (600K  samples, AUC=0.9994)")
    elif cves:
        # Fallback khi EMBER không available — dùng CVSS
        cvss_scores = [c.get('cvss_score') or 0 for c in cves]
        avg_cvss    = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        score = min(100, round((avg_cvss / 10) * 100))
        factors.append(f"Average CVSS score: {avg_cvss:.1f} (EMBER not available)")
    else:
        return None

    # ── CVE context (thông tin bổ sung, không ảnh hưởng điểm) ────────────────
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
        cpe, vendor, product, version, ai_cpe, sem_cpe = \
            _resolve_cpe(cpe_info, filename)

        result['ai_cpe']  = ai_cpe
        result['sem_cpe'] = sem_cpe
        result['cpe']     = cpe
        result['cpe_info'] = {
            'vendor':   vendor,
            'product':  product,
            'version':  version,
            'extraction_method': cpe_info.get('extraction_method', ''),
        }

        # ── 3. CVE lookup ─────────────────────────────────────────────────────
        if cpe:
            print(f"[PE] Querying NVD: {cpe}")
            cves = nvd_api.search_by_cpe(cpe, max_results=50)
            # Keyword fallback: nếu CPE trả về 0 (vendor mismatch),
            # thử lại với keyword "product version"
            if not cves and product and version:
                kw = f"{product} {version}".strip()
                print(f"[PE] CPE returned 0 CVEs — retrying with keyword: {kw!r}")
                cves = nvd_api.search_by_keyword(kw, max_results=50)
            elif not cves and product:
                print(f"[PE] CPE returned 0 CVEs — retrying with keyword: {product!r}")
                cves = nvd_api.search_by_keyword(product, max_results=50)
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
            # Không có CVE nhưng vẫn có EMBER score → tính ai_risk từ EMBER
            ai_risk = _compute_ai_risk_score([], ember_result)
            if ai_risk:
                result['ai_risk'] = ai_risk

    except Exception as e:
        print(f"[PE] CPE/CVE step error: {e}")
        result['cpe_error'] = str(e)

    # ── Hướng 3: CWE Behavior Prediction ─────────────────────────────────────
    # Gate: chỉ chạy khi file có dấu hiệu nguy hiểm thực sự.
    # Điều kiện: EMBER >= 30% HOẶC có ít nhất 1 suspicious API detected.
    # File clean (EMBER thấp + không có suspicious API) → skip, tránh CVE ảo.
    try:
        _ember_prob   = (ember_result.get('probability') or 0.0)
        _suspicious   = result.get('imports', {}).get('suspicious', [])
        # Chỉ tính suspicious API risk HIGH hoặc CRITICAL — MEDIUM quá phổ biến
        # Key đúng là 'function' (từ static_analyzer), không phải 'api'
        _high_risk    = [s for s in _suspicious if s.get('function') and s.get('risk') in ('HIGH', 'CRITICAL')]
        _has_behavior = len(_high_risk) > 0
        _ember_sus    = _ember_prob >= 0.50

        # Nếu đã có CPE rõ ràng (vendor/product xác định được) → không cần Hướng 3
        # Hướng 3 chỉ dành cho file không biết là phần mềm gì
        _cpe_info = result.get('cpe_info') or {}
        _has_definite_cpe = bool(
            _cpe_info.get('vendor') and
            _cpe_info.get('product') and
            _cpe_info.get('vendor').lower() not in ('unknown', 'n/a', '') and
            _cpe_info.get('product').lower() not in ('unknown', 'n/a', '')
        )

        if _suspicious:
            print(f"[PE] Suspicious APIs: {[(s.get('function'), s.get('risk')) for s in _suspicious]}")
        if _has_definite_cpe:
            print(f"[PE] Skipping CWE prediction — CPE identified: "
                  f"{_cpe_info.get('vendor')}:{_cpe_info.get('product')} "
                  f"(Hướng 3 only for unknown software)")
        elif not _ember_sus and not _has_behavior:
            print(f"[PE] Skipping CWE prediction — EMBER={_ember_prob:.1%} BENIGN, "
                  f"no HIGH/CRITICAL suspicious APIs (medium_only={len(_suspicious)})")
        else:
            print(f"[PE] Running CWE behavior prediction "
                  f"(EMBER={_ember_prob:.1%}, suspicious_apis={len(_high_risk)})")
            cwe_result = cwe_predictor.predict_and_fetch(result)
            result['cwe_analysis'] = cwe_result

            if cwe_result.get('cve_results'):
                cwe_cves = cwe_result['cve_results']
                print(f"[PE][CWE] Raw CVEs from Huong 3: {len(cwe_cves)}")

                cwe_cves = _enrich_cves(cwe_cves, result)
                print(f"[PE][CWE] After enrich: {len(cwe_cves)}")

                # Chọn lọc: sort by relevance score DESC, giữ top 10
                cwe_cves.sort(
                    key=lambda c: (
                        c.get('relevance', {}).get('score', 0.0),
                        c.get('cvss_score') or 0.0,
                    ),
                    reverse=True,
                )
                cwe_cves = cwe_cves[:10]
                print(f"[PE][CWE] After top-10 selection: {len(cwe_cves)}")

                existing = result.get('vulnerabilities', [])
                existing_ids = {c.get('cve_id') for c in existing}
                new_cves = [c for c in cwe_cves if c.get('cve_id') not in existing_ids]
                print(f"[PE][CWE] New (dedup): {len(new_cves)}")

                if not existing:
                    # Không có CVE từ CPE → dùng hoàn toàn Hướng 3
                    result['vulnerabilities'] = cwe_cves[:50]
                    result['cve_statistics']  = _calc_stats(cwe_cves)
                    result['cve_source']      = 'cwe_behavior_prediction'
                elif new_cves:
                    # Có CVE từ CPE → chỉ merge CVE có relevance score >= 0.4
                    high_rel_new = [
                        c for c in new_cves
                        if c.get('relevance', {}).get('score', 0.0) >= 0.4
                    ]
                    print(f"[PE][CWE] Merge candidates (relevance>=0.4): {len(high_rel_new)} "
                          f"(dropped {len(new_cves) - len(high_rel_new)})")
                    if high_rel_new:
                        merged = existing + high_rel_new
                        merged.sort(
                            key=lambda c: (
                                c.get('relevance', {}).get('score', 0.0),
                                c.get('cvss_score', 0.0),
                            ),
                            reverse=True,
                        )
                        result['vulnerabilities'] = merged[:50]
                        result['cve_statistics']  = _calc_stats(merged)
                        result['cve_source']      = 'cpe_and_cwe_behavior'
                    else:
                        print(f"[PE][CWE] No high-relevance CVEs to merge — keeping existing")
                else:
                    print(f"[PE][CWE] No new CVEs after dedup — keeping existing")

                ai_risk = _compute_ai_risk_score(result['vulnerabilities'], ember_result)
                if ai_risk:
                    result['ai_risk'] = ai_risk
    except Exception as e:
        import traceback
        print(f"[PE] CWE prediction error: {e}")
        print(traceback.format_exc())

    # ── Rule-based recommendations ────────────────────────────────────────────
    pe_cves  = result.get('vulnerabilities', [])
    pe_stats = result.get('cve_statistics') or _calc_stats(pe_cves)
    # Chỉ dùng tên phần mềm khi CPE được xác định rõ ràng
    # Hướng 3 (behavioral, no CPE) → không đặt tên, tránh gây nhầm lẫn
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
        cpe, vendor, product, version, ai_cpe, sem_cpe = \
            _resolve_cpe(cpe_info, software_name)

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

        if not cves and not cpe:
            return jsonify({'success': False, 'error': 'Could not resolve CPE or find CVEs for this software'})

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
                'vendor':  vendor,
                'product': product,
            },
            'cpe':           cpe,
            'total_cves':    stats['total_cves'],
            'vulnerabilities': cves[:50],
            'statistics':    stats,
            'data_source':   data_source,
            'ai_cpe':        ai_cpe,
            'sem_cpe':       sem_cpe,
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


# ── Rule-based recommendation engine ─────────────────────────────────────────

def _generate_recommendations(cves: list, stats: dict, context: str = 'file',
                              behavioral: dict | None = None,
                              software_name: str = '',
                              ember_result: dict | None = None) -> dict | None:
    """
    Generate rule-based security recommendations from CVE data.
    No LLM required — pure logic from severity stats + description keywords.

    behavioral: dict với keys ember_result, suspicious_apis, ai_risk, cwe_analysis
                dùng khi không có CVE nhưng file vẫn có dấu hiệu nguy hiểm.

    Returns a dict compatible with renderAiPanel() on the frontend.
    """
    no_cves = not cves and stats.get('total_cves', 0) == 0
    # Nếu software_name rỗng (chưa xác định được phần mềm), dùng label chung
    sw      = software_name if software_name else 'file này'
    sw_label = f'[{software_name}]' if software_name else 'File'

    # ── Trường hợp không có CVE nhưng có behavioral signals ─────────────────
    if no_cves:
        if not behavioral:
            return None

        ember   = behavioral.get('ember_result') or {}
        sus     = behavioral.get('suspicious_apis') or []
        ai_risk = behavioral.get('ai_risk') or {}
        cwe_res = behavioral.get('cwe_analysis') or {}

        ember_prob  = ember.get('probability') or 0.0
        ember_avail = ember.get('available', False)
        high_sus    = [s for s in sus if s.get('risk') in ('HIGH', 'CRITICAL')]

        # ── CLEAN: EMBER available + xác suất thấp + không có API nguy hiểm ─
        if ember_avail and ember_prob < 0.2 and not high_sus:
            return {
                'success':            True,
                'overall_risk':       'CLEAN',
                'risk_summary':       (
                    f'{sw} không có CVE đã biết và EMBER ML đánh giá xác suất malware '
                    f'chỉ {ember_prob:.0%} — không phát hiện mối đe dọa.'
                ),
                'top_threats':        [],
                'recommendations':    [
                    f'Tiếp tục theo dõi các bản cập nhật bảo mật cho {sw}',
                    'Duy trì thói quen quét định kỳ khi có phiên bản mới',
                ],
                'key_attack_vectors': ['None detected'],
            }

        ember_prob  = ember.get('probability') or 0.0
        ember_label = ember.get('label', '')
        risk_level  = ai_risk.get('level') or ember.get('level') or ''
        high_sus    = [s for s in sus if s.get('risk') in ('HIGH', 'CRITICAL')]

        # Không có gì → bỏ qua
        if not ember_prob and not high_sus and not risk_level:
            return None

        # Xác định overall risk
        if risk_level == 'CRITICAL' or ember_prob >= 0.7:
            overall_risk = 'CRITICAL'
        elif risk_level == 'HIGH' or ember_prob >= 0.4:
            overall_risk = 'HIGH'
        elif risk_level == 'MEDIUM' or ember_prob >= 0.2 or high_sus:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'

        # Top threats từ suspicious APIs
        top_threats = []
        api_names   = [s.get('function', '').lower() for s in high_sus]
        if any(k in n for n in api_names for k in ('createremotethread', 'virtualallocex', 'writeprocessmemory')):
            top_threats.append('Injection vào tiến trình khác (Process Injection)')
        if any(k in n for n in api_names for k in ('regsetvalue', 'regopenkey', 'regcreatekey')):
            top_threats.append('Chỉnh sửa Registry (Persistence)')
        if any(k in n for n in api_names for k in ('internet', 'urldownload', 'httpsend', 'wsasend', 'socket')):
            top_threats.append('Kết nối mạng ẩn / Download payload từ C2')
        if any(k in n for n in api_names for k in ('createservice', 'openscmanager')):
            top_threats.append('Cài đặt Service ẩn (Persistence / Privilege Escalation)')
        if any(k in n for n in api_names for k in ('cryptencrypt', 'cryptacquire')):
            top_threats.append('Mã hóa dữ liệu (khả năng Ransomware)')
        if any(k in n for n in api_names for k in ('findwindow', 'getforegroundwindow', 'keybd_event')):
            top_threats.append('Theo dõi input / Keylogger')

        cwe_names = [c.get('name', '') for c in (cwe_res.get('top_cwes') or [])]
        for name in cwe_names:
            if name and name not in top_threats:
                top_threats.append(f'CWE dự đoán: {name}')

        if not top_threats:
            top_threats.append(f'EMBER ML phát hiện dấu hiệu malware ({ember_prob:.0%} probability)')

        # Recommendations
        recs = []
        if overall_risk in ('CRITICAL', 'HIGH'):
            recs.append('KHÔNG chạy file này trên hệ thống thật — khả năng cao là malware')
            recs.append('Phân tích trong môi trường sandbox cô lập (FlareVM, Any.run, Cuckoo)')
        else:
            recs.append('Chạy file trong môi trường sandbox/VM trước khi sử dụng')

        if any('injection' in t.lower() or 'process' in t.lower() for t in top_threats):
            recs.append('Giám sát tiến trình hệ thống, phát hiện process injection')
        if any('mạng' in t or 'c2' in t.lower() for t in top_threats):
            recs.append('Cô lập hoàn toàn khỏi mạng, chặn outbound connection')
        if any('registry' in t.lower() or 'service' in t.lower() for t in top_threats):
            recs.append('Kiểm tra Registry và Services sau khi chạy file (Autoruns)')
        if any('ransomware' in t.lower() or 'mã hóa' in t.lower() for t in top_threats):
            recs.append('Backup dữ liệu ngay, chuẩn bị phục hồi nếu bị mã hóa')

        recs.append('Quét bằng nhiều engine AV (VirusTotal) trước khi triển khai')
        recs.append('Báo cáo file cho bộ phận bảo mật để phân tích thêm')

        # Summary
        if ember_prob:
            summary = (f'EMBER ML đánh giá xác suất malware: {ember_prob:.0%} ({ember_label}). '
                       f'Không tìm thấy CVE cụ thể nhưng file có hành vi đáng ngờ.')
        else:
            summary = (f'Phát hiện {len(high_sus)} API đáng ngờ mức HIGH/CRITICAL. '
                       f'Không tìm thấy CVE cụ thể nhưng cần kiểm tra kỹ.')

        vectors = []
        if any('mạng' in t or 'c2' in t.lower() for t in top_threats):
            vectors.append('Network (C2/Download)')
        if any('injection' in t.lower() for t in top_threats):
            vectors.append('Process Injection')
        if any('service' in t.lower() or 'registry' in t.lower() for t in top_threats):
            vectors.append('Persistence (Registry/Service)')
        if not vectors:
            vectors = ['Unknown / Behavioral']

        return {
            'success':            True,
            'overall_risk':       overall_risk,
            'risk_summary':       summary,
            'top_threats':        top_threats[:6],
            'recommendations':    recs[:8],
            'key_attack_vectors': vectors[:6],
        }

    # ── Tính effective severity: ưu tiên BERT > NLI/ML > NVD gốc ────────────
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

    # ── Parse từng CVE: threat type + CVSS vector components ────────────────
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
        'rce':                  'Thực thi mã từ xa (Remote Code Execution)',
        'buffer_overflow':      'Tràn bộ đệm (Buffer Overflow)',
        'privilege_escalation': 'Leo thang đặc quyền (Privilege Escalation)',
        'auth_bypass':          'Bypass xác thực (Authentication Bypass)',
        'info_disclosure':      'Rò rỉ thông tin nhạy cảm (Information Disclosure)',
        'dos':                  'Từ chối dịch vụ (Denial of Service)',
        'injection':            'Tấn công Injection (SQL/Command/Code)',
        'xss':                  'Cross-Site Scripting (XSS)',
        'path_traversal':       'Path Traversal / Directory Traversal',
        'use_after_free':       'Lỗi bộ nhớ Use-After-Free (UAF)',
        'memory_corruption':    'Hỏng bộ nhớ (Memory Corruption / Integer Overflow)',
        'crypto_weak':          'Mã hóa yếu / Lưu mật khẩu dạng plaintext',
    }

    def _parse_cvss_vec(vec: str) -> dict:
        """Parse CVSS v3 vector string thành dict các component."""
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
        # snippet: câu đầu tiên của description, tối đa 120 ký tự
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
    has_no_priv         = _any_vec('PR', 'N')   # không cần auth để khai thác
    has_user_interact   = _any_vec('UI', 'R')   # cần user click/mở file
    has_no_ui           = _any_vec('UI', 'N')   # khai thác tự động, không cần user
    has_low_complexity  = _any_vec('AC', 'L')   # dễ khai thác
    has_conf_impact     = _any_vec('C',  'H')   # lộ thông tin nghiêm trọng
    has_integ_impact    = _any_vec('I',  'H')   # sửa đổi dữ liệu nghiêm trọng
    has_avail_impact    = _any_vec('A',  'H')   # gây downtime

    # ── Top CVEs (most critical) ──────────────────────────────────────────────
    top_cves = sorted(cves, key=lambda c: (
        {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1}.get(_effective_severity(c), 0),
        float(c.get('cvss_score') or 0)
    ), reverse=True)[:3]

    def _cve_tag(cve: dict) -> str:
        return f"{cve.get('cve_id','')} (CVSS {cve.get('cvss_score') or 'N/A'})"

    # ── Build top threats với CVE ID + context khai thác ─────────────────────
    top_threats = []
    for t in THREAT_LABELS:
        if t not in detected_threats:
            continue
        entries  = threat_cve_map[t][:2]
        cve_refs = ', '.join(f"{cid} (CVSS {sc:.1f})" for cid, sc, _, _ in entries if cid)
        # Thêm context khai thác từ CVSS vector của CVE đó
        vec_ctx  = ''
        if entries:
            vp = entries[0][2]
            if vp.get('PR') == 'N':
                vec_ctx = ' — không cần xác thực'
            elif vp.get('AC') == 'L':
                vec_ctx = ' — dễ khai thác'
        label = THREAT_LABELS[t]
        top_threats.append(f"{label}{vec_ctx} — {cve_refs}" if cve_refs else label)

    if not top_threats:
        for cve in top_cves:
            top_threats.append(
                f"{cve.get('cve_id','')} — CVSS {cve.get('cvss_score','N/A')} "
                f"({_effective_severity(cve)})"
            )

    # ── Build recommendations — đặc thù theo CVE + CVSS vector ──────────────
    recs = []

    # R1: Cập nhật — kèm CVE nguy hiểm nhất + mức độ dễ khai thác
    top_cve_str = ', '.join(_cve_tag(c) for c in top_cves)
    if overall_risk in ('CRITICAL', 'HIGH'):
        msg = f'Cập nhật {sw} lên phiên bản mới nhất ngay lập tức'
        if top_cve_str:
            msg += f' — vá ngay: {top_cve_str}'
        if has_low_complexity and has_no_priv:
            msg += ' (lỗ hổng không cần auth, dễ khai thác tự động)'
        recs.append(msg)
    else:
        recs.append(f'Lên kế hoạch cập nhật {sw} — {top_cve_str}')

    # R2: Network — chỉ khi thực sự có network vector
    if has_network_vector:
        net_cves = [cid for cid, _, vp, _ in
                    sorted([(e[0],e[1],e[2],e[3]) for t in detected_threats
                            for e in threat_cve_map[t] if e[2].get('AV')=='N'],
                           key=lambda x: x[1], reverse=True)[:2]]
        msg = f'Cô lập {sw} khỏi mạng'
        if has_no_priv and has_no_ui:
            msg += ' — lỗ hổng có thể bị khai thác từ xa hoàn toàn tự động (PR:N, UI:N)'
        elif has_no_priv:
            msg += ' — không cần xác thực để tấn công qua mạng'
        if net_cves:
            msg += f' ({", ".join(net_cves)})'
        recs.append(msg)
    elif has_local_vector:
        lc = [cid for cid, _, vp, _ in
              [e for t in detected_threats for e in threat_cve_map[t]]
              if _.get('AV') == 'L'][:1] if False else []
        recs.append(f'Kiểm soát quyền truy cập local vào {sw} — lỗ hổng khai thác qua local access')

    # R3: User interaction — nếu cần user click
    if has_user_interact:
        ui_cves = ', '.join(
            cid for cid, sc, vp, _ in
            sorted([e for t in detected_threats for e in threat_cve_map[t]
                    if e[2].get('UI') == 'R'], key=lambda x: x[1], reverse=True)[:2]
            if cid
        )
        msg = f'Cảnh báo người dùng không mở file/link không rõ nguồn gốc từ {sw}'
        if ui_cves:
            msg += f' ({ui_cves} yêu cầu user interaction để khai thác)'
        recs.append(msg)

    # R4: Privilege escalation
    if 'privilege_escalation' in detected_threats:
        pe_cid, pe_cvss, pe_vec, pe_snip = threat_cve_map['privilege_escalation'][0]
        msg = f'Chạy {sw} với quyền tối thiểu (Least Privilege) — {pe_cid} (CVSS {pe_cvss:.1f}) cho phép leo thang đặc quyền'
        recs.append(msg)

    # R5: Auth bypass
    if 'auth_bypass' in detected_threats:
        ab_cid = threat_cve_map['auth_bypass'][0][0]
        recs.append(f'Rà soát và vá cơ chế xác thực của {sw} ({ab_cid}), triển khai MFA nếu có thể')

    # R6: Memory issues — đặc thù theo loại
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
            f'Bật DEP/ASLR/Stack Canary trên hệ thống chạy {sw}'
            f' — phát hiện {", ".join(mem_types)}'
            + (f' ({mem_cids})' if mem_cids else '')
        )

    # R7: Data impact — confidentiality/integrity
    if has_conf_impact or has_integ_impact:
        impacts = []
        if has_conf_impact:  impacts.append('lộ dữ liệu (C:H)')
        if has_integ_impact: impacts.append('sửa đổi dữ liệu (I:H)')
        recs.append(f'Backup dữ liệu liên quan đến {sw} và giám sát bất thường — nguy cơ: {", ".join(impacts)}')

    # R8: Availability — DoS hoặc A:H
    if 'dos' in detected_threats or has_avail_impact:
        dos_cid = (threat_cve_map['dos'][0][0] if threat_cve_map.get('dos') else '')
        msg = f'Chuẩn bị phương án dự phòng/failover cho {sw}'
        if dos_cid:
            msg += f' — {dos_cid} có thể gây gián đoạn dịch vụ'
        recs.append(msg)

    # R9: Crypto
    if 'crypto_weak' in detected_threats:
        cr_cid = threat_cve_map['crypto_weak'][0][0]
        recs.append(f'Thay thế thuật toán mã hóa yếu trong {sw} ({cr_cid}), kiểm tra mật khẩu hardcoded')

    # R10: Injection / path traversal / XSS
    if 'injection' in detected_threats or 'path_traversal' in detected_threats or 'xss' in detected_threats:
        inj_types = [THREAT_LABELS[t].split('(')[0].strip()
                     for t in ['injection','path_traversal','xss'] if t in detected_threats]
        recs.append(f'Sanitize toàn bộ input của {sw}, áp dụng whitelist validation — phát hiện: {", ".join(inj_types)}')

    # Luôn có: advisory + sandbox nếu là file
    recs.append(f'Theo dõi security advisory cho {sw}: https://nvd.nist.gov/vuln/search')
    if context == 'file':
        recs.append(f'Test {sw} trong sandbox trước khi deploy lên production')

    # ── Key attack vectors — chi tiết hơn từ CVSS ────────────────────────────
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

    # Thêm context EMBER nếu có — giải thích rõ file sạch nhưng phần mềm có lỗ hổng
    ember_ctx = ''
    if ember_result and ember_result.get('available') and ember_result.get('probability') is not None:
        prob  = ember_result['probability']
        label = ember_result.get('label', 'BENIGN')
        if prob < 0.2:
            ember_ctx = (f' (Lưu ý: EMBER ML đánh giá file này là {label} — {prob:.0%} malware probability. '
                         f'Lỗ hổng bên dưới là của phần mềm {sw_label}, không phải file malware.)')
        elif prob >= 0.5:
            ember_ctx = f' (EMBER ML: {prob:.0%} malware probability — file có thể độc hại.)'

    if overall_risk == 'CRITICAL':
        summary = (f'{sw_label} có {total} CVE ({sev_str}). '
                   f'NGUY HIỂM CỰC CAO — không sử dụng trên môi trường production cho đến khi vá lỗi.{ember_ctx}')
    elif overall_risk == 'HIGH':
        summary = (f'{sw_label} có {total} CVE ({sev_str}). '
                   f'Mức độ nguy hiểm cao, cần vá lỗi trong thời gian sớm nhất.{ember_ctx}')
    elif overall_risk == 'MEDIUM':
        summary = (f'{sw_label} có {total} CVE ({sev_str}). '
                   f'Rủi ro trung bình, nên cập nhật và theo dõi thường xuyên.{ember_ctx}')
    else:
        summary = (f'{sw_label} có {total} CVE ({sev_str}). '
                   f'Rủi ro thấp, nên cập nhật theo lịch trình bình thường.{ember_ctx}')

    return {
        'success':           True,
        'overall_risk':      overall_risk,
        'risk_summary':      summary,
        'top_threats':       top_threats[:6],
        'recommendations':   recs[:8],
        'key_attack_vectors': list(dict.fromkeys(vectors))[:8],  # dedup, preserve order
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
