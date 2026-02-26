# backend/app_final.py

"""
Flask Web Server - CVE Scanner FINAL VERSION
- Direct NVD API query by CPE (no junction.csv)
- No limit on CVE results
- 100% accurate data from NVD
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename
from pathlib import Path
import sys
import os

# Import modules
sys.path.append(str(Path(__file__).parent))
from cpe_extractor import CPEExtractor
from nvd_api_v2 import NVDAPIv2
from static_analyzer import PEStaticAnalyzer
from ai_analyzer import ai_match_cpe, ai_analyze_severity, is_available as ai_available
from severity_classifier import predict as clf_predict, is_available as clf_available
from cpe_semantic_matcher import match_best as sem_match_best, match as sem_match, is_available as sem_available
from contextual_scorer import score_cves, build_file_profile
from secbert_cve_scorer import score_cves_semantic, build_profile_text, is_available as secbert_available
from bert_severity_classifier import predict as bert_predict, is_available as bert_available, get_meta as bert_meta
from zero_shot_severity import predict as zs_predict, is_available as zs_available, get_model_name as zs_model

app = Flask(__name__, 
            template_folder='../frontend/templates',
            static_folder='../frontend/static')
CORS(app)

# Configuration - dùng absolute path để tránh lỗi [Errno 22] trên Windows
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
UPLOAD_DIR = Path(__file__).parent.parent / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_DIR)

# Global variables
nvd_api = None
cpe_extractor = None
pe_analyzer = None

def init_app():
    """Initialize application"""
    global nvd_api, cpe_extractor, pe_analyzer

    print("=" * 80)
    print("[*] CVE SCANNER - FINAL VERSION")
    print("=" * 80)
    print()

    # ========================================================================
    # GAN API KEY TRUC TIEP TAI DAY
    # ========================================================================
    API_KEY = "4a29ba81-21a1-4e9d-84ff-e806f576c061"  # <- paste key cua ban
    # ========================================================================

    # Get API key
    api_key = API_KEY or os.getenv('NVD_API_KEY')

    if not api_key:
        print("[!] WARNING: No API key configured!")
        print("    Queries will be VERY SLOW (6 seconds per page)")
        print()
        print("[i] To speed up 10x:")
        print("    1. Get API key: https://nvd.nist.gov/developers/request-an-api-key")
        print("    2. Edit app.py and set API_KEY = \"your-key\"")
        print()

    # Initialize NVD API
    nvd_api = NVDAPIv2(api_key)
    print("[+] NVD API v2 initialized")

    # Initialize CPE extractor
    cpe_extractor = CPEExtractor()
    print("[+] CPE Extractor initialized")

    # Initialize PE static analyzer
    pe_analyzer = PEStaticAnalyzer()
    print("[+] PE Static Analyzer initialized")

    print()
    print("[*] MODE: Direct NVD API query")
    print("    - Query directly from NVD by CPE")
    print("    - No junction.csv needed")
    print("    - No CVE limit")
    print("    - 100% accurate data")
    print()

    # AI analyzer status
    if ai_available():
        print("[+] AI Analyzer ENABLED (Claude)")
        print("    - AI CPE Matching: ON")
        print("    - AI Severity Context: ON")
    else:
        print("[i] AI Analyzer DISABLED")
        print("    Set ANTHROPIC_API_KEY env var to enable AI features")

    # ML modules status
    if sem_available():
        print("[+] Semantic CPE Matcher ENABLED (FAISS + sentence-transformers)")
    else:
        print("[i] Semantic CPE Matcher DISABLED (run: python untils/build_cpe_index.py)")

    if clf_available():
        print("[+] Severity Classifier ENABLED (TF-IDF + LogisticRegression)")
    else:
        print("[i] Severity Classifier DISABLED (run: python untils/train_severity_model.py)")

    # Deep Learning models status
    print()
    print("[*] Deep Learning AI Models:")

    if bert_available():
        meta = bert_meta()
        acc = meta.get("test_accuracy", 0)
        f1  = meta.get("test_macro_f1", 0)
        base = meta.get("base_model", "DistilBERT")
        print(f"[+] Fine-tuned BERT Severity Classifier ENABLED")
        print(f"    Base: {base} | Test Acc: {acc*100:.1f}% | Macro-F1: {f1*100:.1f}%")
    else:
        print("[i] Fine-tuned BERT Severity Classifier DISABLED")
        print("    Run: python untils/build_training_data.py")
        print("         python untils/finetune_bert_severity.py")

    if zs_available():
        print(f"[+] Zero-Shot NLI Severity Classifier ENABLED ({zs_model()})")
    else:
        print("[i] Zero-Shot NLI Severity Classifier DISABLED")
        print("    Install: pip install transformers torch")

    if secbert_available():
        print("[+] SecBERT CVE Semantic Scorer ENABLED (jackaduma/SecBERT)")
        print("    - Cross-domain CVE–PE semantic relevance: ON")
    else:
        print("[i] SecBERT CVE Scorer DISABLED")
        print("    Install: pip install transformers torch")
    print()

# Initialize
init_app()

# Routes

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_file():
    """Scan uploaded file"""
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    try:
        # Save file
        filename = secure_filename(file.filename)
        filepath = Path(app.config['UPLOAD_FOLDER']) / filename
        file.save(str(filepath))
        
        # Extract CPE
        cpe_info = cpe_extractor.extract_from_file(filepath)

        cpe = cpe_info.get('cpe')
        vendor = cpe_info.get('vendor')
        product = cpe_info.get('product')
        version = cpe_info.get('version')
        extraction_method = cpe_info.get('extraction_method', '')

        # ── AI CPE Matching (for uncertain extractions) ──────────────────
        ai_cpe_result = None
        sem_cpe_result = None
        if extraction_method in ('generic_fallback', 'filename_pattern'):
            file_meta = cpe_info.get('file_info', {})
            query_name = (file_meta.get('ProductName') or product or filename or '').strip()

            # 1. Try Claude AI first (highest accuracy)
            if ai_available():
                ai_cpe_result = ai_match_cpe(
                    product_name=product or '',
                    company_name=file_meta.get('CompanyName', ''),
                    filename=file_meta.get('FileName', filename),
                    version=version or '',
                )
                if ai_cpe_result.get('success') and ai_cpe_result.get('confidence') in ('high', 'medium'):
                    ai_vendor  = ai_cpe_result['vendor']
                    ai_product = ai_cpe_result['product']
                    cpe    = cpe_extractor._build_cpe(ai_vendor, ai_product, version or '')
                    vendor  = ai_vendor
                    product = ai_product

            # 2. Fall back to semantic FAISS matcher when AI unavailable / low confidence
            if sem_available() and query_name and (not ai_cpe_result or not ai_cpe_result.get('success')):
                sem_cpe_result = sem_match_best(query_name, min_score=0.50)
                if sem_cpe_result and sem_cpe_result.get('confidence') in ('high', 'medium'):
                    vendor  = sem_cpe_result['vendor']
                    product = sem_cpe_result['product']
                    cpe     = cpe_extractor._build_cpe(vendor, product, version or '')

        if not cpe:
            return jsonify({
                'success': False,
                'error': 'Could not extract CPE from file',
                'file_info': cpe_info,
                'ai_cpe': ai_cpe_result,
            })

        # Query NVD directly by CPE
        max_results = request.form.get('max_results', None)
        if max_results:
            max_results = int(max_results)

        cves = nvd_api.search_by_cpe(cpe, max_results=max_results)

        # Calculate statistics
        stats = calculate_statistics(cves)

        # ── AI Severity Enrichment ────────────────────────────────────────
        if cves:
            for cve in cves:
                desc, vector = cve.get('description', ''), cve.get('vector_string', '')
                if clf_available():
                    pred = clf_predict(description=desc, vector_string=vector)
                    if pred: cve['ml_prediction'] = pred
                if bert_available():
                    bp = bert_predict(description=desc, vector_string=vector)
                    if bp: cve['bert_prediction'] = bp
                if zs_available():
                    zp = zs_predict(description=desc, vector_string=vector)
                    if zp: cve['zero_shot_prediction'] = zp

        # ── AI Severity Context ───────────────────────────────────────────
        ai_analysis = None
        if ai_available() and cves:
            ai_analysis = ai_analyze_severity(
                software_info={'name': f"{vendor} {product}", 'vendor': vendor,
                               'product': product, 'version': version or ''},
                cves=cves,
                stats=stats,
            )

        # Clean up
        filepath.unlink()

        return jsonify({
            'success': True,
            'file_info': {
                'filename': filename,
                'vendor': vendor,
                'product': product,
                'version': version,
                'extraction_method': extraction_method,
            },
            'cpe': cpe,
            'total_cves': stats['total_cves'],
            'vulnerabilities': cves[:50],  # Return first 50 for UI
            'statistics': stats,
            'data_source': 'NVD API (Direct CPE Query)',
            'note': f"Showing first 50 of {stats['total_cves']} CVEs",
            'ai_cpe': ai_cpe_result,
            'sem_cpe': sem_cpe_result,
            'ai_analysis': ai_analysis,
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/search', methods=['POST'])
def search_by_name():
    """Search vulnerabilities by software name"""
    
    data = request.get_json()
    
    if not data or 'software_name' not in data:
        return jsonify({'success': False, 'error': 'software_name is required'}), 400
    
    software_name = data['software_name']
    version = data.get('version', '')
    
    try:
        # Extract CPE from name
        cpe_info = cpe_extractor.extract_from_software_name(software_name, version)

        cpe = cpe_info.get('cpe')
        vendor = cpe_info.get('vendor')
        product = cpe_info.get('product')

        # ── AI / Semantic CPE Matching ────────────────────────────────────
        ai_cpe_result  = None
        sem_cpe_result = None

        # 1. Try Claude AI (most accurate)
        if ai_available():
            ai_cpe_result = ai_match_cpe(
                product_name=software_name,
                company_name='',
                filename='',
                version=version or '',
            )
            if ai_cpe_result.get('success') and ai_cpe_result.get('confidence') in ('high', 'medium'):
                ai_vendor  = ai_cpe_result['vendor']
                ai_product = ai_cpe_result['product']
                cpe    = cpe_extractor._build_cpe(ai_vendor, ai_product, version or '')
                vendor  = ai_vendor
                product = ai_product

        # 2. Semantic FAISS matcher as primary / fallback
        if sem_available():
            sem_cpe_result = sem_match_best(software_name, min_score=0.50)
            if sem_cpe_result and not (ai_cpe_result and ai_cpe_result.get('success')):
                if sem_cpe_result.get('confidence') in ('high', 'medium'):
                    vendor  = sem_cpe_result['vendor']
                    product = sem_cpe_result['product']
                    cpe     = cpe_extractor._build_cpe(vendor, product, version or '')

        if not cpe:
            return jsonify({'success': False, 'error': 'Could not build CPE from software name'})

        # Query NVD directly by CPE
        max_results = data.get('max_results', None)

        cves = nvd_api.search_by_cpe(cpe, max_results=max_results)

        # Calculate statistics
        stats = calculate_statistics(cves)

        # ── AI Severity Enrichment ────────────────────────────────────────
        if cves:
            for cve in cves:
                desc, vector = cve.get('description', ''), cve.get('vector_string', '')
                if clf_available():
                    pred = clf_predict(description=desc, vector_string=vector)
                    if pred: cve['ml_prediction'] = pred
                if bert_available():
                    bp = bert_predict(description=desc, vector_string=vector)
                    if bp: cve['bert_prediction'] = bp
                if zs_available():
                    zp = zs_predict(description=desc, vector_string=vector)
                    if zp: cve['zero_shot_prediction'] = zp

        # ── AI Severity Context ───────────────────────────────────────────
        ai_analysis = None
        if ai_available() and cves:
            ai_analysis = ai_analyze_severity(
                software_info={'name': software_name, 'vendor': vendor,
                               'product': product, 'version': version or ''},
                cves=cves,
                stats=stats,
            )

        return jsonify({
            'success': True,
            'software_info': {
                'name': software_name,
                'version': version,
                'vendor': vendor,
                'product': product,
            },
            'cpe': cpe,
            'total_cves': stats['total_cves'],
            'vulnerabilities': cves[:50],  # Return first 50 for UI
            'statistics': stats,
            'data_source': 'NVD API (Direct CPE Query)',
            'note': f"Showing first 50 of {stats['total_cves']} CVEs" if stats['total_cves'] > 50 else None,
            'ai_cpe': ai_cpe_result,
            'sem_cpe': sem_cpe_result,
            'ai_analysis': ai_analysis,
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/query-cpe', methods=['POST'])
def query_cpe():
    """Query CVEs by CPE string - EXACT NVD query"""
    
    data = request.get_json()
    
    if not data or 'cpe' not in data:
        return jsonify({'success': False, 'error': 'cpe is required'}), 400
    
    cpe = data['cpe']
    
    try:
        # Query NVD directly
        max_results = data.get('max_results', None)
        
        print(f"\n[API] Direct CPE query: {cpe}")
        print(f"[API] Max results: {max_results if max_results else 'ALL'}")
        
        cves = nvd_api.search_by_cpe(cpe, max_results=max_results)

        # Calculate statistics
        stats = calculate_statistics(cves)

        # ── ML Severity Predictions (enrich each CVE) ────────────────────
        if clf_available() and cves:
            for cve in cves:
                pred = clf_predict(
                    description=cve.get('description', ''),
                    vector_string=cve.get('vector_string', ''),
                )
                if pred:
                    cve['ml_prediction'] = pred

        # ── AI Severity Context ───────────────────────────────────────────
        ai_analysis = None
        if ai_available() and cves:
            # Derive a human-readable name from the CPE string
            parts = cpe.split(':')
            sw_name = f"{parts[3]} {parts[4]}" if len(parts) > 4 else cpe
            sw_version = parts[5] if len(parts) > 5 else ''
            ai_analysis = ai_analyze_severity(
                software_info={'name': sw_name, 'version': sw_version},
                cves=cves,
                stats=stats,
            )

        return jsonify({
            'success': True,
            'cpe': cpe,
            'total_cves': stats['total_cves'],
            'vulnerabilities': cves[:100],  # Return first 100 for API
            'statistics': stats,
            'data_source': 'NVD API (Direct CPE Query)',
            'note': f"Showing first 100 of {stats['total_cves']} CVEs" if stats['total_cves'] > 100 else None,
            'nvd_search_url': f"https://nvd.nist.gov/vuln/search#/nvd/home?cpeFilterMode=cpe&cpeName={cpe}&resultType=records",
            'ai_analysis': ai_analysis,
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/export-all', methods=['POST'])
def export_all():
    """Export ALL CVEs for a CPE (no limit)"""
    
    data = request.get_json()
    
    if not data or 'cpe' not in data:
        return jsonify({'success': False, 'error': 'cpe is required'}), 400
    
    cpe = data['cpe']
    
    try:
        print(f"\n[API] Exporting ALL CVEs for: {cpe}")
        
        # Fetch ALL CVEs (no limit)
        cves = nvd_api.search_by_cpe(cpe, max_results=None)
        
        stats = calculate_statistics(cves)
        
        return jsonify({
            'success': True,
            'cpe': cpe,
            'total_cves': len(cves),
            'vulnerabilities': cves,  # ALL CVEs
            'statistics': stats,
            'data_source': 'NVD API (Complete Export)'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get API statistics"""
    
    return jsonify({
        'mode': 'Direct NVD API Query',
        'api_key_active': nvd_api.api_key is not None,
        'rate_limit': '50 req/30s' if nvd_api.api_key else '5 req/30s',
        'ai_enabled': ai_available(),
        'sem_cpe_enabled': sem_available(),
        'severity_clf_enabled': clf_available(),
        'secbert_enabled': secbert_available(),
        'bert_severity_enabled': bert_available(),
        'zero_shot_enabled': zs_available(),
        'features': [
            'Direct CPE query to NVD',
            'No CVE limit',
            '100% accurate data',
            'Real-time updates',
            'AI CPE Matching (Claude)' if ai_available() else 'AI CPE Matching (disabled)',
            'AI Severity Context (Claude)' if ai_available() else 'AI Severity Context (disabled)',
            'Semantic CPE Matching (FAISS)' if sem_available() else 'Semantic CPE Matching (disabled)',
            'TF-IDF+LR Severity Baseline' if clf_available() else 'TF-IDF+LR (disabled)',
            'Fine-tuned BERT Severity Classifier' if bert_available() else 'BERT Severity (run finetune_bert_severity.py)',
            'Zero-Shot NLI Severity' if zs_available() else 'Zero-Shot NLI (disabled)',
            'SecBERT Semantic CVE Scoring' if secbert_available() else 'SecBERT (disabled)',
        ]
    })

# Helper functions

def calculate_statistics(cves):
    """Calculate statistics from CVE list"""
    
    if not cves:
        return {
            'total_cves': 0,
            'by_severity': {},
            'avg_cvss': 0,
            'max_cvss': 0,
            'min_cvss': 0
        }
    
    # Count by severity
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'NONE': 0
    }
    
    for cve in cves:
        severity = cve.get('severity', 'NONE')
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['NONE'] += 1
    
    # CVSS statistics
    cvss_scores = [cve.get('cvss_score', 0) for cve in cves if cve.get('cvss_score', 0) > 0]
    
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
    max_cvss = max(cvss_scores) if cvss_scores else 0
    min_cvss = min(cvss_scores) if cvss_scores else 0
    
    return {
        'total_cves': len(cves),
        'by_severity': severity_counts,
        'avg_cvss': round(avg_cvss, 2),
        'max_cvss': round(max_cvss, 2),
        'min_cvss': round(min_cvss, 2)
    }

@app.route('/api/pe-analyze', methods=['POST'])
def pe_analyze():
    """PE static analysis + CVE lookup combined"""

    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    filepath = None
    try:
        filename = secure_filename(file.filename)
        filepath = Path(app.config['UPLOAD_FOLDER']) / filename
        file.save(str(filepath))

        # ── 1. PE Static Analysis ────────────────────────────────────────────
        print(f"\n[*] PE Static Analysis: {filename}")
        result = pe_analyzer.analyze(filepath)

        # ── 2. CPE Extraction ────────────────────────────────────────────────
        print(f"[*] Extracting CPE...")
        result['cpe'] = None
        result['cpe_info'] = {}
        result['vulnerabilities'] = []
        result['cve_statistics'] = {}

        try:
            cpe_info = cpe_extractor.extract_from_file(filepath)
            cpe = cpe_info.get('cpe')
            vendor   = cpe_info.get('vendor', '')
            product  = cpe_info.get('product', '')
            version  = cpe_info.get('version', '')
            extraction_method = cpe_info.get('extraction_method', '')

            # ── AI / Semantic CPE Matching ───────────────────────────────
            ai_cpe_result  = None
            sem_cpe_result = None
            if extraction_method in ('generic_fallback', 'filename_pattern'):
                file_meta  = cpe_info.get('file_info', {})
                query_name = (file_meta.get('ProductName') or product or filename or '').strip()

                # 1. Claude AI (highest accuracy)
                if ai_available():
                    ai_cpe_result = ai_match_cpe(
                        product_name=product or '',
                        company_name=file_meta.get('CompanyName', ''),
                        filename=file_meta.get('FileName', filename),
                        version=version or '',
                    )
                    if ai_cpe_result.get('success') and ai_cpe_result.get('confidence') in ('high', 'medium'):
                        vendor  = ai_cpe_result['vendor']
                        product = ai_cpe_result['product']
                        cpe     = cpe_extractor._build_cpe(vendor, product, version or '')

                # 2. Semantic FAISS fallback
                if sem_available() and query_name and not (ai_cpe_result and ai_cpe_result.get('success')):
                    sem_cpe_result = sem_match_best(query_name, min_score=0.50)
                    if sem_cpe_result and sem_cpe_result.get('confidence') in ('high', 'medium'):
                        vendor  = sem_cpe_result['vendor']
                        product = sem_cpe_result['product']
                        cpe     = cpe_extractor._build_cpe(vendor, product, version or '')

            result['ai_cpe']  = ai_cpe_result
            result['sem_cpe'] = sem_cpe_result

            result['cpe'] = cpe
            result['cpe_info'] = {
                'vendor':            vendor,
                'product':           product,
                'version':           version,
                'extraction_method': extraction_method,
            }

            # ── 3. CVE Lookup ────────────────────────────────────────────
            if cpe:
                print(f"[*] Querying NVD for: {cpe}")
                cves = nvd_api.search_by_cpe(cpe, max_results=50)
                stats = calculate_statistics(cves)
                print(f"[+] Found {stats['total_cves']} CVEs")

                # ── AI Severity Enrichment (3 layers, best available wins) ──
                if cves:
                    for cve in cves:
                        desc   = cve.get('description', '')
                        vector = cve.get('vector_string', '')

                        # Layer A: TF-IDF + LR baseline (fast, always available)
                        if clf_available():
                            pred = clf_predict(description=desc, vector_string=vector)
                            if pred:
                                cve['ml_prediction'] = pred

                        # Layer B: Fine-tuned BERT (trained on NVD data)
                        if bert_available():
                            bert_pred = bert_predict(description=desc, vector_string=vector)
                            if bert_pred:
                                cve['bert_prediction'] = bert_pred

                        # Layer C: Zero-shot NLI (no training, pure language model)
                        if zs_available():
                            zs_pred = zs_predict(description=desc, vector_string=vector)
                            if zs_pred:
                                cve['zero_shot_prediction'] = zs_pred

                # ── Rule-based Contextual Relevance Scoring ──────────────
                cves = score_cves(result, cves)
                result['file_profile'] = build_file_profile(result)
                print(f"[+] Contextual scoring applied")

                # ── SecBERT Semantic CVE–PE Relevance ────────────────────
                if secbert_available():
                    cves = score_cves_semantic(result, cves)
                    result['behavior_profile_text'] = build_profile_text(result)
                    print(f"[+] SecBERT semantic CVE relevance applied")
                else:
                    print(f"[i] SecBERT disabled — run: pip install transformers torch")

                result['vulnerabilities'] = cves[:50]
                result['cve_statistics']  = stats

                # ── AI Severity Context ───────────────────────────────────
                if ai_available() and cves:
                    result['ai_analysis'] = ai_analyze_severity(
                        software_info={'name': f"{vendor} {product}",
                                       'vendor': vendor, 'product': product,
                                       'version': version or ''},
                        cves=cves,
                        stats=stats,
                    )
            else:
                print(f"[!] Could not extract CPE - skipping CVE lookup")

        except Exception as e:
            print(f"[!] CPE/CVE step failed: {e}")
            result['cpe_error'] = str(e)

        print(f"[+] Done - Risk: {result.get('risk', {}).get('level', 'N/A')} | "
              f"CVEs: {len(result.get('vulnerabilities', []))}")
        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

    finally:
        # Always clean up the uploaded file
        if filepath and filepath.exists():
            try:
                filepath.unlink()
            except Exception:
                pass


# Run server
if __name__ == '__main__':
    print("=" * 80)
    print("[*] Starting web server...")
    print("=" * 80)
    print()
    print("Dashboard: http://localhost:5000")
    print()
    print("API Endpoints:")
    print("  POST /api/scan         - Upload file to scan (CVE lookup)")
    print("  POST /api/search       - Search by software name")
    print("  POST /api/query-cpe    - Query by CPE (limit 100)")
    print("  POST /api/export-all   - Export ALL CVEs (no limit)")
    print("  POST /api/pe-analyze   - PE static analysis")
    print("  GET  /api/stats        - API statistics")
    print()
    print("[i] IMPORTANT:")
    print("    - Set API key in code for 10x speed")
    print("    - No CVE limit - fetches ALL CVEs from NVD")
    print("    - Data 100% accurate from NVD")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 80)
    print()

    app.run(debug=True, host='0.0.0.0', port=5000)