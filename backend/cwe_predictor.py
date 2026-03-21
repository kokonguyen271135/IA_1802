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

from pathlib import Path

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


# ── CWEClassifier — ML model (SecBERT fine-tuned) ────────────────────────────

class CWEClassifier:
    """
    SecBERT fine-tuned trên NVD CVE descriptions → CWE categories.

    Được train bởi: python untils/train_cwe_classifier.py
    Model lưu tại: models/bert_cwe/

    Inference:
        text = build_profile_text(pe_analysis)  # behavior description
        predictions = classifier.predict(text, top_k=5)
        # [{"cwe_id": "CWE-94", "confidence": 0.87, ...}, ...]
    """

    MODEL_DIR = Path(__file__).parent.parent / "models" / "bert_cwe"
    META_FILE = Path(__file__).parent.parent / "models" / "bert_cwe_meta.json"

    def __init__(self):
        self._available  = False
        self._model      = None
        self._tokenizer  = None
        self._id2label: dict[int, str] = {}
        self._max_length = 256
        self._load()

    def _load(self) -> None:
        """Load fine-tuned model. Silent fail if not trained yet."""
        if not self.MODEL_DIR.exists() or not self.META_FILE.exists():
            return

        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            with open(self.META_FILE) as f:
                import json
                meta = json.load(f)

            self._max_length = meta.get("max_length", 256)
            self._id2label   = {int(k): v for k, v in meta["id2label"].items()}

            self._tokenizer = AutoTokenizer.from_pretrained(str(self.MODEL_DIR))
            self._model     = AutoModelForSequenceClassification.from_pretrained(
                str(self.MODEL_DIR)
            )
            self._model.eval()
            self._torch     = torch
            self._available = True

            n = len(self._id2label)
            print(f"[CWE ML] Loaded fine-tuned SecBERT CWE classifier ({n} classes)")

        except Exception as e:
            print(f"[CWE ML] Model load failed (will use rule-based fallback): {e}")

    def is_available(self) -> bool:
        return self._available

    def predict(self, text: str, top_k: int = 5) -> list[dict]:
        """
        Predict CWE categories from input text.

        Parameters
        ----------
        text   : behavior profile text (từ build_profile_text) hoặc CVE description
        top_k  : số CWE trả về

        Returns
        -------
        list of dicts sorted by confidence DESC (same format as predict_cwe())
        """
        if not self._available:
            return []

        import torch
        import torch.nn.functional as F

        try:
            inputs = self._tokenizer(
                text,
                max_length=self._max_length,
                truncation=True,
                padding=True,
                return_tensors="pt",
            )
            with torch.no_grad():
                logits = self._model(**inputs).logits
            probs = F.softmax(logits, dim=-1)[0]

            # Get top-K
            topk_vals, topk_ids = torch.topk(probs, min(top_k, len(self._id2label)))

            results = []
            for score, idx in zip(topk_vals.tolist(), topk_ids.tolist()):
                cwe_id = self._id2label.get(idx, f"CWE-{idx}")
                meta   = CWE_CATALOG.get(cwe_id)
                results.append({
                    "cwe_id":       cwe_id,
                    "name":         meta[0] if meta else cwe_id,
                    "description":  meta[1] if meta else "",
                    "confidence":   round(score, 4),
                    "label":        _conf_label(score),
                    "triggered_by": ["SecBERT CWE classifier (fine-tuned on NVD)"],
                    "source":       "ml_model",
                })

            return results

        except Exception as e:
            print(f"[CWE ML] Prediction error: {e}")
            return []


# ── Singleton CWEClassifier ───────────────────────────────────────────────────

_cwe_classifier: CWEClassifier | None = None


def get_cwe_classifier() -> CWEClassifier:
    global _cwe_classifier
    if _cwe_classifier is None:
        _cwe_classifier = CWEClassifier()
    return _cwe_classifier


# ── CWEPredictor class — wraps prediction + NVD lookup ───────────────────────

class CWEPredictor:
    """
    Hướng 3 core class: predict CWE from PE features, then fetch CVEs.

    Thứ tự ưu tiên:
      1. SecBERT ML model (nếu đã train) — dùng build_profile_text() làm input
      2. Rule-based fallback              — dùng BEHAVIOR_TO_CWE mapping

    Hoạt động như fallback khi:
      - Không xác định được CPE của file
      - CPE có nhưng NVD trả về 0 CVE

    Ví dụ dùng trong app.py::

        predictor = CWEPredictor(nvd_api)
        if not cves:
            result['cwe_analysis'] = predictor.predict_and_fetch(pe_analysis)
    """

    # ── Target software detection maps ────────────────────────────────────────

    _TARGET_DLL_MAP: dict[str, tuple[str, str]] = {
        "mso":        ("microsoft", "office"),
        "vbe7":       ("microsoft", "office"),
        "winword":    ("microsoft", "office"),
        "excel":      ("microsoft", "office"),
        "powerpnt":   ("microsoft", "office"),
        "mshtml":     ("microsoft", "internet_explorer"),
        "ieframe":    ("microsoft", "internet_explorer"),
        "jscript":    ("microsoft", "internet_explorer"),
        "jscript9":   ("microsoft", "internet_explorer"),
        "acrobat":    ("adobe", "acrobat"),
        "acrord32":   ("adobe", "acrobat_reader"),
        "jvm":        ("oracle", "java"),
        "java":       ("oracle", "java"),
        "chrome":     ("google", "chrome"),
        "xul":        ("mozilla", "firefox"),
        "nss3":       ("mozilla", "firefox"),
        "win32k":     ("microsoft", "windows"),
        "winspool":   ("microsoft", "windows"),
        "lsasrv":     ("microsoft", "windows"),
        "ntdll":      ("microsoft", "windows"),
        "kernelbase": ("microsoft", "windows"),
        "advapi32":   ("microsoft", "windows"),
        "flash":      ("adobe", "flash_player"),
        "clr":        ("microsoft", "net_framework"),
        "mscorlib":   ("microsoft", "net_framework"),
    }

    _TARGET_REGISTRY_PATTERNS: list[tuple[str, tuple[str, str]]] = [
        (r"Software\\Microsoft\\Office",             ("microsoft", "office")),
        (r"Software\\Adobe\\Acrobat",                ("adobe", "acrobat")),
        (r"Software\\Adobe\\Adobe Acrobat",          ("adobe", "acrobat")),
        (r"Software\\Google\\Chrome",                ("google", "chrome")),
        (r"Software\\Mozilla\\Firefox",              ("mozilla", "firefox")),
        (r"Software\\Oracle\\Java",                  ("oracle", "java")),
        (r"Software\\Microsoft\\Internet Explorer",  ("microsoft", "internet_explorer")),
        (r"Software\\Microsoft\\Windows NT",         ("microsoft", "windows")),
        (r"Software\\Microsoft\\\.NETFramework",     ("microsoft", "net_framework")),
    ]

    _TARGET_PATH_PATTERNS: list[tuple[str, tuple[str, str]]] = [
        (r"Microsoft\s+Office",         ("microsoft", "office")),
        (r"Adobe\\Acrobat",             ("adobe", "acrobat")),
        (r"Adobe\\Reader",              ("adobe", "acrobat_reader")),
        (r"Google\\Chrome",             ("google", "chrome")),
        (r"Mozilla\s+Firefox",          ("mozilla", "firefox")),
        (r"Java\\jre",                  ("oracle", "java")),
        (r"Internet\s+Explorer",        ("microsoft", "internet_explorer")),
        (r"Microsoft\s+Visual\s+Studio",("microsoft", "visual_studio")),
        (r"\\Windows\\System32",        ("microsoft", "windows")),
    ]

    _TARGET_STRING_PATTERNS: list[tuple[str, tuple[str, str]]] = [
        (r"Microsoft\s+Office\s+\d+",       ("microsoft", "office")),
        (r"Adobe\s+Acrobat\s+[\d\.]+",      ("adobe", "acrobat")),
        (r"Adobe\s+Reader\s+[\d\.]+",       ("adobe", "acrobat_reader")),
        (r"Google\s+Chrome\s+[\d\.]+",      ("google", "chrome")),
        (r"Mozilla\s+Firefox\s+[\d\.]+",    ("mozilla", "firefox")),
        (r"Java\(TM\)\s+SE",                ("oracle", "java")),
        (r"Internet\s+Explorer\s+[\d\.]+",  ("microsoft", "internet_explorer")),
    ]

    _BEHAVIOR_KEYWORDS: dict[str, list[str]] = {
        "Process Injection":     ["process injection", "memory", "dll injection", "shellcode"],
        "Privilege Escalation":  ["privilege escalation", "elevation", "token", "admin"],
        "Code Execution":        ["remote code execution", "arbitrary code", "rce"],
        "Network Communication": ["network", "remote", "http", "ftp", "socket"],
        "Cryptography":          ["encryption", "ransomware", "crypto", "cipher"],
        "Registry Manipulation": ["registry", "regedit", "hklm", "hkcu"],
        "Keylogging":            ["keylog", "credential", "password steal"],
        "Anti-Debugging":        ["anti-debug", "sandbox evasion", "obfuscation"],
    }

    _WEB_ONLY_TERMS: list[str] = [
        "php", "xss", "cross-site scripting", "wordpress", "drupal", "joomla",
        "django", "ruby on rails", "laravel", "csrf", "cross-site request",
        "http response splitting",
    ]

    _WINDOWS_TERMS: list[str] = [
        "windows", "dll", "exe", "ntdll", "kernel32", "win32",
        "buffer overflow", "heap overflow", "stack overflow",
        "privilege escalation", "local privilege", "memory corruption",
        "use after free", "arbitrary code execution", "remote code execution",
    ]

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
        self._classifier      = get_cwe_classifier()

        ml_status = "ML model loaded" if self._classifier.is_available() else "rule-based fallback"
        print(f"[CWE Predictor] Initialized ({ml_status})")

    # ── Behavior → keywords mapping for CVE relevance scoring ─────────────────
    _BEHAVIOR_KEYWORDS: dict[str, list[str]] = {
        "process_injection":    ["injection", "process", "memory", "shellcode",
                                  "remote thread", "dll inject", "hollowing"],
        "code_execution":       ["execution", "execute", "shell", "command",
                                  "arbitrary code", "rce", "remote code"],
        "network_communication":["network", "remote", "socket", "http", "download",
                                  "c2", "command and control", "backdoor", "trojan"],
        "privilege_escalation": ["privilege", "elevation", "token", "admin",
                                  "local privilege", "escalat"],
        "keylogging":           ["keylog", "keystroke", "hook", "input capture"],
        "registry_manipulation":["registry", "regedit", "hklm", "hkcu", "regkey"],
        "cryptography":         ["encrypt", "decrypt", "crypto", "ransom",
                                  "ransomware", "cipher"],
        "anti_debugging":       ["debug", "sandbox", "evasion", "anti-analysis",
                                  "obfuscat", "packer", "packed"],
        "service_manipulation": ["service", "daemon", "scm", "persistence",
                                  "startup", "autorun"],
        "dynamic_loading":      ["dynamic", "loadlibrary", "reflective", "loader"],
    }

    # Terms that appear only in web/scripting CVEs — penalize if present without
    # any compensating Windows/PE signals
    _WEB_ONLY_TERMS: list[str] = [
        "php", "javascript", "html", "css", "xss", "cross-site",
        "wordpress", "joomla", "drupal", "magento", "typo3",
        "web browser", "firefox", "chrome", "safari", "internet explorer",
        "ruby on rails", "django", "laravel", "asp.net web",
        "sql injection via", "stored xss", "reflected xss",
    ]

    # Terms that indicate relevance to Windows PE / native executables
    _WINDOWS_TERMS: list[str] = [
        "windows", "win32", "dll", "exe", "executable", "binary",
        "kernel", "ntdll", "winsock", "winapi", "nt kernel",
        "active directory", "registry", "com object", "service",
        "device driver", "sys file", "heap", "stack overflow",
        "buffer overflow", "memory corruption", "use-after-free",
        "out-of-bounds", "privilege escalation", "elevation of privilege",
    ]

    def _score_relevance(
        self,
        cve: dict,
        active_behaviors: list[str],
        analysis: dict,
    ) -> float:
        """
        Tính điểm liên quan giữa một CVE và PE file đang phân tích.

        Trả về float; giá trị âm nghĩa là CVE gần như chắc chắn không liên quan.
        """
        desc = (cve.get("description") or "").lower()
        score = 0.0

        # ── 1. Windows / native binary signals (+) ────────────────────────────
        win_hits = sum(1 for t in self._WINDOWS_TERMS if t in desc)
        score += min(win_hits * 0.08, 0.30)

        # ── 2. Behavior keyword match (+) ─────────────────────────────────────
        for behavior in active_behaviors:
            keywords = self._BEHAVIOR_KEYWORDS.get(behavior, [])
            hits = sum(1 for k in keywords if k in desc)
            if hits:
                score += min(hits * 0.06, 0.12)   # max 0.12 per behavior

        # ── 3. Web-only penalty (–) ───────────────────────────────────────────
        web_hits = sum(1 for t in self._WEB_ONLY_TERMS if t in desc)
        penalty  = min(web_hits * 0.12, 0.40)
        score   -= penalty

        # ── 4. High CVSS gets a small boost (+) ──────────────────────────────
        cvss = cve.get("cvss_score", 0.0) or 0.0
        if cvss >= 9.0:
            score += 0.05
        elif cvss >= 7.0:
            score += 0.02

        # ── 5. CPE platform filter (+) ────────────────────────────────────────
        cpes = cve.get("cpes", [])
        if cpes:
            has_win_cpe = any(
                "microsoft:windows" in c.lower() or ":o:" in c.lower()
                for c in cpes
            )
            if has_win_cpe:
                score += 0.15

        return round(max(-1.0, min(1.0, score)), 4)

    # ── Target software detection ─────────────────────────────────────────────
    # DLL name (lowercase, no .dll) → (vendor_keyword, product_keyword)
    _TARGET_DLL_MAP: dict[str, tuple[str, str]] = {
        # Microsoft Office
        "mso":            ("microsoft", "office"),
        "vbe7":           ("microsoft", "office"),
        "msword":         ("microsoft", "word"),
        "excel":          ("microsoft", "excel"),
        "msppt":          ("microsoft", "powerpoint"),
        "outlook":        ("microsoft", "outlook"),
        "winword":        ("microsoft", "word"),
        # Internet Explorer / Edge
        "mshtml":         ("microsoft", "internet explorer"),
        "ieframe":        ("microsoft", "internet explorer"),
        "jscript":        ("microsoft", "internet explorer"),
        "edgehtml":       ("microsoft", "edge"),
        # Adobe
        "acrobat":        ("adobe", "acrobat"),
        "acrord32":       ("adobe", "acrobat reader"),
        "acroform":       ("adobe", "acrobat reader"),
        "flash":          ("adobe", "flash player"),
        "authplay":       ("adobe", "flash player"),
        # Java
        "jvm":            ("oracle", "java"),
        "java":           ("oracle", "java"),
        "javaw":          ("oracle", "java"),
        # Browsers
        "chrome":         ("google", "chrome"),
        "xul":            ("mozilla", "firefox"),
        # WinRAR / 7-Zip
        "unrar":          ("rarlab", "winrar"),
        "7z":             ("7-zip", "7-zip"),
        # Specific Windows components commonly exploited
        "win32k":         ("microsoft", "windows"),       # kernel graphics (EoP exploits)
        "winspool":       ("microsoft", "windows print spooler"),  # PrintNightmare
        "dnsapi":         ("microsoft", "windows dns"),   # DNS client exploits
        "lsasrv":        ("microsoft", "windows"),        # credential access target
    }

    # (regex, vendor, product) — checked against registry key strings
    _TARGET_REGISTRY_PATTERNS: list[tuple[str, str, str]] = [
        (r"Software\\Microsoft\\Office",           "microsoft", "office"),
        (r"Software\\Microsoft\\Word",             "microsoft", "word"),
        (r"Software\\Microsoft\\Excel",            "microsoft", "excel"),
        (r"Software\\Microsoft\\Outlook",          "microsoft", "outlook"),
        (r"Software\\Microsoft\\Internet Explorer","microsoft", "internet explorer"),
        (r"Software\\Microsoft\\Edge",             "microsoft", "edge"),
        (r"Software\\Microsoft\\Windows NT",       "microsoft", "windows"),
        (r"Software\\Adobe\\Acrobat",              "adobe", "acrobat"),
        (r"Software\\Adobe.*Reader",               "adobe", "acrobat reader"),
        (r"Software\\Adobe.*Flash",                "adobe", "flash player"),
        (r"Software\\Google\\Chrome",              "google", "chrome"),
        (r"Software\\Mozilla\\Firefox",            "mozilla", "firefox"),
        (r"Software\\Oracle\\Java",                "oracle", "java"),
        (r"Software\\JavaSoft",                    "oracle", "java"),
        (r"Software\\RARLab",                      "rarlab", "winrar"),
        (r"Software\\7-Zip",                       "7-zip", "7-zip"),
    ]

    # (regex, vendor, product) — checked against file path strings
    _TARGET_PATH_PATTERNS: list[tuple[str, str, str]] = [
        (r"Microsoft Office",                      "microsoft", "office"),
        (r"Microsoft\\Word",                       "microsoft", "word"),
        (r"Microsoft\\Excel",                      "microsoft", "excel"),
        (r"Internet Explorer",                     "microsoft", "internet explorer"),
        (r"\\Microsoft\\Edge",                     "microsoft", "edge"),
        (r"Adobe\\Acrobat",                        "adobe", "acrobat"),
        (r"Adobe.*Reader",                         "adobe", "acrobat reader"),
        (r"Adobe.*Flash",                          "adobe", "flash player"),
        (r"Google\\Chrome",                        "google", "chrome"),
        (r"Mozilla Firefox",                       "mozilla", "firefox"),
        (r"Oracle\\Java",                          "oracle", "java"),
        (r"\\Java\\jre",                           "oracle", "java"),
        (r"RARLab|WinRAR",                         "rarlab", "winrar"),
        (r"7-Zip",                                 "7-zip", "7-zip"),
        (r"Windows\\System32\\lsass",              "microsoft", "windows"),
        (r"Windows\\System32\\spoolsv",            "microsoft", "windows print spooler"),
    ]

    # (regex, vendor, product) — checked against all printable strings
    _TARGET_STRING_PATTERNS: list[tuple[str, str, str]] = [
        (r"Microsoft\s+Office\s+\d+",              "microsoft", "office"),
        (r"Microsoft\s+Word\s+\d+",                "microsoft", "word"),
        (r"Microsoft\s+Excel\s+\d+",               "microsoft", "excel"),
        (r"Internet Explorer\s+[\d\.]+",           "microsoft", "internet explorer"),
        (r"Adobe\s+Acrobat\s+[\d\.]+",             "adobe", "acrobat"),
        (r"Adobe\s+Reader\s+[\d\.]+",              "adobe", "acrobat reader"),
        (r"Adobe\s+Flash\s+Player\s+[\d\.]+",      "adobe", "flash player"),
        (r"Google\s+Chrome\s+[\d\.]+",             "google", "chrome"),
        (r"Mozilla\s+Firefox\s+[\d\.]+",           "mozilla", "firefox"),
        (r"Java\s+(?:Runtime|SE|JRE)\s+[\d\.]+",  "oracle", "java"),
        (r"WinRAR\s+[\d\.]+",                      "rarlab", "winrar"),
    ]

    def _detect_target_software(self, analysis: dict) -> list[dict]:
        """
        Phát hiện phần mềm mà PE file này nhắm tới, dựa trên:
          - DLL imports (độ tin cậy cao nhất)
          - Registry key strings
          - File path strings
          - Chuỗi text có tên phần mềm cụ thể
          - Components đã được detect sẵn bởi static_analyzer

        Trả về list[{vendor, product, confidence, source}], sort theo confidence.
        """
        import re as _re
        found: dict[tuple[str, str], dict] = {}  # (vendor, product) → best hit

        def _register(vendor: str, product: str, confidence: float, source: str):
            key = (vendor.lower(), product.lower())
            existing = found.get(key)
            if existing is None or confidence > existing["confidence"]:
                found[key] = {
                    "vendor":     vendor,
                    "product":    product,
                    "confidence": confidence,
                    "source":     source,
                }

        # ── 1. DLL imports (highest confidence — direct dependency) ──────────
        dlls = analysis.get("imports", {}).get("dlls", [])
        dll_bases = set()
        for d in dlls:
            name = (d.get("name") or "").lower()
            stem = _re.sub(r'\.(dll|exe|drv|sys|ocx)$', '', name)
            dll_bases.add(stem)
            # Also check stem with numeric suffixes stripped (e.g. msvcr100 → msvcr)
            dll_bases.add(_re.sub(r'[\d]+$', '', stem))

        for dll_key, (vendor, product) in self._TARGET_DLL_MAP.items():
            if dll_key in dll_bases:
                _register(vendor, product, 0.80, f"dll_import:{dll_key}.dll")

        # ── 2. Registry key strings ──────────────────────────────────────────
        reg_keys = analysis.get("strings", {}).get("Registry Keys", [])
        for reg_str in reg_keys:
            for pattern, vendor, product in self._TARGET_REGISTRY_PATTERNS:
                if _re.search(pattern, reg_str, _re.IGNORECASE):
                    _register(vendor, product, 0.70, f"registry:{reg_str[:60]}")

        # ── 3. File path strings ─────────────────────────────────────────────
        file_paths = analysis.get("strings", {}).get("File Paths", [])
        for path_str in file_paths:
            for pattern, vendor, product in self._TARGET_PATH_PATTERNS:
                if _re.search(pattern, path_str, _re.IGNORECASE):
                    _register(vendor, product, 0.60, f"filepath:{path_str[:60]}")

        # ── 4. All printable strings — software name/version patterns ────────
        all_text = " ".join(
            s
            for bucket in analysis.get("strings", {}).values()
            for s in (bucket if isinstance(bucket, list) else [])
        )
        for pattern, vendor, product in self._TARGET_STRING_PATTERNS:
            if _re.search(pattern, all_text, _re.IGNORECASE):
                _register(vendor, product, 0.50, "string_match")

        # ── 5. Components detected by static_analyzer (OpenSSL, Python, …) ──
        for comp in analysis.get("components", []):
            vendor  = comp.get("cpe_vendor", "")
            product = comp.get("cpe_product", comp.get("name", ""))
            if vendor and product:
                _register(vendor, product, 0.65, f"component:{comp.get('source','')}")

        # Filter out Windows-generic hits if more specific targets exist
        results = sorted(found.values(), key=lambda x: x["confidence"], reverse=True)
        has_specific = any(
            r["product"] not in ("windows", "windows nt")
            for r in results
        )
        if has_specific:
            results = [
                r for r in results
                if r["product"] not in ("windows", "windows nt")
            ]

        return results

    def _predict_cwes(self, analysis: dict) -> tuple[list[dict], str]:
        """
        Predict CWEs — thử ML model trước, fallback rule-based.

        Returns (predictions, method_used)
        """
        # ── Thử ML model trước ────────────────────────────────────────────────
        if self._classifier.is_available():
            try:
                # Import build_profile_text từ secbert scorer
                # (dùng cùng behavior text builder đã có)
                from secbert_cve_scorer import build_profile_text
                behavior_text = build_profile_text(analysis)

                if behavior_text and len(behavior_text) > 20:
                    ml_preds = self._classifier.predict(behavior_text, top_k=self.top_cwes + 2)
                    if ml_preds:
                        return ml_preds, "secbert_cwe_classifier"
            except Exception as e:
                print(f"[CWE ML] Prediction failed, using rule-based: {e}")

        # ── Rule-based fallback ───────────────────────────────────────────────
        rule_preds = predict_cwe(analysis, top_k=self.top_cwes + 2)
        return rule_preds, "rule_based"

    def _detect_target_software(self, analysis: dict) -> list[dict]:
        """
        Detect target software from PE features (DLLs, registry/path strings, components).
        Returns list of {vendor, product, confidence, source} sorted by confidence DESC.
        """
        import re
        found: dict[tuple[str, str], dict] = {}

        def _add(vendor: str, product: str, confidence: float, source: str) -> None:
            key = (vendor, product)
            if key not in found or found[key]["confidence"] < confidence:
                found[key] = {"vendor": vendor, "product": product,
                               "confidence": confidence, "source": source}

        # 1. DLL imports
        imports_raw = analysis.get("imports", {})
        dll_names: list[str] = []
        if isinstance(imports_raw, dict):
            dll_names = list(imports_raw.get("by_dll", {}).keys())
            if not dll_names:
                for entry in imports_raw.get("functions", []):
                    if isinstance(entry, dict) and entry.get("dll"):
                        dll_names.append(entry["dll"])
        for dll in dll_names:
            base = dll.lower().replace(".dll", "").replace(".exe", "")
            for key, vp in self._TARGET_DLL_MAP.items():
                if key in base:
                    _add(vp[0], vp[1], 0.80, f"DLL import: {dll}")
                    break

        # 2. Registry key strings
        strings_all: list[str] = []
        strings_data = analysis.get("strings", {})
        if isinstance(strings_data, dict):
            for v in strings_data.values():
                if isinstance(v, list):
                    strings_all.extend(str(x) for x in v)
        for pattern, vp in self._TARGET_REGISTRY_PATTERNS:
            for s in strings_all:
                if re.search(pattern, s, re.IGNORECASE):
                    _add(vp[0], vp[1], 0.70, f"Registry string: {s[:60]}")
                    break

        # 3. File path strings
        for pattern, vp in self._TARGET_PATH_PATTERNS:
            for s in strings_all:
                if re.search(pattern, s, re.IGNORECASE):
                    _add(vp[0], vp[1], 0.60, f"Path string: {s[:60]}")
                    break

        # 4. Generic string patterns
        for pattern, vp in self._TARGET_STRING_PATTERNS:
            for s in strings_all:
                if re.search(pattern, s, re.IGNORECASE):
                    _add(vp[0], vp[1], 0.50, f"String match: {s[:60]}")
                    break

        # 5. Components from static_analyzer
        for comp in analysis.get("components", []):
            v = comp.get("cpe_vendor", "")
            p = comp.get("cpe_product", "")
            if v and p:
                _add(v, p, 0.65, f"Component: {comp.get('name', '')}")

        results = sorted(found.values(), key=lambda x: -x["confidence"])

        # If specific target found, push Windows-generic to back
        specific = [r for r in results if r["product"] != "windows"]
        if specific:
            results = specific + [r for r in results if r["product"] == "windows"]

        return results

    def _score_relevance(self, cve: dict, active_behaviors: list[str], analysis: dict) -> float:
        """
        Score relevance of a CVE to the PE analysis context.
        Returns float from -1.0 to 1.0.
        """
        desc = (cve.get("description") or "").lower()
        score = 0.0

        # Boost for Windows/native terms
        for term in self._WINDOWS_TERMS:
            if term in desc:
                score += 0.15
                break

        # Boost for matching behavior keywords
        for behavior in active_behaviors:
            keywords = self._BEHAVIOR_KEYWORDS.get(behavior, [])
            for kw in keywords:
                if kw in desc:
                    score += 0.10
                    break

        # Boost for Windows CPE
        for cpe in (cve.get("cpe_list") or []):
            if "microsoft:windows" in str(cpe).lower():
                score += 0.20
                break

        # Penalize web-only terms
        for term in self._WEB_ONLY_TERMS:
            if term in desc:
                score -= 0.30
                break

        return max(-1.0, min(1.0, score))

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
            'prediction_method': str, # 'secbert_cwe_classifier' | 'rule_based'
            'method':         str,    # always 'cwe_behavior_prediction'
            'summary':        str,    # human-readable explanation
        }
        """
        print("[CWE] Running CWE behavior prediction (Hướng 3) …")

        # Step 1: Predict CWEs (ML hoặc rule-based)
        predicted, pred_method = self._predict_cwes(analysis)

        if not predicted:
            return {
                "predicted_cwes":    [],
                "cve_results":       [],
                "total_cves":        0,
                "prediction_method": pred_method,
                "method":            "cwe_behavior_prediction",
                "summary":           "No behavioral indicators detected — cannot predict CWE.",
            }

        # Log predictions
        print(f"[CWE] Predicted {len(predicted)} CWE(s) via {pred_method}:")
        for p in predicted:
            print(f"      {p['cwe_id']} ({p['label']}, conf={p['confidence']:.2f}): {p['name']}")

        # Build keyword from PE context to filter NVD results
        import re as _re
        _JUNK = {"unknown", "n/a", "none", "na", "", "null"}

        def _is_useful(s: str) -> bool:
            if s.lower() in _JUNK:
                return False
            if _re.search(r'\d+\.\d+', s.lower()):
                return False
            return True

        cpe_info = analysis.get("cpe_info", {})
        pe_info  = analysis.get("pe_info", {})
        vendor   = (cpe_info.get("vendor") or pe_info.get("company_name") or "").strip()
        product  = (cpe_info.get("product") or pe_info.get("product_name") or "").strip()
        parts    = []
        if _is_useful(vendor):
            parts.append(vendor)
        if _is_useful(product) and product.lower() != vendor.lower():
            parts.append(product)
        kw_filter = " ".join(parts) if parts else None
        if kw_filter:
            print(f"[CWE] Keyword filter: '{kw_filter}'")

        # Step 2: Detect target software from PE features
        targets = self._detect_target_software(analysis)
        if targets:
            print(f"[CWE] Detected {len(targets)} target(s): " +
                  ", ".join(f"{t['vendor']} {t['product']} (conf={t['confidence']:.2f})"
                            for t in targets[:3]))

        # Step 3: Query NVD
        all_cves: list[dict] = []
        seen_ids: set[str]   = set()

        def _add_cves(cves: list[dict], cwe_id: str, pred: dict) -> None:
            for cve in cves:
                cid = cve.get("cve_id", "")
                if cid and cid not in seen_ids:
                    seen_ids.add(cid)
                    cve["matched_cwe"]            = cwe_id
                    cve["matched_cwe_name"]       = pred["name"]
                    cve["matched_cwe_confidence"] = pred["confidence"]
                    all_cves.append(cve)

        if targets:
            # Query CWE + target keyword for top 2 targets × top 3 CWEs
            for target in targets[:2]:
                target_kw = f"{target['vendor']} {target['product']}".replace("_", " ")
                for pred in predicted[:3]:
                    cwe_id = pred["cwe_id"]
                    print(f"[CWE] Querying NVD: {cwe_id} + '{target_kw}' …")
                    cves = self.nvd_api.search_by_cwe(cwe_id,
                                                       max_results=self.max_cves_per_cwe,
                                                       keyword=target_kw)
                    if not cves:
                        print(f"[CWE] CWE+target returned 0 — trying keyword only: '{target_kw}'")
                        cves = self.nvd_api.search_by_keyword(target_kw,
                                                              max_results=self.max_cves_per_cwe)
                    _add_cves(cves, cwe_id, pred)

            # Supplement with generic CWE queries if < 5 CVEs
            if len(all_cves) < 5:
                print(f"[CWE] Only {len(all_cves)} CVEs — supplementing with generic CWE queries")
                for pred in predicted[:self.top_cwes]:
                    cwe_id = pred["cwe_id"]
                    cves = self.nvd_api.search_by_cwe(cwe_id,
                                                       max_results=self.max_cves_per_cwe,
                                                       keyword=None)
                    _add_cves(cves, cwe_id, pred)
        else:
            # No target detected: fallback CWE-only
            for pred in predicted[:self.top_cwes]:
                cwe_id = pred["cwe_id"]
                print(f"[CWE] Querying NVD for {cwe_id} …")
                cves = self.nvd_api.search_by_cwe(cwe_id,
                                                   max_results=self.max_cves_per_cwe,
                                                   keyword=kw_filter)
                if not cves and kw_filter:
                    print(f"[CWE] Keyword {kw_filter!r} returned 0 — retrying without keyword")
                    cves = self.nvd_api.search_by_cwe(cwe_id,
                                                       max_results=self.max_cves_per_cwe,
                                                       keyword=None)
                _add_cves(cves, cwe_id, pred)

        # Step 4: Relevance scoring + filtering
        active_behaviors = list(analysis.get("imports", {}).get("by_category", {}).keys())
        for cve in all_cves:
            cve["_relevance_score"] = self._score_relevance(cve, active_behaviors, analysis)

        all_cves = [c for c in all_cves if c.get("_relevance_score", 0) >= 0]

        all_cves.sort(
            key=lambda c: (
                c.get("_relevance_score", 0) * 0.5
                + c.get("matched_cwe_confidence", 0) * 0.3
                + (c.get("cvss_score") or 0) / 10 * 0.2
            ),
            reverse=True,
        )

        # Step 5: Build summary
        top_cwe_names = ", ".join(
            f"{p['cwe_id']} ({p['name']})" for p in predicted[:3]
        )
        risk_level  = analysis.get("risk", {}).get("level", "UNKNOWN")
        target_info = ""
        if targets:
            target_info = f" Targeting: {targets[0]['vendor']} {targets[0]['product']}.".replace("_", " ")
        summary = (
            f"No CPE identified. Based on behavioral analysis (risk level: {risk_level}), "
            f"this binary exhibits characteristics associated with: {top_cwe_names}.{target_info} "
            f"Showing {min(len(all_cves), 20)} CVEs matching these weakness categories."
        )

        print(f"[CWE] Done — {len(all_cves)} unique CVEs from CWE+target queries")

        return {
            "predicted_cwes":    predicted,
            "cve_results":       all_cves[:20],
            "total_cves":        len(all_cves),
            "prediction_method": pred_method,
            "method":            "cwe_behavior_prediction",
            "summary":           summary,
            "detected_targets":  targets,
        }
