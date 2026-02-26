# backend/codebert_analyzer.py

"""
CodeBERT-Based Deep PE Behavior Analyzer
=========================================

Uses microsoft/codebert-base to perform deep semantic analysis of PE import tables.

Approach:
    PE import function names (VirtualAlloc, CreateRemoteThread, etc.) are valid
    programming language tokens that CodeBERT was trained on. By treating suspicious
    API sequences as "code", we can:
      1. Embed the API sequence → dense semantic vector
      2. Compare against pre-defined malware behavior pattern vectors
      3. Identify behavioral signatures beyond simple keyword matching

Advantages over keyword matching:
    - Two files using different API subsets for the same attack → similar embeddings
    - Detects novel API combinations not in any hardcoded list
    - Provides similarity scores (not just binary flags)
    - Explains WHY a pattern was detected

Reference:
    Feng et al. (2020). "CodeBERT: A Pre-Trained Model for Programming and
    Natural Languages." EMNLP 2020 Findings. arXiv:2002.08155
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Reference malware behavior patterns ───────────────────────────────────────
# Each pattern describes a known attack technique with the APIs that characterize it.
# These are embedded with CodeBERT at load time → reference vectors.
MALWARE_PATTERNS = {
    "Process Hollowing": {
        "apis": [
            "VirtualAllocEx", "WriteProcessMemory", "NtUnmapViewOfSection",
            "CreateRemoteThread", "OpenProcess", "ResumeThread"
        ],
        "description": (
            "Allocates memory in a remote process, unmaps the original executable section, "
            "injects shellcode, and resumes thread execution in the hollowed process."
        ),
        "severity": "CRITICAL",
        "mitre": "T1055.012",
    },
    "Reflective DLL Injection": {
        "apis": [
            "VirtualAlloc", "LoadLibrary", "GetProcAddress",
            "WriteProcessMemory", "CreateRemoteThread"
        ],
        "description": (
            "Loads a DLL directly from memory without touching disk, "
            "bypassing standard DLL load monitoring."
        ),
        "severity": "CRITICAL",
        "mitre": "T1055.001",
    },
    "Thread Hijacking": {
        "apis": [
            "OpenProcess", "SuspendThread", "SetThreadContext",
            "VirtualAllocEx", "WriteProcessMemory", "ResumeThread"
        ],
        "description": (
            "Suspends an existing thread, overwrites its context register to redirect "
            "execution to injected code, then resumes it."
        ),
        "severity": "CRITICAL",
        "mitre": "T1055.003",
    },
    "Keylogger": {
        "apis": [
            "SetWindowsHookEx", "GetAsyncKeyState",
            "GetForegroundWindow", "GetWindowText", "CallNextHookEx"
        ],
        "description": (
            "Hooks keyboard events via Windows hook mechanism, captures keystrokes "
            "and window context for credential harvesting."
        ),
        "severity": "HIGH",
        "mitre": "T1056.001",
    },
    "Ransomware Core": {
        "apis": [
            "CryptEncrypt", "CryptGenKey", "CryptAcquireContext",
            "FindFirstFile", "FindNextFile", "DeleteFile"
        ],
        "description": (
            "Enumerates file system, generates an encryption key, "
            "encrypts victim files, and destroys originals."
        ),
        "severity": "CRITICAL",
        "mitre": "T1486",
    },
    "Network Backdoor / C2": {
        "apis": [
            "WSAStartup", "socket", "connect", "recv",
            "send", "CreateProcess", "ShellExecute"
        ],
        "description": (
            "Establishes a network connection to a C2 server, "
            "receives commands, and executes them locally."
        ),
        "severity": "CRITICAL",
        "mitre": "T1071.001",
    },
    "Privilege Escalation via Token Impersonation": {
        "apis": [
            "OpenProcessToken", "AdjustTokenPrivileges",
            "ImpersonateLoggedOnUser", "DuplicateTokenEx",
            "CreateProcessWithTokenW"
        ],
        "description": (
            "Obtains a high-privilege process token, duplicates it, "
            "and spawns a new process running under the elevated identity."
        ),
        "severity": "HIGH",
        "mitre": "T1134",
    },
    "Anti-Debug / Sandbox Evasion": {
        "apis": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "NtSetInformationThread",
            "FindWindow", "OutputDebugString"
        ],
        "description": (
            "Detects debugging tools and analysis environments; "
            "alters thread information to hide from debuggers."
        ),
        "severity": "MEDIUM",
        "mitre": "T1497",
    },
    "Registry Persistence": {
        "apis": [
            "RegOpenKeyEx", "RegSetValueEx", "RegCreateKeyEx",
            "RegDeleteValue", "RegQueryValueEx"
        ],
        "description": (
            "Writes malware path into HKCU/HKLM Run registry keys "
            "to maintain persistence across system reboots."
        ),
        "severity": "MEDIUM",
        "mitre": "T1547.001",
    },
    "Service Installation for Persistence": {
        "apis": [
            "OpenSCManager", "CreateService", "StartService",
            "ControlService", "RegisterServiceCtrlHandler"
        ],
        "description": (
            "Installs itself as a Windows service to run with SYSTEM privileges "
            "and persist through reboots."
        ),
        "severity": "HIGH",
        "mitre": "T1543.003",
    },
    "Credential Dumping": {
        "apis": [
            "OpenProcess", "ReadProcessMemory", "OpenProcessToken",
            "LookupPrivilegeValue", "AdjustTokenPrivileges"
        ],
        "description": (
            "Reads memory of LSASS or other credential-storing processes "
            "to extract plaintext credentials or hashes."
        ),
        "severity": "CRITICAL",
        "mitre": "T1003",
    },
    "Dynamic Code Loading": {
        "apis": [
            "VirtualAlloc", "VirtualProtect", "LoadLibrary",
            "GetProcAddress", "LdrLoadDll"
        ],
        "description": (
            "Dynamically allocates executable memory, changes page protection, "
            "and loads code at runtime — common in packers and loaders."
        ),
        "severity": "HIGH",
        "mitre": "T1027",
    },
}


# ── Singleton instance ─────────────────────────────────────────────────────────

_instance: Optional["CodeBERTPEAnalyzer"] = None


def get_analyzer() -> "CodeBERTPEAnalyzer":
    global _instance
    if _instance is None:
        _instance = CodeBERTPEAnalyzer()
    return _instance


def is_available() -> bool:
    return get_analyzer().is_available()


def analyze(suspicious_by_category: dict, all_suspicious: list) -> dict:
    return get_analyzer().analyze(suspicious_by_category, all_suspicious)


# ── Main class ─────────────────────────────────────────────────────────────────

class CodeBERTPEAnalyzer:
    """
    CodeBERT-powered PE behavior analyzer.

    Treats PE import sequences as code tokens, encodes them with CodeBERT,
    and matches against pre-computed malware behavior pattern embeddings.
    """

    MODEL_NAME = "microsoft/codebert-base"

    # Cosine similarity threshold for a pattern to be "detected"
    DETECTION_THRESHOLD = 0.60

    def __init__(self):
        self.tokenizer = None
        self.model = None
        self._torch = None
        self._F = None
        self._pattern_embeddings: dict = {}
        self._available = False
        self._load()

    def _load(self):
        """Load CodeBERT model and pre-compute reference pattern embeddings."""
        try:
            import torch
            import torch.nn.functional as F
            from transformers import AutoTokenizer, AutoModel

            logger.info(f"[CodeBERT] Loading {self.MODEL_NAME} …")
            self.tokenizer = AutoTokenizer.from_pretrained(self.MODEL_NAME)
            self.model = AutoModel.from_pretrained(self.MODEL_NAME)
            self.model.eval()
            self._torch = torch
            self._F = F
            self._available = True

            # Pre-compute embeddings for all reference patterns
            self._precompute_patterns()
            logger.info(
                f"[CodeBERT] Ready — {len(self._pattern_embeddings)} reference patterns loaded"
            )
        except Exception as e:
            logger.warning(f"[CodeBERT] Not available: {e}")
            self._available = False

    def is_available(self) -> bool:
        return self._available

    # ── Encoding helpers ──────────────────────────────────────────────────────

    def _encode(self, text: str):
        """Encode text → [CLS] token embedding (no gradient)."""
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            max_length=512,
            truncation=True,
            padding=True,
        )
        with self._torch.no_grad():
            outputs = self.model(**inputs)
        # [CLS] token = outputs.last_hidden_state[:, 0, :]
        return outputs.last_hidden_state[:, 0, :].squeeze()

    def _cosine_sim(self, v1, v2) -> float:
        return float(
            self._F.cosine_similarity(v1.unsqueeze(0), v2.unsqueeze(0)).item()
        )

    @staticmethod
    def _apis_to_code(apis: list) -> str:
        """
        Convert a list of Windows API names to a pseudo-code string.

        Example: ["VirtualAlloc", "WriteProcessMemory"] →
                 "VirtualAlloc() WriteProcessMemory()"

        CodeBERT was trained on actual source code, so this syntax is
        more natural for the model than plain space-separated tokens.
        """
        return " ".join(f"{api}()" for api in apis if api)

    # ── Pre-computation ───────────────────────────────────────────────────────

    def _precompute_patterns(self):
        """Encode all reference malware patterns into embeddings at startup."""
        for name, info in MALWARE_PATTERNS.items():
            code_text = self._apis_to_code(info["apis"])
            self._pattern_embeddings[name] = self._encode(code_text)
        logger.info(
            f"[CodeBERT] Pattern embeddings computed for: "
            f"{', '.join(self._pattern_embeddings.keys())}"
        )

    # ── Main analysis ─────────────────────────────────────────────────────────

    def analyze(
        self,
        suspicious_by_category: dict,
        all_suspicious: list,
    ) -> dict:
        """
        Deep-analyze a PE file's suspicious imports using CodeBERT.

        Parameters
        ----------
        suspicious_by_category : dict
            {category_name: [{function, dll, risk}]}  from PEStaticAnalyzer
        all_suspicious : list
            Flat list of all suspicious API entries

        Returns
        -------
        dict
            available        : bool
            codebert_score   : float  0.0–1.0  overall maliciousness probability
            detected_patterns: list[dict]  patterns above DETECTION_THRESHOLD
            all_scores       : list[dict]  all patterns sorted by similarity
            behavior_summary : str   human-readable sentence
            top_pattern      : str | None
            top_similarity   : float
            confidence       : str   "high" / "medium" / "low" / "none"
            model            : str
        """
        if not self._available:
            return {
                "available": False,
                "reason": "CodeBERT model not loaded (run: pip install transformers torch)",
            }

        if not all_suspicious:
            return {
                "available": True,
                "codebert_score": 0.0,
                "detected_patterns": [],
                "all_scores": [],
                "behavior_summary": (
                    "No suspicious APIs detected — file appears benign at import level."
                ),
                "top_pattern": None,
                "top_similarity": 0.0,
                "confidence": "none",
                "model": self.MODEL_NAME,
            }

        # Build API sequence text from all suspicious imports
        api_names = [s["function"] for s in all_suspicious if s.get("function")]
        if not api_names:
            return {
                "available": True,
                "codebert_score": 0.0,
                "detected_patterns": [],
                "all_scores": [],
                "behavior_summary": "No API names extracted.",
                "top_pattern": None,
                "top_similarity": 0.0,
                "confidence": "none",
                "model": self.MODEL_NAME,
            }

        api_text = self._apis_to_code(api_names)

        # Encode the file's API sequence
        file_emb = self._encode(api_text)

        # Compare against every reference pattern
        scores = []
        for name, ref_emb in self._pattern_embeddings.items():
            sim = self._cosine_sim(file_emb, ref_emb)
            info = MALWARE_PATTERNS[name]
            scores.append({
                "pattern": name,
                "similarity": round(float(sim), 4),
                "description": info["description"],
                "severity": info["severity"],
                "mitre": info["mitre"],
            })

        # Sort descending by similarity
        scores.sort(key=lambda x: -x["similarity"])

        # Patterns above detection threshold → "detected"
        detected = [s for s in scores if s["similarity"] >= self.DETECTION_THRESHOLD]

        top = scores[0] if scores else None
        top_sim = top["similarity"] if top else 0.0

        # Overall maliciousness: exponentially decaying sum of top-3 similarities
        codebert_score = sum(
            s["similarity"] * (0.5 ** i) for i, s in enumerate(scores[:3])
        )
        # Normalize to [0, 1]
        codebert_score = round(min(codebert_score, 1.0), 4)

        # Confidence label
        if top_sim >= 0.80:
            confidence = "high"
        elif top_sim >= 0.65:
            confidence = "medium"
        elif top_sim >= 0.50:
            confidence = "low"
        else:
            confidence = "none"

        # Human-readable summary
        if detected:
            pattern_names = ", ".join(f'"{d["pattern"]}"' for d in detected[:3])
            behavior_summary = (
                f"CodeBERT detected behavioral similarity to known attack technique(s): "
                f"{pattern_names}."
            )
        elif top:
            behavior_summary = (
                f"API pattern most similar to '{top['pattern']}' "
                f"(similarity={top_sim:.2f}) — below detection threshold of "
                f"{self.DETECTION_THRESHOLD}."
            )
        else:
            behavior_summary = "Could not match API sequence to any known pattern."

        return {
            "available": True,
            "codebert_score": codebert_score,
            "detected_patterns": detected,
            "all_scores": scores[:10],       # top-10 for UI
            "behavior_summary": behavior_summary,
            "top_pattern": top["pattern"] if top else None,
            "top_similarity": top_sim,
            "confidence": confidence,
            "input_api_count": len(api_names),
            "model": self.MODEL_NAME,
        }
