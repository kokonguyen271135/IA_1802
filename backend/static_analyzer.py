# backend/static_analyzer.py

"""
PE Binary Static Analyzer
Analyzes Windows PE files (exe, dll, sys) for suspicious behaviors.
Uses pefile (already installed) + standard library only.
"""

import pefile
import hashlib
import math
import re
from pathlib import Path
from datetime import datetime

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class PEStaticAnalyzer:
    """Static analyzer for PE binary files (exe, dll, sys)"""

    # -------------------------------------------------------------------------
    # Known embedded library/component version patterns
    # Used for vulnerability-focused component detection
    # -------------------------------------------------------------------------
    COMPONENT_PATTERNS = {
        # Format: component_name → (regex, cpe_vendor, cpe_product)
        'OpenSSL':       (r'OpenSSL\s+(\d+\.\d+[\.\d\w\-]*)',   'openssl',    'openssl'),
        'libcurl':       (r'libcurl[/\s]+(\d+\.\d+[\.\d]*)',     'haxx',       'libcurl'),
        'zlib':          (r'zlib[/\s]+(\d+\.\d+[\.\d]*)',        'zlib',       'zlib'),
        'Python':        (r'Python\s+(\d+\.\d+[\.\d]*)',          'python',     'python'),
        'SQLite':        (r'SQLite[/\s]+(\d+\.\d+[\.\d]*)',       'sqlite',     'sqlite'),
        'Lua':           (r'Lua\s+(\d+\.\d+[\.\d]*)',             'lua',        'lua'),
        'Expat':         (r'expat[/\s]+(\d+\.\d+[\.\d]*)',        'libexpat',   'libexpat'),
        'libxml2':       (r'libxml2[/\s]+(\d+\.\d+[\.\d]*)',      'xmlsoft',    'libxml2'),
        'libpng':        (r'libpng[/\s]+(\d+\.\d+[\.\d]*)',       'libpng',     'libpng'),
        'libjpeg':       (r'libjpeg[/\s]+(\d+\.\d+[\.\d]*)',      'ijg',        'libjpeg'),
        'PCRE':          (r'PCRE\s+(\d+\.\d+[\.\d]*)',             'pcre',       'pcre'),
        'Boost':         (r'Boost\s+(\d+\.\d+[\.\d]*)',            'boost',      'boost'),
        'Qt':            (r'Qt\s+(\d+\.\d+[\.\d]*)',               'qt',         'qt'),
        'WinRAR':        (r'WinRAR\s+(\d+\.\d+[\.\d]*)',           'rarlab',     'winrar'),
        '7-Zip':         (r'7-Zip\s+(\d+\.\d+[\.\d]*)',            '7-zip',      '7-zip'),
        'Chromium':      (r'Chromium[/\s]+(\d+\.\d+[\.\d\w]*)',   'google',     'chrome'),
        'Electron':      (r'Electron[/\s]+(\d+\.\d+[\.\d]*)',     'github',     'electron'),
        'Node.js':       (r'node[.js]*\s+v?(\d+\.\d+[\.\d]*)',    'nodejs',     'node.js'),
        'V8':            (r'V8[/\s]+(\d+\.\d+[\.\d]*)',            'google',     'v8'),
        'OpenCV':        (r'OpenCV[/\s]+(\d+\.\d+[\.\d]*)',        'opencv',     'opencv'),
    }

    # DLL filename → component info (version from filename when possible)
    DLL_COMPONENT_MAP = {
        'openssl':        {'component': 'OpenSSL',   'cpe_vendor': 'openssl',  'cpe_product': 'openssl'},
        'libssl':         {'component': 'OpenSSL',   'cpe_vendor': 'openssl',  'cpe_product': 'openssl'},
        'libcrypto':      {'component': 'OpenSSL',   'cpe_vendor': 'openssl',  'cpe_product': 'openssl'},
        'libcurl':        {'component': 'libcurl',   'cpe_vendor': 'haxx',     'cpe_product': 'libcurl'},
        'curl':           {'component': 'libcurl',   'cpe_vendor': 'haxx',     'cpe_product': 'libcurl'},
        'python':         {'component': 'Python',    'cpe_vendor': 'python',   'cpe_product': 'python'},
        'sqlite3':        {'component': 'SQLite',    'cpe_vendor': 'sqlite',   'cpe_product': 'sqlite'},
        'libxml2':        {'component': 'libxml2',   'cpe_vendor': 'xmlsoft',  'cpe_product': 'libxml2'},
        'zlib':           {'component': 'zlib',      'cpe_vendor': 'zlib',     'cpe_product': 'zlib'},
        'node':           {'component': 'Node.js',   'cpe_vendor': 'nodejs',   'cpe_product': 'node.js'},
        'v8':             {'component': 'V8',         'cpe_vendor': 'google',   'cpe_product': 'v8'},
        'msvcr':          {'component': 'MSVC Runtime', 'cpe_vendor': 'microsoft', 'cpe_product': 'visual_c++'},
        'msvcp':          {'component': 'MSVC Runtime', 'cpe_vendor': 'microsoft', 'cpe_product': 'visual_c++'},
        'vcruntime':      {'component': 'MSVC Runtime', 'cpe_vendor': 'microsoft', 'cpe_product': 'visual_c++'},
    }

    # -------------------------------------------------------------------------
    # Suspicious API database - categorized by behavior
    # -------------------------------------------------------------------------
    SUSPICIOUS_APIS = {
        'Process Injection': {
            'risk': 'HIGH',
            'apis': [
                'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
                'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
                'CreateRemoteThreadEx', 'NtCreateThreadEx', 'RtlCreateUserThread',
                'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'QueueUserAPC',
                'NtQueueApcThread', 'SetThreadContext', 'GetThreadContext',
                'SuspendThread', 'ResumeThread', 'MapViewOfFile', 'MapViewOfFileEx',
                'CreateFileMapping', 'OpenProcess', 'NtOpenProcess',
            ]
        },
        'Anti-Debugging': {
            'risk': 'MEDIUM',
            'apis': [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                'NtQueryInformationProcess', 'OutputDebugString',
                'NtSetInformationThread', 'ZwQueryInformationProcess',
                'FindWindow', 'FindWindowEx',
            ]
        },
        'Network Communication': {
            'risk': 'MEDIUM',
            'apis': [
                'WSAStartup', 'socket', 'connect', 'bind', 'listen', 'accept',
                'send', 'recv', 'sendto', 'recvfrom', 'gethostbyname', 'getaddrinfo',
                'InternetOpen', 'InternetConnect', 'InternetReadFile', 'InternetWriteFile',
                'HttpOpenRequest', 'HttpSendRequest', 'HttpQueryInfo',
                'URLDownloadToFile', 'URLDownloadToCacheFile',
                'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest',
                'FtpPutFile', 'FtpGetFile',
            ]
        },
        'Code Execution': {
            'risk': 'CRITICAL',
            'apis': [
                'ShellExecute', 'ShellExecuteEx', 'WinExec', 'CreateProcess',
                'CreateProcessAsUser', 'CreateProcessWithLogonW',
                'NtCreateProcess', 'ZwCreateProcess', 'RtlCreateProcess',
            ]
        },
        'Keylogging': {
            'risk': 'HIGH',
            'apis': [
                'SetWindowsHookEx', 'UnhookWindowsHookEx', 'CallNextHookEx',
                'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState',
                'RegisterHotKey', 'GetForegroundWindow', 'GetWindowText',
            ]
        },
        'Registry Manipulation': {
            'risk': 'LOW',
            'apis': [
                'RegOpenKey', 'RegOpenKeyEx', 'RegCreateKey', 'RegCreateKeyEx',
                'RegSetValue', 'RegSetValueEx', 'RegDeleteKey', 'RegDeleteValue',
                'RegQueryValue', 'RegQueryValueEx', 'RegEnumKey', 'RegEnumValue',
                'SHGetValue', 'SHSetValue', 'SHDeleteKey',
            ]
        },
        'Cryptography': {
            'risk': 'LOW',
            'apis': [
                'CryptEncrypt', 'CryptDecrypt', 'CryptHashData', 'CryptCreateHash',
                'CryptDeriveKey', 'CryptGenKey', 'CryptAcquireContext',
                'BCryptEncrypt', 'BCryptDecrypt', 'BCryptHashData',
                'NCryptEncrypt', 'NCryptDecrypt',
            ]
        },
        'Privilege Escalation': {
            'risk': 'HIGH',
            'apis': [
                'AdjustTokenPrivileges', 'LookupPrivilegeValue', 'OpenProcessToken',
                'OpenThreadToken', 'ImpersonateLoggedOnUser', 'DuplicateToken',
                'DuplicateTokenEx', 'SetTokenInformation', 'CreateProcessWithTokenW',
            ]
        },
        'Service Manipulation': {
            'risk': 'MEDIUM',
            'apis': [
                'OpenSCManager', 'CreateService', 'StartService', 'StopService',
                'DeleteService', 'ControlService', 'QueryServiceStatus',
                'RegisterServiceCtrlHandler', 'SetServiceStatus',
            ]
        },
        'Dynamic Loading': {
            'risk': 'MEDIUM',
            'apis': [
                'LoadLibrary', 'LoadLibraryEx', 'GetProcAddress',
                'LdrLoadDll', 'LdrGetProcedureAddress',
            ]
        },
    }

    # Suspicious string patterns
    STRING_PATTERNS = {
        'URLs': r'https?://[^\s\x00-\x1f\x7f-\xff]{8,}',
        'IP Addresses': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        'Email Addresses': r'[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}',
        'Registry Keys': r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKCR|HKU)\\[^\x00\r\n]{5,}',
        'File Paths': r'[A-Za-z]:\\(?:[^\x00\r\n\\/:*?"<>|]{1,255}\\)*[^\x00\r\n\\/:*?"<>|]{1,255}',
        'Suspicious Commands': r'(?i)(?:cmd\.exe|powershell(?:\.exe)?|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|net\.exe)[^\x00\r\n]{0,120}',
        'Potential Base64': r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    }

    def analyze(self, filepath):
        """
        Main analysis entrypoint.
        Returns a dict with all analysis results.
        """
        filepath = Path(filepath)
        result = {
            'success': False,
            'filename': filepath.name,
            'file_info': {},
            'pe_info': None,
            'sections': [],
            'imports': {},
            'exports': [],
            'strings': {},
            'risk': {},
            'errors': [],
        }

        try:
            # 1. Basic file info + hashes
            result['file_info'] = self._get_file_info(filepath)

            # 2. PE analysis
            try:
                pe = pefile.PE(str(filepath.resolve()), fast_load=False)
                result['pe_info'] = self._analyze_pe_header(pe)
                result['sections'] = self._analyze_sections(pe)
                result['imports'] = self._analyze_imports(pe)
                result['exports'] = self._analyze_exports(pe)
                # 2b. Security mitigations (ASLR, DEP/NX, CFG, Stack Canary, etc.)
                result['security_mitigations'] = self._analyze_security_mitigations(pe)
                # 2c. Disassembly — actual machine code for AI code analysis
                result['disassembly'] = self._disassemble_binary(pe)
                pe.close()
            except pefile.PEFormatError as e:
                result['errors'].append(f'PE parse error: {str(e)}')
                result['pe_info'] = None
            except Exception as e:
                result['errors'].append(f'PE analysis error: {str(e)}')
                result['pe_info'] = None

            # 3. String extraction
            result['strings'] = self._extract_strings(filepath)

            # 4. Component/version detection (for vulnerability assessment)
            result['components'] = self._detect_components(filepath, result)

            # 5. Risk scoring
            result['risk'] = self._calculate_risk(result)

            result['success'] = True

        except Exception as e:
            result['errors'].append(f'Fatal error: {str(e)}')

        return result

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _get_file_info(self, filepath):
        stat = filepath.stat()
        # Chunked hashing - tránh load cả file vào RAM (quan trọng cho file lớn)
        md5    = hashlib.md5()
        sha1   = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(str(filepath), 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            'size': stat.st_size,
            'size_human': self._human_size(stat.st_size),
            'md5':    md5.hexdigest(),
            'sha1':   sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
        }

    def _analyze_pe_header(self, pe):
        machine_map = {
            0x014c: 'x86 (32-bit)',
            0x8664: 'x64 (64-bit)',
            0x01c4: 'ARM',
            0xaa64: 'ARM64',
            0x0200: 'IA-64 (Itanium)',
        }
        subsystem_map = {
            1: 'Native',
            2: 'Windows GUI',
            3: 'Windows Console (CUI)',
            5: 'OS/2 Console',
            7: 'POSIX Console',
            9: 'Windows CE GUI',
            10: 'EFI Application',
            14: 'Xbox',
            16: 'Boot Application',
        }

        machine = pe.FILE_HEADER.Machine
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        ts = pe.FILE_HEADER.TimeDateStamp

        try:
            compile_time = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
            # Sanity check: timestamps before 1995 or after 2035 are likely fake/zeroed
            if ts < 788918400 or ts > 2051222400:
                compile_time += ' (possibly fake)'
        except Exception:
            compile_time = 'Unknown'

        chars = pe.FILE_HEADER.Characteristics

        return {
            'machine': machine_map.get(machine, f'Unknown (0x{machine:04x})'),
            'compile_time': compile_time,
            'is_dll': bool(chars & 0x2000),
            'is_exe': bool(chars & 0x0002),
            'subsystem': subsystem_map.get(subsystem, f'Unknown ({subsystem})'),
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            'num_sections': pe.FILE_HEADER.NumberOfSections,
            'has_debug': hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'),
            'has_tls': hasattr(pe, 'DIRECTORY_ENTRY_TLS'),
            'has_resources': hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'),
        }

    def _analyze_sections(self, pe):
        KNOWN_SECTIONS = {
            '.text', '.data', '.rdata', '.rsrc', '.reloc', '.bss',
            '.idata', '.edata', '.tls', '.pdata', '.debug', '.xdata',
            '.sdata', '.sbss', '.srdata', '.textbss', '.ndata', '.boot',
            'CODE', 'DATA', 'BSS', '.CRT', '.gfids',
        }

        sections = []
        for section in pe.sections:
            try:
                name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            except Exception:
                name = 'Unknown'

            raw_data = section.get_data()
            entropy = self._calculate_entropy(raw_data)
            chars = section.Characteristics

            sections.append({
                'name': name,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'virtual_address': hex(section.VirtualAddress),
                'entropy': round(entropy, 3),
                'high_entropy': entropy > 7.0,
                'suspicious_name': name not in KNOWN_SECTIONS and name != '',
                'executable': bool(chars & 0x20000000),
                'writable': bool(chars & 0x80000000),
                'readable': bool(chars & 0x40000000),
            })

        return sections

    def _analyze_imports(self, pe):
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return {
                'total_dlls': 0,
                'total_functions': 0,
                'dlls': [],
                'suspicious': [],
                'by_category': {},
            }

        all_dlls = {}
        suspicious = []
        by_category = {}
        total_functions = 0

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode('utf-8', errors='replace')
            except Exception:
                dll_name = 'unknown.dll'

            funcs = []
            for imp in entry.imports:
                if imp.name:
                    try:
                        func_name = imp.name.decode('utf-8', errors='replace')
                    except Exception:
                        func_name = f'Ordinal_{imp.ordinal}'
                else:
                    func_name = f'Ordinal_{imp.ordinal}'

                funcs.append(func_name)
                total_functions += 1

                # Check against suspicious API list
                for category, info in self.SUSPICIOUS_APIS.items():
                    for api in info['apis']:
                        if func_name.lower() == api.lower():
                            if category not in by_category:
                                by_category[category] = []
                            entry_data = {
                                'function': func_name,
                                'dll': dll_name.lower(),
                                'risk': info['risk'],
                            }
                            by_category[category].append(entry_data)
                            suspicious.append({
                                'dll': dll_name.lower(),
                                'function': func_name,
                                'category': category,
                                'risk': info['risk'],
                            })
                            break

            all_dlls[dll_name.lower()] = funcs

        return {
            'total_dlls': len(all_dlls),
            'total_functions': total_functions,
            'dlls': [{'name': dll, 'functions': funcs} for dll, funcs in all_dlls.items()],
            'suspicious': suspicious,
            'by_category': by_category,
        }

    def _analyze_exports(self, pe):
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return []

        exports = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                name = exp.name.decode('utf-8', errors='replace') if exp.name else f'Ordinal_{exp.ordinal}'
            except Exception:
                name = f'Ordinal_{exp.ordinal}'

            exports.append({
                'ordinal': exp.ordinal,
                'name': name,
                'address': hex(exp.address) if exp.address else '0x0',
            })

        return exports[:100]  # cap for UI

    MAX_STRING_SCAN_BYTES = 50 * 1024 * 1024  # chỉ scan 50MB đầu tiên

    def _extract_strings(self, filepath):
        with open(str(filepath), 'rb') as f:
            data = f.read(self.MAX_STRING_SCAN_BYTES)

        # Extract printable ASCII strings (min length 6)
        raw_strings = re.findall(rb'[\x20-\x7e]{6,}', data)
        combined = '\n'.join(s.decode('ascii', errors='replace') for s in raw_strings[:8000])

        found = {}
        for category, pattern in self.STRING_PATTERNS.items():
            matches = re.findall(pattern, combined, re.IGNORECASE)
            unique = list(dict.fromkeys(matches))[:30]
            if unique:
                found[category] = unique

        return found

    # -------------------------------------------------------------------------
    # Security Mitigations Analysis
    # Checks PE DllCharacteristics flags and import patterns for
    # compiler/OS security protections. Missing mitigations represent
    # concrete, measurable exploitability factors independent of CVE database.
    # -------------------------------------------------------------------------

    # DllCharacteristics flags
    _DC_HIGH_ENTROPY_VA  = 0x0020  # 64-bit ASLR
    _DC_DYNAMIC_BASE     = 0x0040  # ASLR
    _DC_FORCE_INTEGRITY  = 0x0080  # Require signed images
    _DC_NX_COMPAT        = 0x0100  # DEP / NX
    _DC_NO_ISOLATION     = 0x0200  # No manifest isolation
    _DC_NO_SEH           = 0x0400  # No structured exception handling
    _DC_NO_BIND          = 0x0800  # Prevent IAT binding
    _DC_APPCONTAINER     = 0x1000  # AppContainer (sandboxed)
    _DC_WDM_DRIVER       = 0x2000  # WDM kernel driver
    _DC_GUARD_CF         = 0x4000  # Control Flow Guard

    def _analyze_security_mitigations(self, pe) -> dict:
        """
        Analyze PE security mitigations by inspecting DllCharacteristics,
        import entries, and directory entries.

        Returns a structured report of present/missing mitigations and
        a 0-100 security posture score (100 = all protections present).
        """
        dc = pe.OPTIONAL_HEADER.DllCharacteristics

        # ── Stack Canary: GS protection (/GS compiler flag) ─────────────────
        # Compilers insert __security_check_cookie when /GS is active.
        has_stack_canary = False
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and b'__security_check_cookie' in imp.name:
                        has_stack_canary = True
                        break
                if has_stack_canary:
                    break

        # ── Authenticode digital signature ───────────────────────────────────
        has_signature = (
            hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')
            and len(pe.DIRECTORY_ENTRY_SECURITY) > 0
        )

        # ── Collect present mitigations ──────────────────────────────────────
        flags = {
            'aslr':             bool(dc & self._DC_DYNAMIC_BASE),
            'high_entropy_va':  bool(dc & self._DC_HIGH_ENTROPY_VA),
            'dep_nx':           bool(dc & self._DC_NX_COMPAT),
            'cfg':              bool(dc & self._DC_GUARD_CF),
            'safe_seh':         not bool(dc & self._DC_NO_SEH),
            'force_integrity':  bool(dc & self._DC_FORCE_INTEGRITY),
            'appcontainer':     bool(dc & self._DC_APPCONTAINER),
            'stack_canary':     has_stack_canary,
            'authenticode':     has_signature,
        }

        # ── Missing critical mitigations → concrete attack impact ────────────
        missing = []

        if not flags['aslr']:
            missing.append({
                'name':        'ASLR',
                'cwe':         'CWE-119',
                'risk':        'HIGH',
                'description': 'Not compiled with /DYNAMICBASE — memory layout is fixed',
                'impact':      (
                    'Attacker can predict exact addresses of code/heap/stack. '
                    'Reliable exploitation of ANY memory-corruption bug becomes trivial '
                    'without needing an information-leak gadget first.'
                ),
            })

        if not flags['dep_nx']:
            missing.append({
                'name':        'DEP / NX',
                'cwe':         'CWE-693',
                'risk':        'HIGH',
                'description': 'Not compiled with /NXCOMPAT — stack/heap are executable',
                'impact':      (
                    'Shellcode can be placed in data or stack memory and executed directly. '
                    'Classic stack-based buffer overflows (CWE-121) become immediately '
                    'exploitable without ROP chains.'
                ),
            })

        if not flags['stack_canary']:
            missing.append({
                'name':        'Stack Canary (GS)',
                'cwe':         'CWE-121',
                'risk':        'HIGH',
                'description': 'Not compiled with /GS — no stack buffer overflow detection',
                'impact':      (
                    'Stack-based overflows can silently overwrite saved return addresses. '
                    'Combined with missing DEP, this directly leads to code execution '
                    'via a single overflow.'
                ),
            })

        if not flags['cfg']:
            missing.append({
                'name':        'CFG (Control Flow Guard)',
                'cwe':         'CWE-691',
                'risk':        'MEDIUM',
                'description': 'Not compiled with /guard:cf — indirect calls are unverified',
                'impact':      (
                    'Return-Oriented Programming (ROP) and Jump-Oriented Programming (JOP) '
                    'attacks are feasible. Attacker can redirect execution to arbitrary '
                    'gadgets by corrupting function pointers or vtables.'
                ),
            })

        if not flags['safe_seh']:
            missing.append({
                'name':        'SafeSEH',
                'cwe':         'CWE-755',
                'risk':        'MEDIUM',
                'description': 'Structured Exception Handler Overwrite Protection absent',
                'impact':      (
                    'SEH chains can be overwritten to hijack execution via exception '
                    'handling (classic SEH-overwrite exploit technique).'
                ),
            })

        if not flags['authenticode']:
            missing.append({
                'name':        'Authenticode Signature',
                'cwe':         'CWE-345',
                'risk':        'LOW',
                'description': 'Binary carries no digital signature',
                'impact':      (
                    'Cannot cryptographically verify the publisher or detect tampering. '
                    'Binary may be replaced with a trojanized version without detection.'
                ),
            })

        # ── Posture score: weighted sum of critical protections ──────────────
        weight_map = {
            'aslr':         25,
            'dep_nx':       25,
            'stack_canary': 25,
            'cfg':          15,
            'authenticode': 10,
        }
        posture_score = sum(w for k, w in weight_map.items() if flags.get(k, False))

        if posture_score >= 85:
            posture_level = 'STRONG'
        elif posture_score >= 60:
            posture_level = 'MODERATE'
        elif posture_score >= 30:
            posture_level = 'WEAK'
        else:
            posture_level = 'CRITICAL'

        return {
            'flags':          flags,
            'missing':        missing,
            'posture_score':  posture_score,
            'posture_level':  posture_level,
            'dll_chars_hex':  hex(dc),
        }

    # -------------------------------------------------------------------------
    # Binary Disassembly — for AI code-level analysis
    # Uses Capstone to extract real assembly code so Claude can read it and
    # identify vulnerability patterns directly in the binary's logic.
    # -------------------------------------------------------------------------

    MAX_DISASM_INSTRUCTIONS = 150   # per chunk sent to AI
    MAX_DISASM_CHUNKS       = 4     # entry point + up to 3 suspicious function stubs

    def _disassemble_binary(self, pe) -> dict:
        """
        Disassemble key code regions of the PE binary.

        Extracts:
          1. Entry point code  — the first instructions executed
          2. Code stubs near suspicious API calls — shows HOW dangerous
             APIs (VirtualAllocEx, WriteProcessMemory, etc.) are invoked
             and what precedes/follows each call

        Returns:
          {
            "available": bool,
            "arch": "x86" | "x64",
            "entry_point": [{"address": "0x...", "mnemonic": "...", "op_str": "..."}, ...],
            "suspicious_stubs": [
                {"api": "VirtualAllocEx", "instructions": [...]},
                ...
            ],
            "total_instructions": int,
          }
        """
        if not CAPSTONE_AVAILABLE:
            return {"available": False, "reason": "capstone not installed"}

        try:
            # Determine architecture
            machine = pe.FILE_HEADER.Machine
            if machine == 0x8664:    # AMD64
                cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                arch = "x64"
            elif machine == 0x014c:  # i386
                cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                arch = "x86"
            else:
                return {"available": False, "reason": f"Unsupported arch: {hex(machine)}"}

            cs.detail = False  # faster — we only need mnemonic + op_str

            result = {
                "available": True,
                "arch":      arch,
                "entry_point":       [],
                "suspicious_stubs":  [],
                "total_instructions": 0,
            }

            # ── 1. Entry point disassembly ────────────────────────────────
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if ep_rva:
                try:
                    ep_data = pe.get_data(ep_rva, 1024)
                    ep_va   = pe.OPTIONAL_HEADER.ImageBase + ep_rva
                    insns = []
                    for insn in cs.disasm(ep_data, ep_va):
                        insns.append({
                            "address":  f"0x{insn.address:08x}",
                            "mnemonic": insn.mnemonic,
                            "op_str":   insn.op_str,
                            "bytes":    insn.bytes.hex(),
                        })
                        if len(insns) >= self.MAX_DISASM_INSTRUCTIONS:
                            break
                    result["entry_point"] = insns
                    result["total_instructions"] += len(insns)
                except Exception:
                    pass

            # ── 2. Suspicious API stubs ───────────────────────────────────
            # Find code bytes around each import that references a suspicious API.
            # Approach: walk IAT, for each suspicious import find thunk RVA,
            # then disassemble the code section that CALLs into that thunk.
            HIGH_VALUE_APIS = {
                'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                'CreateRemoteThreadEx', 'NtCreateThreadEx',
                'ShellExecute', 'ShellExecuteEx', 'WinExec',
                'SetWindowsHookEx', 'GetAsyncKeyState',
                'AdjustTokenPrivileges', 'OpenProcessToken',
                'URLDownloadToFile', 'InternetReadFile',
                'CryptEncrypt', 'CryptDecrypt',
            }

            stubs_found = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if stubs_found >= self.MAX_DISASM_CHUNKS - 1:
                        break
                    for imp in dll_entry.imports:
                        if stubs_found >= self.MAX_DISASM_CHUNKS - 1:
                            break
                        if not imp.name:
                            continue
                        try:
                            func_name = imp.name.decode('utf-8', errors='replace')
                        except Exception:
                            continue

                        if func_name not in HIGH_VALUE_APIS:
                            continue

                        # imp.address = VA of the IAT slot (pointer to function)
                        # Disassemble ~64 bytes of code leading INTO this call
                        # by scanning .text section for a CALL instruction that
                        # references the IAT slot.
                        thunk_va = imp.address
                        if not thunk_va:
                            continue

                        # Find a code section and scan for CALL [thunk_va]
                        stub_insns = self._find_call_stub(pe, cs, thunk_va, arch)
                        if stub_insns:
                            result["suspicious_stubs"].append({
                                "api":          func_name,
                                "instructions": stub_insns,
                            })
                            result["total_instructions"] += len(stub_insns)
                            stubs_found += 1

            return result

        except Exception as exc:
            return {"available": False, "reason": str(exc)}

    def _find_call_stub(self, pe, cs, thunk_va: int, arch: str) -> list:
        """
        Scan executable sections for a CALL instruction targeting thunk_va.
        Return up to 30 instructions centered on that call site.
        """
        CALL_BYTES_32 = b'\xff\x15'   # CALL DWORD PTR [addr]
        CALL_BYTES_64 = b'\xff\x15'   # CALL QWORD PTR [rip+offset]

        image_base = pe.OPTIONAL_HEADER.ImageBase

        for section in pe.sections:
            chars = section.Characteristics
            if not (chars & 0x20000000):  # not executable
                continue
            try:
                sec_data = section.get_data()
                sec_va   = image_base + section.VirtualAddress

                # Search for indirect CALL pattern
                offset = 0
                while offset < len(sec_data) - 6:
                    pos = sec_data.find(CALL_BYTES_32, offset)
                    if pos == -1:
                        break
                    offset = pos + 1

                    # For x86: CALL [abs32]
                    if arch == "x86" and pos + 6 <= len(sec_data):
                        import struct
                        target = struct.unpack_from('<I', sec_data, pos + 2)[0]
                        if target == thunk_va:
                            return self._disasm_around(cs, sec_data, sec_va, pos, 15)

                    # For x64: CALL [rip + rel32]
                    elif arch == "x64" and pos + 6 <= len(sec_data):
                        import struct
                        rel = struct.unpack_from('<i', sec_data, pos + 2)[0]
                        resolved = sec_va + pos + 6 + rel
                        if resolved == thunk_va:
                            return self._disasm_around(cs, sec_data, sec_va, pos, 15)

            except Exception:
                continue

        return []

    def _disasm_around(self, cs, sec_data: bytes, sec_va: int, call_offset: int,
                       context: int = 15) -> list:
        """
        Disassemble `context` instructions before AND after call_offset.
        Returns list of instruction dicts.
        """
        # Back up to get instructions before the CALL
        start = max(0, call_offset - context * 8)   # rough estimate
        chunk = sec_data[start: call_offset + 64]
        va    = sec_va + start

        insns = []
        for insn in cs.disasm(chunk, va):
            insns.append({
                "address":  f"0x{insn.address:08x}",
                "mnemonic": insn.mnemonic,
                "op_str":   insn.op_str,
                "bytes":    insn.bytes.hex(),
            })
            if len(insns) >= context * 2 + 5:
                break

        return insns

    def _calculate_risk(self, analysis):
        score = 0
        factors = []

        # --- Imports ---
        imports = analysis.get('imports', {})
        suspicious = imports.get('suspicious', [])
        by_category = imports.get('by_category', {})

        critical_count = sum(1 for s in suspicious if s['risk'] == 'CRITICAL')
        high_count     = sum(1 for s in suspicious if s['risk'] == 'HIGH')
        medium_count   = sum(1 for s in suspicious if s['risk'] == 'MEDIUM')

        score += critical_count * 20
        score += high_count * 12
        score += medium_count * 4

        for cat, entries in by_category.items():
            factors.append(f'{len(entries)} {cat} API(s) detected')

        # --- Sections ---
        high_entropy = [s for s in analysis.get('sections', []) if s.get('high_entropy')]
        if high_entropy:
            score += len(high_entropy) * 20
            factors.append(f'{len(high_entropy)} high-entropy section(s) found - possible packing/encryption')

        suspicious_names = [s for s in analysis.get('sections', []) if s.get('suspicious_name')]
        if suspicious_names:
            score += len(suspicious_names) * 5
            names = ', '.join(s['name'] for s in suspicious_names)
            factors.append(f'Unusual section name(s): {names}')

        # --- Strings ---
        strings = analysis.get('strings', {})
        if strings.get('URLs'):
            n = len(strings['URLs'])
            score += min(n * 3, 15)
            factors.append(f'{n} embedded URL(s) found')
        if strings.get('IP Addresses'):
            n = len(strings['IP Addresses'])
            score += min(n * 5, 20)
            factors.append(f'{n} embedded IP address(es) found')
        if strings.get('Suspicious Commands'):
            n = len(strings['Suspicious Commands'])
            score += n * 10
            factors.append(f'{n} suspicious command string(s) detected')
        if strings.get('Potential Base64'):
            n = len(strings['Potential Base64'])
            score += min(n * 2, 10)
            factors.append(f'{n} potential Base64 encoded payload(s)')

        # --- PE header flags ---
        pe_info = analysis.get('pe_info') or {}
        if pe_info.get('has_tls'):
            score += 5
            factors.append('TLS callbacks present (possible anti-debug)')

        # --- Security mitigations (missing = higher exploitability risk) ---
        mitigations = analysis.get('security_mitigations', {})
        missing = mitigations.get('missing', [])
        high_risk_missing = [m for m in missing if m.get('risk') == 'HIGH']
        if len(high_risk_missing) >= 3:
            score += 20
            factors.append(f'{len(high_risk_missing)} critical security mitigations absent (ASLR/DEP/GS)')
        elif len(high_risk_missing) >= 2:
            score += 12
            factors.append(f'{len(high_risk_missing)} critical security mitigations absent')
        elif len(high_risk_missing) == 1:
            score += 6
            factors.append(f'Missing {high_risk_missing[0]["name"]} protection')

        score = min(score, 100)

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

        return {
            'score': score,
            'level': level,
            'factors': factors if factors else ['No significant indicators found'],
        }

    # -------------------------------------------------------------------------
    # Component / version detection (vulnerability-assessment focused)
    # -------------------------------------------------------------------------

    def _detect_components(self, filepath, analysis: dict) -> list:
        """
        Detect embedded software components and their versions.

        Searches for version strings of known libraries (OpenSSL, libcurl,
        SQLite, Python, etc.) in extracted strings and DLL import names.

        Returns list of dicts:
            [{name, version, cpe_vendor, cpe_product, source}]

        This data feeds directly into CPE generation for NVD CVE lookups —
        a file embedding OpenSSL 1.0.1 may be affected by Heartbleed even
        if it has no other identifying information.
        """
        found: dict[str, dict] = {}   # component_name → best match

        # ── 1. Search extracted strings for version patterns ──────────────
        strings = analysis.get('strings', {})
        all_strings_text = '\n'.join(
            s for bucket in strings.values()
            for s in (bucket if isinstance(bucket, list) else [])
        )

        # Also scan raw file bytes (first 4MB) for version strings
        try:
            with open(str(filepath), 'rb') as f:
                raw = f.read(4 * 1024 * 1024)
            raw_text = raw.decode('ascii', errors='replace')
        except Exception:
            raw_text = ''

        scan_text = all_strings_text + '\n' + raw_text

        for comp_name, (pattern, cpe_vendor, cpe_product) in self.COMPONENT_PATTERNS.items():
            matches = re.findall(pattern, scan_text, re.IGNORECASE)
            if matches:
                version = matches[0].strip()
                if comp_name not in found:
                    found[comp_name] = {
                        'name':        comp_name,
                        'version':     version,
                        'cpe_vendor':  cpe_vendor,
                        'cpe_product': cpe_product,
                        'source':      'string_scan',
                    }

        # ── 2. Check DLL imports for known component names ────────────────
        imports = analysis.get('imports', {})
        for dll_entry in imports.get('dlls', []):
            dll_name = (dll_entry.get('name') or '').lower()
            # Strip extension and version suffix: python39.dll → python
            base = dll_name.replace('.dll', '').replace('.so', '')
            # Check against known DLL prefixes
            for prefix, info in self.DLL_COMPONENT_MAP.items():
                if base.startswith(prefix):
                    comp_name = info['component']
                    # Try to extract version from DLL name
                    # e.g. python39.dll → 3.9, msvcr100.dll → 100
                    version_match = re.search(r'(\d+)', base[len(prefix):])
                    version = ''
                    if version_match:
                        raw_ver = version_match.group(1)
                        # Normalize: "39" → "3.9", "100" → "10.0"
                        if len(raw_ver) == 2 and raw_ver.isdigit():
                            version = f"{raw_ver[0]}.{raw_ver[1]}"
                        elif len(raw_ver) == 3 and raw_ver.isdigit():
                            version = f"{raw_ver[0]}.{raw_ver[1]}.0"
                        else:
                            version = raw_ver

                    if comp_name not in found:
                        found[comp_name] = {
                            'name':        comp_name,
                            'version':     version,
                            'cpe_vendor':  info['cpe_vendor'],
                            'cpe_product': info['cpe_product'],
                            'source':      f'dll_import ({dll_name})',
                        }
                    break

        # ── 3. Extract version from PE VERSIONINFO resource ───────────────
        pe_info = analysis.get('pe_info')
        if pe_info:
            # pe_info comes from _analyze_pe_header — check compile_time for hints
            # The actual VersionInfo is in file_info if populated by cpe_extractor
            pass

        return list(found.values())

    # -------------------------------------------------------------------------
    # Utility
    # -------------------------------------------------------------------------

    def _calculate_entropy(self, data):
        """Shannon entropy (0.0 - 8.0). Values > 7.0 indicate packing/encryption."""
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        entropy = 0.0
        length = len(data)
        for count in byte_counts:
            if count:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _human_size(self, size_bytes):
        if size_bytes < 1024:
            return f'{size_bytes} B'
        elif size_bytes < 1024 ** 2:
            return f'{size_bytes / 1024:.1f} KB'
        elif size_bytes < 1024 ** 3:
            return f'{size_bytes / 1024 ** 2:.1f} MB'
        else:
            return f'{size_bytes / 1024 ** 3:.1f} GB'
