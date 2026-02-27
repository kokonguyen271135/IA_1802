# backend/cpe_extractor.py

"""
CPE Extractor - Extract CPE from executable files
Supports: PE files (Windows executables, DLLs)

Extraction pipeline:
  1. Read PE VersionInfo resource (ProductName, FileVersion, CompanyName)
  2. Match ProductName + CompanyName against KNOWN_PATTERNS
  3. Fall back to filename pattern matching
  4. Fall back to generic (caller will invoke Claude AI / FAISS)
"""

import pefile
import re
from pathlib import Path


class CPEExtractor:
    """Extract CPE information from files"""

    # -------------------------------------------------------------------------
    # Known software patterns
    # Format: keyword → (cpe_vendor, cpe_product)
    # keyword is matched (substring) against ProductName (lowercase) or CompanyName
    # -------------------------------------------------------------------------
    KNOWN_PATTERNS = {
        # ── Microsoft products ──────────────────────────────────────────────
        'sql server':            ('microsoft', 'sql_server'),
        'sqlserver':             ('microsoft', 'sql_server'),
        'sql2019':               ('microsoft', 'sql_server'),
        'sql2022':               ('microsoft', 'sql_server'),
        'sql2017':               ('microsoft', 'sql_server'),
        'sql2016':               ('microsoft', 'sql_server'),
        'sql2014':               ('microsoft', 'sql_server'),
        'microsoft office':      ('microsoft', 'office'),
        'microsoft word':        ('microsoft', 'word'),
        'microsoft excel':       ('microsoft', 'excel'),
        'microsoft outlook':     ('microsoft', 'outlook'),
        'microsoft powerpoint':  ('microsoft', 'powerpoint'),
        'microsoft access':      ('microsoft', 'access'),
        'microsoft teams':       ('microsoft', 'teams'),
        'microsoft edge':        ('microsoft', 'edge'),
        'internet explorer':     ('microsoft', 'internet_explorer'),
        'visual studio':         ('microsoft', 'visual_studio'),
        'visual studio code':    ('microsoft', 'visual_studio_code'),
        'windows defender':      ('microsoft', 'windows_defender'),
        'exchange server':       ('microsoft', 'exchange_server'),
        'sharepoint':            ('microsoft', 'sharepoint_server'),
        'skype':                 ('microsoft', 'skype'),
        'onedrive':              ('microsoft', 'onedrive'),
        'powershell':            ('microsoft', 'powershell'),
        'iis':                   ('microsoft', 'iis'),
        '.net framework':        ('microsoft', '.net_framework'),
        'dotnet':                ('microsoft', '.net_framework'),
        'net framework':         ('microsoft', '.net_framework'),

        # ── Web servers ──────────────────────────────────────────────────────
        'apache':                ('apache', 'http_server'),
        'httpd':                 ('apache', 'http_server'),
        'nginx':                 ('nginx', 'nginx'),
        'lighttpd':              ('lighttpd', 'lighttpd'),
        'tomcat':                ('apache', 'tomcat'),
        'jboss':                 ('redhat', 'jboss_enterprise_application_platform'),
        'wildfly':               ('redhat', 'wildfly'),
        'websphere':             ('ibm', 'websphere_application_server'),
        'weblogic':              ('oracle', 'weblogic_server'),
        'glassfish':             ('oracle', 'glassfish_server'),

        # ── Databases ────────────────────────────────────────────────────────
        'mysql':                 ('oracle', 'mysql'),
        'postgresql':            ('postgresql', 'postgresql'),
        'postgres':              ('postgresql', 'postgresql'),
        'mongodb':               ('mongodb', 'mongodb'),
        'redis':                 ('redis', 'redis'),
        'sqlite':                ('sqlite', 'sqlite'),
        'elasticsearch':         ('elastic', 'elasticsearch'),
        'kibana':                ('elastic', 'kibana'),
        'mariadb':               ('mariadb', 'mariadb'),
        'oracle database':       ('oracle', 'database_server'),
        'oracle db':             ('oracle', 'database_server'),
        'db2':                   ('ibm', 'db2'),
        'cassandra':             ('apache', 'cassandra'),

        # ── Security libraries ───────────────────────────────────────────────
        'openssl':               ('openssl', 'openssl'),
        'openssh':               ('openbsd', 'openssh'),
        'libssl':                ('openssl', 'openssl'),
        'libcurl':               ('haxx', 'libcurl'),
        'curl':                  ('haxx', 'curl'),
        'gnupg':                 ('gnupg', 'gnupg'),
        'gnutls':                ('gnu', 'gnutls'),

        # ── Languages & runtimes ─────────────────────────────────────────────
        'python':                ('python', 'python'),
        'php':                   ('php', 'php'),
        'node.js':               ('nodejs', 'node.js'),
        'nodejs':                ('nodejs', 'node.js'),
        'ruby':                  ('ruby-lang', 'ruby'),
        'golang':                ('golang', 'go'),
        'java runtime':          ('oracle', 'jre'),
        'java se':               ('oracle', 'jre'),
        'jre':                   ('oracle', 'jre'),
        'jdk':                   ('oracle', 'jdk'),
        'openjdk':               ('oracle', 'openjdk'),
        'perl':                  ('perl', 'perl'),

        # ── Frameworks & libraries ───────────────────────────────────────────
        'log4j':                 ('apache', 'log4j'),
        'struts':                ('apache', 'struts'),
        'spring framework':      ('pivotal_software', 'spring_framework'),
        'spring boot':           ('pivotal_software', 'spring_boot'),
        'django':                ('djangoproject', 'django'),
        'rails':                 ('rubyonrails', 'ruby_on_rails'),
        'laravel':               ('laravel', 'laravel'),
        'symfony':               ('sensio', 'symfony'),
        'wordpress':             ('wordpress', 'wordpress'),
        'drupal':                ('drupal', 'drupal'),
        'joomla':                ('joomla', 'joomla!'),
        'magento':               ('magento', 'magento'),

        # ── Browsers ─────────────────────────────────────────────────────────
        'chrome':                ('google', 'chrome'),
        'chromium':              ('google', 'chrome'),
        'firefox':               ('mozilla', 'firefox'),
        'mozilla firefox':       ('mozilla', 'firefox'),
        'safari':                ('apple', 'safari'),

        # ── Archive / compression ────────────────────────────────────────────
        'winrar':                ('rarlab', 'winrar'),
        '7-zip':                 ('7-zip', '7-zip'),
        '7zip':                  ('7-zip', '7-zip'),
        'winzip':                ('winzip', 'winzip'),

        # ── Developer tools ──────────────────────────────────────────────────
        'git':                   ('git-scm', 'git'),
        'jenkins':               ('jenkins', 'jenkins'),
        'gitlab':                ('gitlab', 'gitlab'),
        'github desktop':        ('github', 'github_desktop'),
        'docker':                ('docker', 'docker'),
        'kubernetes':            ('kubernetes', 'kubernetes'),
        'ansible':               ('redhat', 'ansible'),
        'terraform':             ('hashicorp', 'terraform'),
        'vagrant':               ('hashicorp', 'vagrant'),
        'putty':                 ('putty', 'putty'),
        'filezilla':             ('filezilla-project', 'filezilla'),
        'winscp':                ('winscp', 'winscp'),

        # ── Adobe products ───────────────────────────────────────────────────
        'adobe acrobat':         ('adobe', 'acrobat'),
        'acrobat reader':        ('adobe', 'acrobat_reader'),
        'adobe reader':          ('adobe', 'acrobat_reader'),
        'adobe photoshop':       ('adobe', 'photoshop'),
        'adobe flash':           ('adobe', 'flash_player'),
        'flash player':          ('adobe', 'flash_player'),
        'adobe illustrator':     ('adobe', 'illustrator'),

        # ── Communication ────────────────────────────────────────────────────
        'zoom':                  ('zoom', 'zoom'),
        'slack':                 ('slack', 'slack'),
        'discord':               ('discord', 'discord'),
        'telegram':              ('telegram', 'telegram'),
        'signal':                ('signal', 'signal'),
        'whatsapp':              ('whatsapp', 'whatsapp'),

        # ── Security tools ───────────────────────────────────────────────────
        'wireshark':             ('wireshark', 'wireshark'),
        'nmap':                  ('nmap', 'nmap'),
        'metasploit':            ('rapid7', 'metasploit_framework'),

        # ── Network / infrastructure ─────────────────────────────────────────
        'openvpn':               ('openvpn', 'openvpn'),
        'stunnel':               ('stunnel', 'stunnel'),

        # ── Media & misc ─────────────────────────────────────────────────────
        'vlc':                   ('videolan', 'vlc_media_player'),
        'notepad++':             ('notepad-plus-plus', 'notepad++'),
        'notepad plus':          ('notepad-plus-plus', 'notepad++'),
        'sublime text':          ('sublimehq', 'sublime_text'),
        'vim':                   ('vim', 'vim'),
        'virtualbox':            ('oracle', 'vm_virtualbox'),
        'vmware':                ('vmware', 'workstation'),
    }

    # Company name → CPE vendor mapping
    COMPANY_TO_VENDOR = {
        'microsoft':        'microsoft',
        'oracle':           'oracle',
        'adobe systems':    'adobe',
        'adobe':            'adobe',
        'google':           'google',
        'mozilla':          'mozilla',
        'apache':           'apache',
        'nginx':            'nginx',
        'postgresql':       'postgresql',
        'openssl':          'openssl',
        'python software':  'python',
        'nodejs':           'nodejs',
        'docker':           'docker',
        'elastic':          'elastic',
        'redis':            'redis',
        'mongodb':          'mongodb',
        'rarlab':           'rarlab',
        '7-zip':            '7-zip',
        'simon tatham':     'putty',
        'notepad++':        'notepad-plus-plus',
        'videolan':         'videolan',
        'zoom video':       'zoom',
        'slack':            'slack',
    }

    def __init__(self):
        pass

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def extract_from_file(self, file_path) -> dict:
        """
        Extract CPE info from a file.
        Returns dict: {cpe, vendor, product, version, file_info, extraction_method}
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        ext = file_path.suffix.lower()
        if ext in ('.exe', '.dll', '.sys', '.ocx', '.drv'):
            return self._extract_from_pe(file_path)
        return self._extract_from_filename(file_path)

    def extract_from_software_name(self, software_name: str, version: str = '') -> dict:
        """Extract CPE from a software name string (manual/search input)."""
        name_lower = software_name.lower().strip()
        vendor, product = self._match_name(name_lower, company='')
        cpe = self._build_cpe(vendor, product, version)
        return {
            'cpe': cpe,
            'vendor': vendor,
            'product': product,
            'version': version,
            'extraction_method': 'manual_input',
        }

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _extract_from_pe(self, file_path: Path) -> dict:
        """Read PE VersionInfo then match to CPE."""
        file_info = {}
        try:
            pe = pefile.PE(str(file_path), fast_load=False)
            file_info = self._read_version_info(pe)
            pe.close()
        except Exception:
            pass

        product_name = file_info.get('ProductName', '').strip()
        file_version = file_info.get('FileVersion', '').strip()
        company_name = file_info.get('CompanyName', '').strip()
        version      = self._clean_version(file_version)

        vendor, product = self._match_name(product_name.lower(), company_name.lower())

        if vendor and product:
            return {
                'cpe':               self._build_cpe(vendor, product, version),
                'vendor':            vendor,
                'product':           product,
                'version':           version,
                'file_info':         file_info,
                'extraction_method': 'pe_version_info',
            }

        # Fall through to filename
        return self._extract_from_filename(file_path, file_info=file_info)

    def _read_version_info(self, pe) -> dict:
        """Parse VS_VERSIONINFO StringTable."""
        info = {}
        try:
            if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe, 'FileInfo'):
                for fi_list in pe.FileInfo:
                    items = fi_list if isinstance(fi_list, list) else [fi_list]
                    for fi in items:
                        if hasattr(fi, 'StringTable'):
                            for st in fi.StringTable:
                                for k, v in st.entries.items():
                                    try:
                                        key = k.decode('utf-8', errors='ignore').strip()
                                        val = v.decode('utf-8', errors='ignore').strip()
                                        if key and val:
                                            info[key] = val
                                    except Exception:
                                        pass
        except Exception:
            pass
        return info

    def _extract_from_filename(self, file_path: Path, file_info: dict = None) -> dict:
        """Match the filename stem against KNOWN_PATTERNS."""
        stem   = file_path.stem.lower()
        vendor, product = self._match_name(stem, company='')
        version = self._extract_version_from_str(stem)

        if vendor and product:
            method = 'filename_pattern'
            cpe    = self._build_cpe(vendor, product, version)
        else:
            method = 'generic_fallback'
            cpe    = None

        return {
            'cpe':               cpe,
            'vendor':            vendor or 'unknown',
            'product':           product or stem,
            'version':           version,
            'file_info':         file_info or {'FileName': file_path.name},
            'extraction_method': method,
        }

    def _match_name(self, name: str, company: str) -> tuple:
        """
        Match name/company against KNOWN_PATTERNS.
        Returns (vendor, product) or ('', '').
        Longest keyword wins to avoid 'sql' matching before 'sql server'.
        """
        for keyword in sorted(self.KNOWN_PATTERNS, key=len, reverse=True):
            if keyword in name:
                return self.KNOWN_PATTERNS[keyword]

        if company:
            for keyword in sorted(self.KNOWN_PATTERNS, key=len, reverse=True):
                if keyword in company:
                    return self.KNOWN_PATTERNS[keyword]

            for co_kw, vendor in self.COMPANY_TO_VENDOR.items():
                if co_kw in company:
                    product = re.sub(r'[^\w]', '_', name.strip()) or 'unknown'
                    return vendor, product

        return '', ''

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _clean_version(self, version_string: str) -> str:
        if not version_string:
            return ''
        m = re.search(r'(\d+(?:\.\d+){1,3})', version_string)
        return m.group(1) if m else ''

    def _extract_version_from_str(self, text: str) -> str:
        for pat in (r'v?(\d+\.\d+(?:\.\d+)?)', r'version[_\s]?(\d+\.\d+(?:\.\d+)?)'):
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return ''

    def _build_cpe(self, vendor: str, product: str, version: str) -> str:
        if not vendor or not product:
            return None
        v = version if version else '-'
        return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"
