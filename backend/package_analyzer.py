"""
Package Manifest Analyzer

Parses software dependency files to extract package names and versions
for CVE vulnerability assessment.

Supported formats:
  - Python : requirements.txt, Pipfile, setup.cfg
  - Node   : package.json, yarn.lock (basic)
  - Java   : pom.xml (Maven), build.gradle (Gradle)
  - PHP    : composer.json
  - Ruby   : Gemfile
  - Go     : go.mod
  - Rust   : Cargo.toml

Each detected dependency returns:
    {'name': str, 'version': str, 'ecosystem': str}

Usage:
    from package_analyzer import PackageAnalyzer
    result = PackageAnalyzer().analyze('/path/to/requirements.txt')
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path


# ── Ecosystem helpers ─────────────────────────────────────────────────────────

# filename → ecosystem
_FILE_MAP: dict[str, str] = {
    'requirements.txt':  'python',
    'requirements.in':   'python',
    'requirements-dev.txt': 'python',
    'requirements-test.txt': 'python',
    'Pipfile':           'python',
    'setup.cfg':         'python',
    'package.json':      'npm',
    'package-lock.json': 'npm',
    'yarn.lock':         'npm',
    'pom.xml':           'maven',
    'build.gradle':      'gradle',
    'build.gradle.kts':  'gradle',
    'composer.json':     'composer',
    'Gemfile':           'ruby',
    'go.mod':            'go',
    'Cargo.toml':        'cargo',
}

# extension → ecosystem (fallback)
_EXT_MAP: dict[str, str] = {
    '.txt': 'python',
    '.cfg': 'python',
    '.xml': 'maven',
    '.json': 'npm',
    '.toml': 'cargo',
    '.mod':  'go',
}

# Known package-name → (cpe_vendor, cpe_product) for common packages
_KNOWN_CPE: dict[str, tuple[str, str]] = {
    # Python
    'django':         ('djangoproject', 'django'),
    'flask':          ('palletsprojects', 'flask'),
    'requests':       ('python-requests', 'requests'),
    'pillow':         ('python-pillow', 'pillow'),
    'pyyaml':         ('pyyaml', 'pyyaml'),
    'paramiko':       ('paramiko', 'paramiko'),
    'cryptography':   ('pyca', 'cryptography'),
    'sqlalchemy':     ('sqlalchemy', 'sqlalchemy'),
    'numpy':          ('numpy', 'numpy'),
    'urllib3':        ('urllib3', 'urllib3'),
    'werkzeug':       ('palletsprojects', 'werkzeug'),
    'jinja2':         ('palletsprojects', 'jinja2'),
    'celery':         ('celeryproject', 'celery'),
    'redis':          ('redis', 'redis'),
    # npm / Node.js
    'express':        ('expressjs', 'express'),
    'lodash':         ('lodash', 'lodash'),
    'moment':         ('momentjs', 'moment'),
    'axios':          ('axios', 'axios'),
    'webpack':        ('webpack', 'webpack'),
    'react':          ('facebook', 'react'),
    'angular':        ('google', 'angular'),
    'vue':            ('vuejs', 'vue'),
    'jquery':         ('jquery', 'jquery'),
    'next':           ('vercel', 'next.js'),
    'express-validator': ('express-validator', 'express-validator'),
    # Java
    'log4j-core':     ('apache', 'log4j'),
    'log4j':          ('apache', 'log4j'),
    'spring-core':    ('pivotal_software', 'spring_framework'),
    'spring-web':     ('pivotal_software', 'spring_framework'),
    'struts2-core':   ('apache', 'struts'),
    'commons-collections': ('apache', 'commons-collections'),
    'jackson-databind': ('fasterxml', 'jackson-databind'),
    'guava':          ('google', 'guava'),
    # PHP
    'symfony/http-foundation': ('sensiolabs', 'symfony'),
    'laravel/framework':       ('laravel', 'laravel'),
    'guzzlehttp/guzzle':       ('guzzlephp', 'guzzle'),
}


class PackageAnalyzer:
    """Parse package manifest files to extract software dependencies."""

    SUPPORTED_EXTENSIONS = {'.txt', '.cfg', '.json', '.xml', '.toml', '.mod', '.lock'}

    def detect_ecosystem(self, filepath: Path) -> str | None:
        """Detect the package ecosystem from filename and extension."""
        name = filepath.name
        ext  = filepath.suffix.lower()

        # Exact filename match
        if name in _FILE_MAP:
            return _FILE_MAP[name]

        # Handle requirements*.txt pattern
        if re.match(r'requirements.*\.txt', name, re.IGNORECASE):
            return 'python'

        return _EXT_MAP.get(ext)

    def analyze(self, filepath) -> dict:
        """
        Analyze a package manifest file.

        Returns:
            {
                'success':    bool,
                'ecosystem':  str,       # 'python'|'npm'|'maven'|...
                'filename':   str,
                'packages':   [
                    {
                        'name':      str,
                        'version':   str,
                        'ecosystem': str,
                        'cpe_hints': {vendor, product, confidence} | None,
                    },
                    ...
                ],
                'total':      int,
                'error':      str | None,
            }
        """
        filepath = Path(filepath)

        if not filepath.exists():
            return {'success': False, 'error': f'File not found: {filepath}', 'packages': []}

        ecosystem = self.detect_ecosystem(filepath)
        if not ecosystem:
            return {
                'success':   False,
                'error':     f'Unsupported file type: {filepath.name}',
                'supported': list(_FILE_MAP.keys()),
                'packages':  [],
            }

        try:
            content = filepath.read_text(encoding='utf-8', errors='replace')
        except Exception as e:
            return {'success': False, 'error': str(e), 'packages': []}

        parsers = {
            'python':   self._parse_requirements,
            'npm':      self._parse_package_json,
            'maven':    self._parse_pom_xml,
            'gradle':   self._parse_gradle,
            'composer': self._parse_composer,
            'ruby':     self._parse_gemfile,
            'go':       self._parse_go_mod,
            'cargo':    self._parse_cargo_toml,
        }

        parser = parsers.get(ecosystem)
        if not parser:
            return {'success': False, 'error': f'No parser for ecosystem: {ecosystem}', 'packages': []}

        try:
            packages = parser(content)
        except Exception as e:
            return {'success': False, 'error': f'Parse error: {e}', 'packages': []}

        # Attach CPE hints
        for pkg in packages:
            pkg['cpe_hints'] = self._cpe_hints(pkg['name'])

        return {
            'success':   True,
            'ecosystem': ecosystem,
            'filename':  filepath.name,
            'packages':  packages,
            'total':     len(packages),
        }

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_requirements(self, content: str) -> list:
        """Parse requirements.txt / requirements*.txt / Pipfile [packages]."""
        packages = []
        in_pipfile_packages = False

        for raw_line in content.splitlines():
            line = raw_line.strip()

            # Pipfile section detection
            if line == '[packages]' or line == '[dev-packages]':
                in_pipfile_packages = True
                continue
            if line.startswith('[') and in_pipfile_packages:
                in_pipfile_packages = False
                continue

            # Skip comments, blank lines, options
            if not line or line.startswith('#') or line.startswith('-'):
                continue

            # Remove inline comments
            line = line.split('#')[0].strip()
            if not line:
                continue

            # Pipfile format: name = "version"
            if in_pipfile_packages:
                m = re.match(r'^([A-Za-z0-9._-]+)\s*=\s*["\']([^"\']*)["\']', line)
                if m:
                    name, ver = m.group(1), re.sub(r'[~>=<^*]', '', m.group(2)).strip()
                    packages.append({'name': name, 'version': ver, 'ecosystem': 'python'})
                continue

            # Remove extras: package[extra] → package
            line = re.sub(r'\[.*?\]', '', line)

            # Match: name[op]version
            m = re.match(r'^([A-Za-z0-9._-]+)\s*([=<>!~^]{1,3})\s*([^\s,;]+)', line)
            if m:
                name = m.group(1).strip()
                op   = m.group(2).strip()
                ver  = m.group(3).strip()
                # Normalize: strip epoch prefix e.g. 1!2.0 → 2.0
                ver = re.sub(r'^\d+!', '', ver)
                packages.append({
                    'name':      name,
                    'version':   ver if op in ('==', '===') else ver,
                    'ecosystem': 'python',
                })
            else:
                # Package without constraint
                m = re.match(r'^([A-Za-z0-9._-]+)', line)
                if m:
                    packages.append({'name': m.group(1), 'version': '', 'ecosystem': 'python'})

        return packages

    def _parse_package_json(self, content: str) -> list:
        """Parse package.json dependencies."""
        packages = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return packages

        sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
        for section in sections:
            for name, ver_spec in (data.get(section) or {}).items():
                # Clean: ^1.2.3 → 1.2.3, ~1.2 → 1.2, workspace:* → ''
                clean = re.sub(r'^[\^~>=<v]', '', str(ver_spec)).strip()
                clean = re.sub(r'^\d+:', '', clean)  # remove epoch
                if clean in ('*', 'latest', 'next', ''):
                    clean = ''
                packages.append({'name': name, 'version': clean, 'ecosystem': 'npm'})

        return packages

    def _parse_pom_xml(self, content: str) -> list:
        """Parse Maven pom.xml <dependency> entries."""
        packages = []
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return packages

        # Handle namespace
        ns_match = re.match(r'\{([^}]+)\}', root.tag)
        ns = f'{{{ns_match.group(1)}}}' if ns_match else ''

        for dep in root.iter(f'{ns}dependency'):
            gid = (dep.findtext(f'{ns}groupId') or '').strip()
            aid = (dep.findtext(f'{ns}artifactId') or '').strip()
            ver = (dep.findtext(f'{ns}version') or '').strip()

            if not aid:
                continue

            # Handle ${property} placeholders
            if ver.startswith('${'):
                ver = ''

            name = f'{gid}:{aid}' if gid else aid
            packages.append({
                'name':      name,
                'version':   ver,
                'ecosystem': 'maven',
                'group_id':  gid,
                'artifact_id': aid,
            })

        return packages

    def _parse_gradle(self, content: str) -> list:
        """Parse build.gradle / build.gradle.kts dependency declarations."""
        packages = []

        # Matches: implementation 'group:artifact:version'
        #          api("group:artifact:version")
        pattern = re.compile(
            r"(?:implementation|api|compile|runtimeOnly|testImplementation|"
            r"testCompile|compileOnly|annotationProcessor|kapt)\s*['\"]([^'\"]+)['\"]",
        )

        for m in pattern.finditer(content):
            dep = m.group(1)
            parts = dep.split(':')
            if len(parts) < 2:
                continue
            name    = f'{parts[0]}:{parts[1]}'
            version = parts[2].strip() if len(parts) >= 3 else ''
            # Remove dynamic version markers
            if re.match(r'.*[\+\$].*', version):
                version = ''
            packages.append({'name': name, 'version': version, 'ecosystem': 'gradle'})

        return packages

    def _parse_composer(self, content: str) -> list:
        """Parse composer.json."""
        packages = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return packages

        for section in ('require', 'require-dev'):
            for name, ver_spec in (data.get(section) or {}).items():
                if name.lower() in ('php', 'ext-json', 'ext-mbstring', 'ext-pdo'):
                    continue  # skip runtime requirements
                clean = re.sub(r'^[\^~>=<v*]', '', str(ver_spec)).strip()
                packages.append({'name': name, 'version': clean, 'ecosystem': 'php'})

        return packages

    def _parse_gemfile(self, content: str) -> list:
        """Parse Ruby Gemfile."""
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # gem 'name', '~> 1.0'  or  gem "name"
            m = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]*)['\"])?", line)
            if m:
                name = m.group(1)
                ver  = re.sub(r'[~>=<\s]', '', m.group(2) or '').strip()
                packages.append({'name': name, 'version': ver, 'ecosystem': 'ruby'})

        return packages

    def _parse_go_mod(self, content: str) -> list:
        """Parse go.mod."""
        packages = []
        in_require = False

        for line in content.splitlines():
            line = line.strip()
            if line.startswith('require ('):
                in_require = True
                continue
            if in_require and line == ')':
                in_require = False
                continue
            if in_require or line.startswith('require '):
                m = re.search(r'([^\s]+)\s+(v[\d.][^\s]*)', line)
                if m:
                    name    = m.group(1)
                    version = m.group(2).lstrip('v')
                    packages.append({'name': name, 'version': version, 'ecosystem': 'go'})

        return packages

    def _parse_cargo_toml(self, content: str) -> list:
        """Parse Rust Cargo.toml."""
        packages = []
        in_deps = False

        for line in content.splitlines():
            line = line.strip()
            if line in ('[dependencies]', '[dev-dependencies]', '[build-dependencies]'):
                in_deps = True
                continue
            if line.startswith('[') and in_deps:
                in_deps = False
                continue
            if not in_deps:
                continue

            # name = "1.0"
            m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', line)
            if m:
                packages.append({'name': m.group(1), 'version': m.group(2), 'ecosystem': 'rust'})
                continue

            # name = { version = "1.0", ... }
            m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*\{.*?version\s*=\s*"([^"]+)"', line)
            if m:
                packages.append({'name': m.group(1), 'version': m.group(2), 'ecosystem': 'rust'})

        return packages

    # ── CPE hints ─────────────────────────────────────────────────────────────

    def _cpe_hints(self, name: str) -> dict | None:
        """
        Return CPE vendor/product hints for well-known packages.
        Used to improve NVD query accuracy.
        """
        key = name.lower().replace('_', '-')

        # Direct match
        if key in _KNOWN_CPE:
            v, p = _KNOWN_CPE[key]
            return {'vendor': v, 'product': p, 'confidence': 'high'}

        # For Maven groupId:artifactId, try artifact only
        if ':' in key:
            artifact = key.split(':')[-1]
            if artifact in _KNOWN_CPE:
                v, p = _KNOWN_CPE[artifact]
                return {'vendor': v, 'product': p, 'confidence': 'medium'}

        return None

    @staticmethod
    def is_package_file(filename: str) -> bool:
        """Return True if the filename is a recognized package manifest."""
        name = Path(filename).name
        ext  = Path(filename).suffix.lower()
        return (
            name in _FILE_MAP
            or re.match(r'requirements.*\.txt', name, re.IGNORECASE) is not None
            or ext in _EXT_MAP
        )

    @staticmethod
    def supported_filenames() -> list[str]:
        return list(_FILE_MAP.keys()) + [
            'requirements-dev.txt',
            'requirements-test.txt',
            'requirements-prod.txt',
        ]
