# backend/nvd_api_v2.py

"""
NVD API Client V2 - Direct CPE Query
Query CVEs directly from the NVD API by CPE (does not go through junction.csv).
Official NVD API: https://nvd.nist.gov/developers/vulnerabilities
"""

import requests
import time
import json
import re
from pathlib import Path
from datetime import datetime
from itertools import zip_longest
from urllib.parse import quote

class NVDAPIv2:
    """Direct NVD API query by CPE"""
    
    def __init__(self, api_key=None):
        """
        Initialize NVD API client
        
        Args:
            api_key: NVD API key (paste directly here or load from environment)
        """
        if api_key is None:
            api_key = "c95dd30e-7d9f-48b7-b9b9-0e799b0cd859"
        self.api_key = api_key
        
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limiting
        self.last_request_time = 0
        if self.api_key:
            self.request_delay = 0.6  # 50 requests / 30s
            print(f"[NVD API v2] [+] API key detected - Rate: 50 req/30s")
        else:
            self.request_delay = 6.0  # 5 requests / 30s
            print(f"[NVD API v2] [!] No API key - Rate: 5 req/30s (SLOW!)")
            print(f"[NVD API v2] [i] Get key: https://nvd.nist.gov/developers/request-an-api-key")
        
        # Cache
        self.cache_dir = Path("data/cache/nvd_v2")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def search_by_cpe(self, cpe_name, results_per_page=100, max_results=None):
        """
        Search CVEs by CPE name — DIRECTLY from the NVD API
        
        Args:
            cpe_name: CPE string (e.g., "cpe:2.3:o:linux:linux_kernel:2.6.20.6:*:*:*:*:*:*:*")
            results_per_page: Number of results per page (max 2000)
            max_results: Maximum total results (None = all)
            
        Returns:
            List of CVE objects
        """
        
        print(f"\n[NVD Search] CPE: {cpe_name}")
        print(f"[NVD Search] Querying NVD API directly...")
        
        all_cves = []
        start_index = 0
        total_results = None
        
        while True:
            # Rate limiting
            self._rate_limit()
            
            # Build request
            # Use virtualMatchString instead of cpeName:
            # cpeName requires an exact registered CPE in the NVD dictionary and
            # returns 0 results when the CPE string isn't registered (e.g. version
            # variants).  virtualMatchString does a wildcard/partial match and works
            # even when the exact CPE is not in the dictionary.
            params = {
                'virtualMatchString': cpe_name,
                'resultsPerPage': min(results_per_page, 2000),  # NVD max = 2000
                'startIndex': start_index
            }
            
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            try:
                print(f"[NVD Search] Fetching results {start_index}-{start_index + results_per_page}...", end='\r')
                
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30
                )
                
                response.raise_for_status()
                data = response.json()
                
                # Get total results from first response
                if total_results is None:
                    total_results = data.get('totalResults', 0)
                    print(f"\n[NVD Search] [+] Found {total_results:,} total CVEs in NVD")

                    if total_results == 0:
                        print(f"[NVD Search] [!] No CVEs found for this CPE")
                        return []
                
                # Parse vulnerabilities
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    cve_data = self._parse_cve(vuln)
                    all_cves.append(cve_data)
                
                # Check if we should continue
                start_index += len(vulnerabilities)
                
                # Stop if we've fetched all results
                if start_index >= total_results:
                    break
                
                # Stop if we hit max_results limit
                if max_results and len(all_cves) >= max_results:
                    all_cves = all_cves[:max_results]
                    print(f"\n[NVD Search] [!] Reached max_results limit: {max_results}")
                    break
                
                # Stop if no more results in this page
                if len(vulnerabilities) == 0:
                    break
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    print(f"\n[NVD Search] [ERROR] Error 403: Invalid API key or rate limit exceeded")
                elif e.response.status_code == 404:
                    print(f"\n[NVD Search] [ERROR] Error 404: CPE not found")
                else:
                    print(f"\n[NVD Search] [ERROR] HTTP Error: {e}")
                break

            except Exception as e:
                print(f"\n[NVD Search] [ERROR] Error: {e}")
                break

        print(f"\n[NVD Search] [+] Fetched {len(all_cves):,} CVEs successfully")
        
        return all_cves
    
    def search_by_keyword(self, keyword, results_per_page=100, max_results=50):
        """
        Search CVEs by keyword using NVD keywordSearch parameter.
        Used as fallback when CPE-based search returns 0 results.

        Args:
            keyword: Software name or search term
            results_per_page: Number of results per page (max 2000)
            max_results: Maximum total results to return

        Returns:
            List of CVE objects
        """
        print(f"\n[NVD Search] Keyword fallback: '{keyword}'")

        all_cves = []
        start_index = 0
        total_results = None

        while True:
            self._rate_limit()

            params = {
                'keywordSearch': keyword,
                'resultsPerPage': min(results_per_page, 2000),
                'startIndex': start_index,
            }

            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key

            try:
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30,
                )
                response.raise_for_status()
                data = response.json()

                if total_results is None:
                    total_results = data.get('totalResults', 0)
                    print(f"[NVD Search] [+] Keyword search found {total_results:,} CVEs")
                    if total_results == 0:
                        return []

                vulnerabilities = data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    cve_data = self._parse_cve(vuln)
                    cve_data['search_method'] = 'keyword'
                    cve_data['search_total_results'] = total_results
                    cve_data['search_keyword'] = keyword
                    all_cves.append(cve_data)

                start_index += len(vulnerabilities)

                if start_index >= total_results:
                    break
                if max_results and len(all_cves) >= max_results:
                    all_cves = all_cves[:max_results]
                    break
                if len(vulnerabilities) == 0:
                    break

            except requests.exceptions.HTTPError as e:
                print(f"\n[NVD Search] [ERROR] Keyword search HTTP error: {e}")
                break
            except Exception as e:
                print(f"\n[NVD Search] [ERROR] Keyword search error: {e}")
                break

        print(f"[NVD Search] [+] Keyword search returned {len(all_cves)} CVEs")
        return all_cves

    def compare_versions(self, left: str, right: str) -> int:
        """Public wrapper so other modules can compare version-like strings."""
        return self._compare_versions(left, right)

    def filter_cves_for_target(self, cves: list, target_cpe: str | None) -> list:
        """
        Keep only CVEs that actually match the queried vendor/product/version.

        virtualMatchString is intentionally broad, so this post-filter removes
        false positives such as unrelated Apache modules when the user queried
        Apache HTTP Server itself.
        """
        target = self._parse_cpe23(target_cpe)
        if not target:
            return cves

        filtered = []
        for cve in cves:
            applicability = self._evaluate_cve_for_target(cve, target)
            cve['applicability'] = applicability
            if not applicability.get('matches_target'):
                continue

            if applicability.get('affected_range'):
                cve['affected_range'] = applicability['affected_range']
            if applicability.get('fixed_version'):
                cve['fixed_version'] = applicability['fixed_version']
            if applicability.get('fixed_version_label'):
                cve['fixed_version_label'] = applicability['fixed_version_label']
            if applicability.get('matched_cpe'):
                cve['matched_cpe'] = applicability['matched_cpe']
            if applicability.get('match_reason'):
                cve['match_reason'] = applicability['match_reason']

            filtered.append(cve)

        return filtered

    def _parse_cve(self, vuln_data):
        """Parse NVD vulnerability data - EXACT format"""
        
        cve = vuln_data.get('cve', {})
        
        # CVE ID
        cve_id = cve.get('id', 'N/A')
        
        # Description (English)
        descriptions = cve.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # CVSS Metrics
        metrics = cve.get('metrics', {})
        
        cvss_score = 0.0
        severity = 'NONE'
        vector_string = ''
        cvss_version = ''
        exploitability = None
        impact = None
        attack_vector = ''
        attack_complexity = ''
        privileges_required = ''
        user_interaction = ''
        confidentiality_impact = ''
        integrity_impact = ''
        availability_impact = ''
        scope = ''
        
        # CVSS v3.1 (Priority 1)
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            metric = metrics['cvssMetricV31'][0]
            cvss_data = metric.get('cvssData', {})
            
            cvss_score = float(cvss_data.get('baseScore', 0.0))
            severity = cvss_data.get('baseSeverity', 'NONE')
            vector_string = cvss_data.get('vectorString', '')
            cvss_version = 'CVSS v3.1'
            attack_vector = cvss_data.get('attackVector', '')
            attack_complexity = cvss_data.get('attackComplexity', '')
            privileges_required = cvss_data.get('privilegesRequired', '')
            user_interaction = cvss_data.get('userInteraction', '')
            confidentiality_impact = cvss_data.get('confidentialityImpact', '')
            integrity_impact = cvss_data.get('integrityImpact', '')
            availability_impact = cvss_data.get('availabilityImpact', '')
            scope = cvss_data.get('scope', '')
            
            exploitability = metric.get('exploitabilityScore')
            impact = metric.get('impactScore')
        
        # CVSS v3.0 (Priority 2)
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            metric = metrics['cvssMetricV30'][0]
            cvss_data = metric.get('cvssData', {})
            
            cvss_score = float(cvss_data.get('baseScore', 0.0))
            severity = cvss_data.get('baseSeverity', 'NONE')
            vector_string = cvss_data.get('vectorString', '')
            cvss_version = 'CVSS v3.0'
            attack_vector = cvss_data.get('attackVector', '')
            attack_complexity = cvss_data.get('attackComplexity', '')
            privileges_required = cvss_data.get('privilegesRequired', '')
            user_interaction = cvss_data.get('userInteraction', '')
            confidentiality_impact = cvss_data.get('confidentialityImpact', '')
            integrity_impact = cvss_data.get('integrityImpact', '')
            availability_impact = cvss_data.get('availabilityImpact', '')
            scope = cvss_data.get('scope', '')
            
            exploitability = metric.get('exploitabilityScore')
            impact = metric.get('impactScore')
        
        # CVSS v2 (Priority 3)
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            metric = metrics['cvssMetricV2'][0]
            cvss_data = metric.get('cvssData', {})
            
            cvss_score = float(cvss_data.get('baseScore', 0.0))
            cvss_version = 'CVSS v2.0'
            
            # Map v2 score to severity
            if cvss_score >= 7.0:
                severity = 'HIGH'
            elif cvss_score >= 4.0:
                severity = 'MEDIUM'
            elif cvss_score > 0:
                severity = 'LOW'
            
            vector_string = cvss_data.get('vectorString', '')
            attack_vector = cvss_data.get('accessVector', '')
            attack_complexity = cvss_data.get('accessComplexity', '')
            privileges_required = cvss_data.get('authentication', '')
            confidentiality_impact = cvss_data.get('confidentialityImpact', '')
            integrity_impact = cvss_data.get('integrityImpact', '')
            availability_impact = cvss_data.get('availabilityImpact', '')
            
            exploitability = metric.get('exploitabilityScore')
            impact = metric.get('impactScore')
        
        # Dates
        published = cve.get('published', '')
        modified = cve.get('lastModified', '')
        
        # Format dates
        if published:
            try:
                dt = datetime.fromisoformat(published.replace('Z', '+00:00'))
                published = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        if modified:
            try:
                dt = datetime.fromisoformat(modified.replace('Z', '+00:00'))
                modified = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        # References
        references = []
        reference_details = []
        exploit_references = []
        for ref in cve.get('references', []):
            url = ref.get('url', '')
            tags = ref.get('tags') or []
            if url and url not in references:
                references.append(url)
            if url:
                detail = {
                    'url': url,
                    'source': ref.get('source', ''),
                    'tags': tags,
                }
                reference_details.append(detail)
                if any(str(tag).lower() == 'exploit' for tag in tags):
                    exploit_references.append(detail)
        
        # Affected CPEs
        cpes = []
        affected_products = self._extract_affected_products(cve.get('configurations', []))
        for match in affected_products:
            cpe_uri = match.get('criteria', '')
            if cpe_uri and cpe_uri not in cpes:
                cpes.append(cpe_uri)
        
        # Weaknesses (CWE)
        weaknesses = []
        for weakness in cve.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe = desc.get('value', '')
                    if cwe and cwe not in weaknesses:
                        weaknesses.append(cwe)
        
        source_identifier = cve.get('sourceIdentifier', 'Unknown')
        kev_date = cve.get('cisaExploitAdd', '')
        kev_due = cve.get('cisaActionDue', '')
        cve_tags = cve.get('cveTags') or []
        flat_cve_tags = []
        for entry in cve_tags:
            if isinstance(entry, dict):
                flat_cve_tags.extend(entry.get('tags') or [])
            elif entry:
                flat_cve_tags.append(str(entry))

        known_exploited = bool(kev_date or kev_due)
        fix_from_text = self._extract_recommended_version_from_text(description)
        
        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'severity': severity,
            'vector_string': vector_string,
            'cvss_version': cvss_version,
            'published': published,
            'modified': modified,
            'references': references,
            'reference_details': reference_details,
            'has_public_exploit': len(exploit_references) > 0,
            'exploit_reference_count': len(exploit_references),
            'exploit_references': exploit_references[:5],
            'cpes': cpes,
            'affected_products': affected_products,
            'weaknesses': weaknesses,
            'exploitability_score': exploitability,
            'impact_score': impact,
            'attack_vector': attack_vector,
            'attack_complexity': attack_complexity,
            'privileges_required': privileges_required,
            'user_interaction': user_interaction,
            'confidentiality_impact': confidentiality_impact,
            'integrity_impact': integrity_impact,
            'availability_impact': availability_impact,
            'scope': scope,
            'known_exploited': known_exploited,
            'cisa_kev': {
                'date_added': kev_date,
                'due_date': kev_due,
                'required_action': cve.get('cisaRequiredAction', ''),
                'vulnerability_name': cve.get('cisaVulnerabilityName', ''),
            } if known_exploited else None,
            'cve_tags': flat_cve_tags,
            'suggested_fix_version': fix_from_text,
            'nvd_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            'cna': cve.get('sourceIdentifier', 'Unknown')
        }
    
    def search_by_cwe(self, cwe_id: str, max_results: int = 20, keyword: str | None = None) -> list:
        """
        Search CVEs by CWE ID — used by Track 3 (CWE behavior prediction).

        NVD API parameter: cweId (e.g. "CWE-94", "CWE-78")
        Returns CVEs that have been classified under the given weakness type.

        Args:
            cwe_id:      CWE identifier string, e.g. "CWE-94"
            max_results: Maximum number of CVEs to return
            keyword:     Optional keyword to narrow results (e.g. "Windows")

        Returns:
            List of CVE dicts (same format as search_by_cpe / search_by_keyword)
        """
        kw_label = f" + keyword='{keyword}'" if keyword else ""
        print(f"\n[NVD Search] CWE query: {cwe_id}{kw_label} (max {max_results})")

        all_cves: list = []
        start_index    = 0
        total_results  = None

        while True:
            self._rate_limit()

            params = {
                "cweId":          cwe_id,
                "resultsPerPage": min(max_results, 2000),
                "startIndex":     start_index,
            }
            if keyword:
                params["keywordSearch"] = keyword
            headers = {"apiKey": self.api_key} if self.api_key else {}

            try:
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30,
                )
                response.raise_for_status()
                data = response.json()

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    print(f"[NVD Search] [+] {cwe_id}: {total_results:,} total CVEs in NVD")
                    if total_results == 0:
                        return []

                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve_data = self._parse_cve(vuln)
                    cve_data["search_method"] = "cwe"
                    all_cves.append(cve_data)

                start_index += len(vulnerabilities)

                if start_index >= total_results:
                    break
                if len(all_cves) >= max_results:
                    all_cves = all_cves[:max_results]
                    break
                if not vulnerabilities:
                    break

            except requests.exceptions.HTTPError as e:
                print(f"\n[NVD Search] [ERROR] CWE search HTTP error: {e}")
                break
            except Exception as e:
                print(f"\n[NVD Search] [ERROR] CWE search error: {e}")
                break

        print(f"[NVD Search] [+] CWE {cwe_id}: returned {len(all_cves)} CVEs")
        return all_cves

    def _rate_limit(self):
        """Enforce rate limiting"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time

        if elapsed < self.request_delay:
            sleep_time = self.request_delay - elapsed
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _parse_cpe23(self, cpe_uri: str | None) -> dict | None:
        """Parse a minimal subset of CPE 2.3 for vendor/product/version checks."""
        if not cpe_uri or not isinstance(cpe_uri, str):
            return None
        parts = cpe_uri.split(':')
        if len(parts) < 6 or parts[0] != 'cpe' or parts[1] != '2.3':
            return None
        return {
            'part': parts[2],
            'vendor': parts[3],
            'product': parts[4],
            'version': parts[5] if len(parts) > 5 else '',
        }

    def _extract_affected_products(self, configurations: list) -> list:
        """Flatten nested NVD configuration nodes into vulnerable CPE rules."""
        matches = []
        for config in configurations or []:
            for node in config.get('nodes', []):
                matches.extend(self._extract_cpe_matches(node))
        return matches

    def _extract_cpe_matches(self, node: dict) -> list:
        matches = []
        for cpe_match in node.get('cpeMatch', []):
            criteria = cpe_match.get('criteria', '')
            parsed = self._parse_cpe23(criteria) or {}
            matches.append({
                'criteria': criteria,
                'part': parsed.get('part', ''),
                'vendor': parsed.get('vendor', ''),
                'product': parsed.get('product', ''),
                'version': parsed.get('version', ''),
                'vulnerable': cpe_match.get('vulnerable', True),
                'versionStartIncluding': cpe_match.get('versionStartIncluding', ''),
                'versionStartExcluding': cpe_match.get('versionStartExcluding', ''),
                'versionEndIncluding': cpe_match.get('versionEndIncluding', ''),
                'versionEndExcluding': cpe_match.get('versionEndExcluding', ''),
            })
        for child in node.get('nodes', []):
            matches.extend(self._extract_cpe_matches(child))
        return matches

    def _evaluate_cve_for_target(self, cve: dict, target: dict) -> dict:
        """Decide whether a CVE's affected CPE rules match the target query."""
        products = cve.get('affected_products') or []
        if not products:
            return {'matches_target': False, 'match_reason': 'No affected CPE rules from NVD'}

        matched_rules = []
        for rule in products:
            if not rule.get('vulnerable', True):
                continue
            if rule.get('vendor') != target.get('vendor') or rule.get('product') != target.get('product'):
                continue
            if self._version_matches_rule(target.get('version', ''), rule):
                matched_rules.append(rule)

        if not matched_rules:
            return {'matches_target': False, 'match_reason': 'Vendor/product/version mismatch'}

        best_rule = self._pick_best_rule(matched_rules)
        fixed_version, fixed_version_label = self._derive_fix_version(
            best_rule,
            cve.get('suggested_fix_version', ''),
        )

        return {
            'matches_target': True,
            'matched_cpe': best_rule.get('criteria', ''),
            'affected_range': self._format_affected_range(best_rule),
            'fixed_version': fixed_version,
            'fixed_version_label': fixed_version_label,
            'match_reason': 'Matched affected CPE rule from NVD configuration',
        }

    def _pick_best_rule(self, rules: list) -> dict:
        """Prefer the most specific affected rule when multiple rules match."""
        def score(rule: dict) -> tuple:
            exact_version = rule.get('version') not in ('', '-', '*')
            has_range = any(rule.get(key) for key in (
                'versionStartIncluding',
                'versionStartExcluding',
                'versionEndIncluding',
                'versionEndExcluding',
            ))
            return (1 if exact_version else 0, 1 if has_range else 0)

        return sorted(rules, key=score, reverse=True)[0]

    def _version_matches_rule(self, target_version: str, rule: dict) -> bool:
        """Check whether a queried version is inside the CVE's affected range."""
        if not target_version or target_version in ('-', '*'):
            return True

        rule_version = rule.get('version', '')
        if rule_version not in ('', '-', '*'):
            return self._compare_versions(target_version, rule_version) == 0

        start_inc = rule.get('versionStartIncluding', '')
        start_exc = rule.get('versionStartExcluding', '')
        end_inc = rule.get('versionEndIncluding', '')
        end_exc = rule.get('versionEndExcluding', '')

        if start_inc and self._compare_versions(target_version, start_inc) < 0:
            return False
        if start_exc and self._compare_versions(target_version, start_exc) <= 0:
            return False
        if end_inc and self._compare_versions(target_version, end_inc) > 0:
            return False
        if end_exc and self._compare_versions(target_version, end_exc) >= 0:
            return False

        return True

    def _format_affected_range(self, rule: dict) -> str:
        """Create a human-readable affected version range."""
        rule_version = rule.get('version', '')
        if rule_version not in ('', '-', '*'):
            return rule_version

        parts = []
        if rule.get('versionStartIncluding'):
            parts.append(f">= {rule['versionStartIncluding']}")
        if rule.get('versionStartExcluding'):
            parts.append(f"> {rule['versionStartExcluding']}")
        if rule.get('versionEndIncluding'):
            parts.append(f"<= {rule['versionEndIncluding']}")
        if rule.get('versionEndExcluding'):
            parts.append(f"< {rule['versionEndExcluding']}")

        return ' and '.join(parts) if parts else 'All known versions'

    def _derive_fix_version(self, rule: dict, suggested_fix: str = '') -> tuple[str, str]:
        """
        Derive the first likely safe version from NVD range metadata.

        Returns (fixed_version_raw, display_label).
        """
        if rule.get('versionEndExcluding'):
            fix = rule['versionEndExcluding']
            return fix, f"{fix}+"

        if suggested_fix:
            return suggested_fix, suggested_fix

        if rule.get('versionEndIncluding'):
            fix = rule['versionEndIncluding']
            return fix, f"> {fix}"

        return '', ''

    def _extract_recommended_version_from_text(self, description: str) -> str:
        """Heuristic fallback when NVD ranges do not expose a clean fixed version."""
        if not description:
            return ''

        patterns = [
            r'upgrade to version\s+([0-9][a-z0-9._-]*)',
            r'upgrade to\s+([0-9][a-z0-9._-]*)',
            r'fixed in version\s+([0-9][a-z0-9._-]*)',
            r'fixed in\s+([0-9][a-z0-9._-]*)',
        ]
        text = description.lower()
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                return match.group(1).strip('.,;:)]} ')
        return ''

    def _compare_versions(self, left: str, right: str) -> int:
        """
        Best-effort comparator for dotted vendor versions.

        This is intentionally tolerant rather than PEP440-strict because NVD
        versions often contain vendor-specific tokens such as "sp1" or "rc2".
        """
        left_tokens = self._normalize_version_tokens(left)
        right_tokens = self._normalize_version_tokens(right)

        for l_token, r_token in zip_longest(left_tokens, right_tokens, fillvalue=(0, 0, '')):
            if l_token == r_token:
                continue
            return 1 if l_token > r_token else -1

        return 0

    def _normalize_version_tokens(self, value: str) -> list:
        value = (value or '').strip().lower()
        value = re.sub(r'^[v_]+', '', value)
        if not value or value in ('*', '-'):
            return []

        raw_tokens = re.findall(r'\d+|[a-z]+', value)
        normalized = []
        pre_release_order = {
            'dev': -4,
            'a': -3,
            'alpha': -3,
            'b': -2,
            'beta': -2,
            'pre': -1,
            'preview': -1,
            'rc': 0,
        }

        for token in raw_tokens:
            if token.isdigit():
                normalized.append((2, int(token), ''))
            else:
                normalized.append((1, pre_release_order.get(token, 1), token))

        return normalized


# Quick test
if __name__ == "__main__":
    print("=" * 80)
    print("[*] TESTING NVD API V2 - Direct CPE Query")
    print("=" * 80)
    print()
    
    # Test CPE
    test_cpe = "cpe:2.3:o:linux:linux_kernel:2.6.20.6:*:*:*:*:*:*:*"
    
    print(f"Test CPE: {test_cpe}")
    print(f"Expected: ~3918 CVEs (from NVD website)")
    print()
    
    # Initialize API
    api = NVDAPIv2()
    
    # Search (limit to 10 for test)
    print("Searching first 10 CVEs...")
    cves = api.search_by_cpe(test_cpe, max_results=10)
    
    print()
    print("=" * 80)
    print("[*] RESULTS")
    print("=" * 80)
    print()
    
    print(f"Total fetched: {len(cves)} CVEs")
    print()
    
    if cves:
        print("Top 5 CVEs by CVSS:")
        sorted_cves = sorted(cves, key=lambda x: x['cvss_score'], reverse=True)
        
        for i, cve in enumerate(sorted_cves[:5], 1):
            print(f"{i}. {cve['cve_id']}")
            print(f"   Severity: {cve['severity']}")
            print(f"   CVSS: {cve['cvss_score']} ({cve['cvss_version']})")
            print(f"   Published: {cve['published']}")
            print(f"   URL: {cve['nvd_url']}")
            print()
