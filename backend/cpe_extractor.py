# backend/cpe_extractor.py

"""
CPE Extractor - Extract CPE from executable files
Supports: PE files (Windows executables, DLLs)
"""

import pefile
import re
from pathlib import Path

class CPEExtractor:
    """Extract CPE information from files"""
    
    def __init__(self):
        self.known_patterns = self._load_known_patterns()
    
    def _load_known_patterns(self):
        """Load known software patterns for CPE matching"""
        return {
            # Format: software_name: (vendor, product)
            'winrar': ('rarlab', 'winrar'),
            'apache': ('apache', 'http_server'),
            'httpd': ('apache', 'http_server'),
            'nginx': ('nginx', 'nginx'),
            'mysql': ('mysql', 'mysql'),
            'php': ('php', 'php'),
            'openssl': ('openssl', 'openssl'),
            'python': ('python', 'python'),
            'node': ('nodejs', 'node.js'),
            'java': ('oracle', 'jre'),
            '7-zip': ('7-zip', '7-zip'),
            'notepad++': ('notepad-plus-plus', 'notepad++'),
        }
    
    def extract_from_file(self, file_path):
        """
        Extract CPE from file
        
        Args:
            file_path: Path to file
            
        Returns:
            dict: {
                'cpe': CPE string,
                'vendor': Vendor name,
                'product': Product name,
                'version': Version,
                'file_info': Additional file info
            }
        """
        
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Check file type
        ext = file_path.suffix.lower()
        
        if ext in ['.exe', '.dll', '.sys']:
            return self._extract_from_pe(file_path)
        else:
            return self._extract_from_generic(file_path)
    
    def _extract_from_pe(self, file_path):
        """Extract info from PE (Portable Executable) files"""
        
        try:
            pe = pefile.PE(str(file_path))
            
            # Extract version info
            file_info = self._extract_pe_version_info(pe)
            
            # Get product name and version
            product_name = file_info.get('ProductName', '')
            file_version = file_info.get('FileVersion', '')
            company_name = file_info.get('CompanyName', '')
            
            # Clean and normalize
            product_clean = self._normalize_name(product_name)
            version_clean = self._extract_version(file_version)
            
            # Match to known vendor/product
            vendor, product = self._match_vendor_product(
                product_clean, 
                company_name
            )
            
            # Build CPE
            cpe = self._build_cpe(vendor, product, version_clean)
            
            return {
                'cpe': cpe,
                'vendor': vendor,
                'product': product,
                'version': version_clean,
                'file_info': file_info,
                'extraction_method': 'pe_version_info'
            }
            
        except Exception as e:
            # Fallback: extract from filename
            return self._extract_from_filename(file_path)
    
    def _extract_pe_version_info(self, pe):
        """Extract version information from PE file"""
        
        info = {}
        
        if hasattr(pe, 'VS_VERSIONINFO'):
            if hasattr(pe, 'FileInfo'):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, 'StringTable'):
                        for string_table in file_info.StringTable:
                            for key, value in string_table.entries.items():
                                try:
                                    key_str = key.decode('utf-8', errors='ignore')
                                    value_str = value.decode('utf-8', errors='ignore')
                                    info[key_str] = value_str
                                except:
                                    pass
        
        return info
    
    def _extract_from_filename(self, file_path):
        """Extract info from filename as fallback"""
        
        filename = file_path.stem.lower()
        
        # Try to match known patterns
        for soft_name, (vendor, product) in self.known_patterns.items():
            if soft_name in filename:
                # Try to extract version from filename
                version = self._extract_version_from_string(filename)
                cpe = self._build_cpe(vendor, product, version)
                
                return {
                    'cpe': cpe,
                    'vendor': vendor,
                    'product': product,
                    'version': version,
                    'file_info': {'FileName': file_path.name},
                    'extraction_method': 'filename_pattern'
                }
        
        # Generic fallback
        return {
            'cpe': None,
            'vendor': 'unknown',
            'product': filename,
            'version': '',
            'file_info': {'FileName': file_path.name},
            'extraction_method': 'generic_fallback'
        }
    
    def _extract_from_generic(self, file_path):
        """Extract from non-PE files"""
        return self._extract_from_filename(file_path)
    
    def _normalize_name(self, name):
        """Normalize software name"""
        if not name:
            return ''
        
        name = name.lower()
        name = re.sub(r'[^\w\s.-]', '', name)
        name = name.strip()
        
        return name
    
    def _extract_version(self, version_string):
        """Extract clean version number"""
        if not version_string:
            return ''
        
        # Match version pattern like 1.2.3.4 or 1.2.3
        match = re.search(r'(\d+(?:\.\d+){1,3})', version_string)
        if match:
            return match.group(1)
        
        return ''
    
    def _extract_version_from_string(self, text):
        """Extract version from any string"""
        # Common patterns: v1.2.3, version1.2.3, 1.2.3
        patterns = [
            r'v?(\d+\.\d+(?:\.\d+)?)',
            r'version[_\s]?(\d+\.\d+(?:\.\d+)?)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ''
    
    def _match_vendor_product(self, product_name, company_name):
        """Match product name to known vendor/product"""
        
        product_lower = product_name.lower()
        company_lower = company_name.lower() if company_name else ''
        
        # Check known patterns
        for soft_name, (vendor, product) in self.known_patterns.items():
            if soft_name in product_lower or soft_name in company_lower:
                return vendor, product
        
        # Try to infer vendor from company name
        if company_name:
            # Clean company name
            vendor = re.sub(r'\s+(inc|corp|llc|ltd|gmbh)\.?$', '', company_lower)
            vendor = re.sub(r'[^\w]', '_', vendor)
            product = re.sub(r'[^\w]', '_', product_lower)
            return vendor, product
        
        # Fallback: use product name as both vendor and product
        clean = re.sub(r'[^\w]', '_', product_lower)
        return clean, clean
    
    def _build_cpe(self, vendor, product, version):
        """Build CPE 2.3 string"""
        
        if not vendor or not product:
            return None
        
        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        # We use part='a' (application)
        
        version_str = version if version else '-'
        
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version_str}:*:*:*:*:*:*:*"
        
        return cpe
    
    def extract_from_software_name(self, software_name, version=''):
        """
        Extract CPE from software name and version
        Useful for manual input or searching
        
        Args:
            software_name: Software name (e.g., "WinRAR", "Apache")
            version: Version string (optional)
            
        Returns:
            dict with CPE info
        """
        
        name_clean = self._normalize_name(software_name)
        version_clean = version if version else ''
        
        # Match to known patterns
        vendor, product = self._match_vendor_product(name_clean, '')
        
        # Build CPE
        cpe = self._build_cpe(vendor, product, version_clean)
        
        return {
            'cpe': cpe,
            'vendor': vendor,
            'product': product,
            'version': version_clean,
            'extraction_method': 'manual_input'
        }


# Quick test
if __name__ == "__main__":
    extractor = CPEExtractor()
    
    # Test with software name
    result = extractor.extract_from_software_name("WinRAR", "6.0")
    print("Test: WinRAR 6.0")
    print(f"CPE: {result['cpe']}")
    print(f"Vendor: {result['vendor']}")
    print(f"Product: {result['product']}")