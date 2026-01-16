# tests/test_cpe_extractor.py

"""
Test cases for CPE Extractor
Run: pytest tests/test_cpe_extractor.py -v
"""

import pytest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'backend'))

from cpe_extractor import CPEExtractor

class TestCPEExtractor:
    """Test CPE extraction functionality"""
    
    @pytest.fixture
    def extractor(self):
        """Create CPEExtractor instance"""
        return CPEExtractor()
    
    def test_extract_from_software_name_winrar(self, extractor):
        """Test: Extract CPE from WinRAR"""
        result = extractor.extract_from_software_name("WinRAR", "6.0")
        
        assert result is not None
        assert result['cpe'] is not None
        assert 'rarlab' in result['cpe'].lower()
        assert 'winrar' in result['cpe'].lower()
        assert result['vendor'] == 'rarlab'
        assert result['product'] == 'winrar'
        assert result['version'] == '6.0'
        
        print(f"\n✅ WinRAR Test:")
        print(f"   CPE: {result['cpe']}")
        print(f"   Vendor: {result['vendor']}")
        print(f"   Product: {result['product']}")
    
    def test_extract_from_software_name_apache(self, extractor):
        """Test: Extract CPE from Apache HTTP Server"""
        result = extractor.extract_from_software_name("Apache HTTP Server", "2.4.49")
        
        assert result is not None
        assert result['cpe'] is not None
        assert 'apache' in result['cpe'].lower()
        assert result['version'] == '2.4.49'
        
        print(f"\n✅ Apache Test:")
        print(f"   CPE: {result['cpe']}")
    
    def test_extract_from_software_name_openssl(self, extractor):
        """Test: Extract CPE from OpenSSL"""
        result = extractor.extract_from_software_name("OpenSSL", "1.0.1")
        
        assert result is not None
        assert result['cpe'] is not None
        assert 'openssl' in result['cpe'].lower()
        assert result['version'] == '1.0.1'
        
        print(f"\n✅ OpenSSL Test:")
        print(f"   CPE: {result['cpe']}")
    
    def test_extract_from_software_name_mysql(self, extractor):
        """Test: Extract CPE from MySQL"""
        result = extractor.extract_from_software_name("MySQL", "5.7.20")
        
        assert result is not None
        assert result['cpe'] is not None
        assert 'mysql' in result['cpe'].lower()
        assert result['version'] == '5.7.20'
        
        print(f"\n✅ MySQL Test:")
        print(f"   CPE: {result['cpe']}")
    
    def test_extract_from_software_name_nginx(self, extractor):
        """Test: Extract CPE from Nginx"""
        result = extractor.extract_from_software_name("nginx", "1.18.0")
        
        assert result is not None
        assert result['cpe'] is not None
        assert 'nginx' in result['cpe'].lower()
        assert result['version'] == '1.18.0'
        
        print(f"\n✅ Nginx Test:")
        print(f"   CPE: {result['cpe']}")
    
    def test_normalize_name(self, extractor):
        """Test: Name normalization"""
        assert extractor._normalize_name("WinRAR Server") == "winrar server"
        assert extractor._normalize_name("Apache@2.4") == "apache2.4"  # Fixed: keeps dots
        assert extractor._normalize_name("  MySQL  ") == "mysql"
    
    def test_extract_version(self, extractor):
        """Test: Version extraction"""
        assert extractor._extract_version("1.2.3.4") == "1.2.3.4"
        assert extractor._extract_version("v2.4.49") == "2.4.49"
        assert extractor._extract_version("Version 1.0.1") == "1.0.1"
    
    def test_build_cpe(self, extractor):
        """Test: CPE string building"""
        cpe = extractor._build_cpe("rarlab", "winrar", "6.0")
        
        assert cpe.startswith("cpe:2.3:a:")
        assert "rarlab" in cpe
        assert "winrar" in cpe
        assert "6.0" in cpe
    
    def test_multiple_software(self, extractor):
        """Test: Multiple software extraction"""
        test_cases = [
            ("WinRAR", "6.0"),
            ("Apache HTTP Server", "2.4.49"),
            ("OpenSSL", "1.0.1"),
            ("PHP", "7.4.3"),
            ("MySQL", "5.7.20"),
            ("Nginx", "1.18.0")
        ]
        
        print("\n" + "=" * 70)
        print("🧪 TESTING MULTIPLE SOFTWARE")
        print("=" * 70)
        
        for name, version in test_cases:
            result = extractor.extract_from_software_name(name, version)
            assert result is not None
            assert result['cpe'] is not None
            print(f"\n✅ {name} {version}")
            print(f"   CPE: {result['cpe']}")
            print(f"   Vendor: {result['vendor']}")
            print(f"   Product: {result['product']}")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])