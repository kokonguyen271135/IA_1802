# tests/test_api.py

"""
Test API endpoints
Run: pytest tests/test_api.py -v
"""

import pytest
import requests
import json
import time

BASE_URL = "http://localhost:5000"

class TestAPI:
    """Test Flask API endpoints"""
    
    @pytest.fixture(scope="class", autouse=True)
    def wait_for_server(self):
        """Wait for server to be ready"""
        max_retries = 5
        for i in range(max_retries):
            try:
                response = requests.get(f"{BASE_URL}/api/stats", timeout=2)
                if response.status_code == 200:
                    print("\n✅ Server is ready")
                    return
            except:
                if i < max_retries - 1:
                    print(f"\n⏳ Waiting for server... ({i+1}/{max_retries})")
                    time.sleep(2)
        
        pytest.skip("Server not running. Start with: python backend/app.py")
    
    def test_server_running(self):
        """Test: Server is running"""
        response = requests.get(f"{BASE_URL}/api/stats")
        assert response.status_code == 200
        print("\n✅ Server is running")
    
    def test_stats_endpoint(self):
        """Test: GET /api/stats"""
        response = requests.get(f"{BASE_URL}/api/stats")
        
        assert response.status_code == 200
        data = response.json()
        
        assert 'total_cves' in data
        assert 'total_cpes' in data
        assert 'total_mappings' in data
        
        print(f"\n✅ Database Stats:")
        print(f"   Total CVEs: {data['total_cves']:,}")
        print(f"   Total CPEs: {data['total_cpes']:,}")
        print(f"   Total Mappings: {data['total_mappings']:,}")
    
    def test_search_winrar(self):
        """Test: POST /api/search - WinRAR"""
        payload = {
            "software_name": "WinRAR",
            "version": "6.0"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/search",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data['success'] == True
        assert 'cpe' in data
        assert 'vulnerabilities' in data
        assert 'statistics' in data
        
        print(f"\n✅ WinRAR Search:")
        print(f"   CPE: {data['cpe']}")
        print(f"   Total CVEs: {data['statistics']['total_cves']}")
        print(f"   Critical: {data['statistics']['by_severity'].get('CRITICAL', 0)}")
        print(f"   High: {data['statistics']['by_severity'].get('HIGH', 0)}")
        
        if data['vulnerabilities']:
            print(f"\n   Top vulnerability:")
            cve = data['vulnerabilities'][0]
            print(f"   - {cve['cve_id']}: {cve['severity']} (CVSS {cve['cvss_score']})")
    
    def test_search_apache(self):
        """Test: POST /api/search - Apache"""
        payload = {
            "software_name": "Apache HTTP Server",
            "version": "2.4.49"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/search",
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data['success'] == True
        
        print(f"\n✅ Apache Search:")
        print(f"   CPE: {data['cpe']}")
        print(f"   Total CVEs: {data['statistics']['total_cves']}")
    
    def test_search_openssl(self):
        """Test: POST /api/search - OpenSSL (Heartbleed)"""
        payload = {
            "software_name": "OpenSSL",
            "version": "1.0.1"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/search",
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data['success'] == True
        
        print(f"\n✅ OpenSSL Search (Heartbleed):")
        print(f"   CPE: {data['cpe']}")
        print(f"   Total CVEs: {data['statistics']['total_cves']}")
        
        # Check for Heartbleed CVE-2014-0160
        cve_ids = [v['cve_id'] for v in data['vulnerabilities']]
        if 'CVE-2014-0160' in cve_ids:
            print(f"   ✅ Heartbleed (CVE-2014-0160) detected!")
    
    def test_query_cpe(self):
        """Test: POST /api/query-cpe"""
        payload = {
            "cpe": "cpe:2.3:a:rarlab:winrar:6.0:*:*:*:*:*:*:*"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/query-cpe",
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data['success'] == True
        
        print(f"\n✅ CPE Query:")
        print(f"   CPE: {data['cpe']}")
        print(f"   Total CVEs: {data['statistics']['total_cves']}")
    
    def test_search_invalid(self):
        """Test: Search without software_name"""
        payload = {
            "version": "1.0"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/search",
            json=payload
        )
        
        assert response.status_code == 400
        data = response.json()
        
        assert data['success'] == False
        assert 'error' in data
        
        print(f"\n✅ Invalid request handled correctly")
    
    def test_multiple_software_batch(self):
        """Test: Batch search multiple software"""
        test_cases = [
            ("WinRAR", "6.0", "rarlab:winrar"),
            ("Apache HTTP Server", "2.4.49", "apache:http_server"),
            ("MySQL", "5.7.20", "mysql:mysql"),
            ("Nginx", "1.18.0", "nginx:nginx"),
            ("PHP", "7.4.3", "php:php")
        ]
        
        print("\n" + "=" * 70)
        print("🧪 BATCH TESTING MULTIPLE SOFTWARE")
        print("=" * 70)
        
        for name, version, expected_vendor_product in test_cases:
            payload = {
                "software_name": name,
                "version": version
            }
            
            response = requests.post(
                f"{BASE_URL}/api/search",
                json=payload
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True
            
            print(f"\n✅ {name} {version}")
            print(f"   CPE: {data['cpe']}")
            print(f"   CVEs: {data['statistics']['total_cves']}")
            
            if data['vulnerabilities']:
                top = data['vulnerabilities'][0]
                print(f"   Top: {top['cve_id']} - {top['severity']} (CVSS {top['cvss_score']})")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])