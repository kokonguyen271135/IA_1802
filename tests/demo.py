# tests/demo.py

"""
Quick Demo Script
Demonstrates all features without web browser

Run: python tests/demo.py
"""

import sys
from pathlib import Path
import requests
import json
import time

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'backend'))

from cpe_extractor import CPEExtractor

BASE_URL = "http://localhost:5000"

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(text.center(70))
    print("=" * 70)

def print_section(text):
    """Print section header"""
    print("\n" + "-" * 70)
    print(text)
    print("-" * 70)

def demo_cpe_extractor():
    """Demo: CPE Extractor"""
    print_header("🔍 DEMO: CPE EXTRACTOR")
    
    extractor = CPEExtractor()
    
    test_cases = [
        ("WinRAR", "6.0"),
        ("Apache HTTP Server", "2.4.49"),
        ("OpenSSL", "1.0.1"),
        ("MySQL", "5.7.20"),
        ("PHP", "7.4.3"),
        ("Nginx", "1.18.0")
    ]
    
    for software_name, version in test_cases:
        print_section(f"Software: {software_name} {version}")
        
        result = extractor.extract_from_software_name(software_name, version)
        
        print(f"✅ CPE: {result['cpe']}")
        print(f"   Vendor: {result['vendor']}")
        print(f"   Product: {result['product']}")
        print(f"   Version: {result['version']}")

def check_server():
    """Check if server is running"""
    try:
        response = requests.get(f"{BASE_URL}/api/stats", timeout=2)
        return response.status_code == 200
    except:
        return False

def demo_api():
    """Demo: API Endpoints"""
    print_header("🌐 DEMO: API ENDPOINTS")
    
    if not check_server():
        print("\n❌ Server not running!")
        print("   Start server: python backend/app.py")
        print("   Then run this demo again")
        return
    
    print("\n✅ Server is running at http://localhost:5000")
    
    # Demo 1: WinRAR
    print_section("Demo 1: Search WinRAR 6.0")
    
    payload = {
        "software_name": "WinRAR",
        "version": "6.0"
    }
    
    response = requests.post(f"{BASE_URL}/api/search", json=payload)
    data = response.json()
    
    if data['success']:
        print(f"✅ CPE: {data['cpe']}")
        print(f"\n📊 Statistics:")
        print(f"   Total CVEs: {data['statistics']['total_cves']}")
        print(f"   Critical: {data['statistics']['by_severity'].get('CRITICAL', 0)}")
        print(f"   High: {data['statistics']['by_severity'].get('HIGH', 0)}")
        print(f"   Medium: {data['statistics']['by_severity'].get('MEDIUM', 0)}")
        print(f"   Low: {data['statistics']['by_severity'].get('LOW', 0)}")
        print(f"   Avg CVSS: {data['statistics']['avg_cvss']}")
        
        if data['vulnerabilities']:
            print(f"\n🔴 Top 3 Vulnerabilities:")
            for i, cve in enumerate(data['vulnerabilities'][:3], 1):
                print(f"\n   {i}. {cve['cve_id']} - {cve['severity']} (CVSS {cve['cvss_score']})")
                print(f"      {cve['summary'][:100]}...")
    
    # Demo 2: Apache (CVE-2021-41773)
    print_section("Demo 2: Search Apache 2.4.49 (Known vulnerability)")
    
    payload = {
        "software_name": "Apache HTTP Server",
        "version": "2.4.49"
    }
    
    response = requests.post(f"{BASE_URL}/api/search", json=payload)
    data = response.json()
    
    if data['success']:
        print(f"✅ CPE: {data['cpe']}")
        print(f"   Total CVEs: {data['statistics']['total_cves']}")
        
        # Check for CVE-2021-41773
        cve_ids = [v['cve_id'] for v in data['vulnerabilities']]
        if 'CVE-2021-41773' in cve_ids:
            print(f"\n   ✅ CVE-2021-41773 (Path Traversal) detected!")
    
    # Demo 3: OpenSSL (Heartbleed)
    print_section("Demo 3: Search OpenSSL 1.0.1 (Heartbleed)")
    
    payload = {
        "software_name": "OpenSSL",
        "version": "1.0.1"
    }
    
    response = requests.post(f"{BASE_URL}/api/search", json=payload)
    data = response.json()
    
    if data['success']:
        print(f"✅ CPE: {data['cpe']}")
        print(f"   Total CVEs: {data['statistics']['total_cves']}")
        
        # Check for CVE-2014-0160 (Heartbleed)
        cve_ids = [v['cve_id'] for v in data['vulnerabilities']]
        if 'CVE-2014-0160' in cve_ids:
            print(f"\n   ✅ CVE-2014-0160 (Heartbleed) detected!")
    
    # Demo 4: Query by CPE
    print_section("Demo 4: Direct CPE Query")
    
    payload = {
        "cpe": "cpe:2.3:a:rarlab:winrar:-:*:*:*:*:*:*:*"
    }
    
    response = requests.post(f"{BASE_URL}/api/query-cpe", json=payload)
    data = response.json()
    
    if data['success']:
        print(f"✅ CPE: {data['cpe']}")
        print(f"   Total CVEs: {data['statistics']['total_cves']}")

def demo_comparison():
    """Demo: Comparison with/without AI"""
    print_header("📊 DEMO: COMPARISON")
    
    if not check_server():
        print("\n❌ Server not running!")
        return
    
    test_cases = [
        "winrar",  # Should match WinRAR
        "apache",  # Should match Apache
        "ssl",     # Should match OpenSSL
    ]
    
    print("\n🧪 Testing fuzzy/semantic matching:")
    
    for query in test_cases:
        print(f"\n🔍 Query: '{query}'")
        
        # Try exact match (will likely fail)
        payload = {"software_name": query}
        response = requests.post(f"{BASE_URL}/api/search", json=payload)
        data = response.json()
        
        if data['success']:
            print(f"   ✅ Matched: {data['cpe']}")
            print(f"      Method: Fuzzy/Semantic matching")
        else:
            print(f"   ❌ No match found")

def main():
    """Run all demos"""
    print_header("🎮 CVE-CPE VULNERABILITY SCANNER - DEMO")
    
    print("\n📋 Available Demos:")
    print("   1. CPE Extractor Demo")
    print("   2. API Endpoints Demo")
    print("   3. Comparison Demo")
    print("   4. All Demos")
    
    choice = input("\nSelect demo (1-4) or press Enter for all: ").strip()
    
    if choice == "1":
        demo_cpe_extractor()
    elif choice == "2":
        demo_api()
    elif choice == "3":
        demo_comparison()
    else:
        # Run all
        demo_cpe_extractor()
        time.sleep(1)
        demo_api()
        time.sleep(1)
        demo_comparison()
    
    print_header("✅ DEMO COMPLETED")
    print("\n📝 Next steps:")
    print("   - Open web browser: http://localhost:5000")
    print("   - Upload files to scan")
    print("   - Run tests: pytest tests/ -v")

if __name__ == "__main__":
    main()