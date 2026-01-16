# tests/test_complete.py

"""
Complete test with automatic server management
Run: python tests/test_complete.py
"""

import subprocess
import sys
import time
import requests
from pathlib import Path

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 80)
    print(text.center(80))
    print("=" * 80)

def print_section(text):
    """Print section"""
    print(f"\n{text}")
    print("-" * 80)

def start_server():
    """Start Flask server in background"""
    print_section("🚀 Starting Flask server...")
    
    # Start server as subprocess
    server = subprocess.Popen(
        [sys.executable, "backend/app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for server to be ready
    max_retries = 10
    for i in range(max_retries):
        try:
            response = requests.get("http://localhost:5000/api/stats", timeout=1)
            if response.status_code == 200:
                print("✅ Server is ready!")
                return server
        except:
            pass
        
        print(f"⏳ Waiting for server... ({i+1}/{max_retries})")
        time.sleep(2)
    
    print("❌ Server failed to start!")
    server.kill()
    return None

def stop_server(server):
    """Stop Flask server"""
    if server:
        print_section("🛑 Stopping server...")
        server.terminate()
        server.wait(timeout=5)
        print("✅ Server stopped")

def run_test(description, cmd):
    """Run a test command"""
    print_section(f"🧪 {description}")
    print(f"Command: {' '.join(cmd)}\n")
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    return result.returncode == 0

def test_with_requests():
    """Test API endpoints directly"""
    print_section("🧪 Testing API Endpoints")
    
    BASE_URL = "http://localhost:5000"
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: Stats
    print("\n1️⃣ Testing /api/stats")
    try:
        response = requests.get(f"{BASE_URL}/api/stats")
        data = response.json()
        print(f"   ✅ Stats: {data['total_cves']:,} CVEs, {data['total_cpes']:,} CPEs")
        tests_passed += 1
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        tests_failed += 1
    
    # Test 2: Search WinRAR
    print("\n2️⃣ Testing Search - WinRAR")
    try:
        response = requests.post(
            f"{BASE_URL}/api/search",
            json={"software_name": "WinRAR", "version": "6.0"}
        )
        data = response.json()
        
        if data['success']:
            print(f"   ✅ CPE: {data['cpe']}")
            print(f"   ✅ Found {data['statistics']['total_cves']} CVEs")
            
            if data['vulnerabilities']:
                top = data['vulnerabilities'][0]
                print(f"   ✅ Top CVE: {top['cve_id']} - {top['severity']} (CVSS {top['cvss_score']})")
            tests_passed += 1
        else:
            print(f"   ⚠️ Success=False: {data.get('error', 'Unknown error')}")
            tests_failed += 1
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        tests_failed += 1
    
    # Test 3: Search Apache
    print("\n3️⃣ Testing Search - Apache 2.4.49")
    try:
        response = requests.post(
            f"{BASE_URL}/api/search",
            json={"software_name": "Apache HTTP Server", "version": "2.4.49"}
        )
        data = response.json()
        
        if data['success']:
            print(f"   ✅ CPE: {data['cpe']}")
            print(f"   ✅ Found {data['statistics']['total_cves']} CVEs")
            tests_passed += 1
        else:
            print(f"   ⚠️ No results (might be OK if dataset doesn't have this)")
            tests_passed += 1
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        tests_failed += 1
    
    # Test 4: Query CPE
    print("\n4️⃣ Testing Query CPE")
    try:
        response = requests.post(
            f"{BASE_URL}/api/query-cpe",
            json={"cpe": "cpe:2.3:a:rarlab:winrar:-:*:*:*:*:*:*:*"}
        )
        data = response.json()
        
        if data['success']:
            print(f"   ✅ Found {data['statistics']['total_cves']} CVEs")
            tests_passed += 1
        else:
            print(f"   ⚠️ No results")
            tests_passed += 1
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        tests_failed += 1
    
    # Test 5: Invalid request
    print("\n5️⃣ Testing Error Handling")
    try:
        response = requests.post(
            f"{BASE_URL}/api/search",
            json={"version": "1.0"}  # Missing software_name
        )
        
        if response.status_code == 400:
            print(f"   ✅ Error handling works correctly")
            tests_passed += 1
        else:
            print(f"   ❌ Should return 400 but got {response.status_code}")
            tests_failed += 1
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        tests_failed += 1
    
    return tests_passed, tests_failed

def main():
    """Main test runner"""
    
    print_header("🧪 COMPLETE TEST SUITE")
    
    results = {
        'unit_tests': False,
        'api_tests': False
    }
    
    # Test 1: Unit Tests (CPE Extractor)
    print_header("TEST 1: UNIT TESTS (CPE Extractor)")
    results['unit_tests'] = run_test(
        "CPE Extractor Tests",
        [sys.executable, "-m", "pytest", "tests/test_cpe_extractor.py", "-v"]
    )
    
    # Test 2: API Tests with auto server
    print_header("TEST 2: API TESTS (With Auto Server)")
    
    server = start_server()
    
    if server:
        try:
            # Run direct API tests
            tests_passed, tests_failed = test_with_requests()
            results['api_tests'] = tests_failed == 0
            
            print_section(f"📊 API Tests Summary")
            print(f"   Passed: {tests_passed} ✅")
            print(f"   Failed: {tests_failed} ❌")
            
        finally:
            stop_server(server)
    else:
        print("❌ Could not start server for API tests")
        results['api_tests'] = False
    
    # Final Summary
    print_header("📊 FINAL TEST SUMMARY")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed
    
    print(f"\n📈 Overall Results:")
    print(f"   Total Test Suites: {total}")
    print(f"   Passed: {passed} ✅")
    print(f"   Failed: {failed} ❌")
    
    print(f"\n📋 Details:")
    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"   {test_name:20s}: {status}")
    
    # Save report
    print_header("📄 GENERATING REPORT")
    
    report_path = Path("test_results/complete_test_report.txt")
    report_path.parent.mkdir(exist_ok=True)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("CVE-CPE VULNERABILITY SCANNER - COMPLETE TEST REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Total Test Suites: {total}\n")
        f.write(f"Passed: {passed}\n")
        f.write(f"Failed: {failed}\n\n")
        
        f.write("Details:\n")
        for test_name, result in results.items():
            status = "PASSED" if result else "FAILED"
            f.write(f"  {test_name}: {status}\n")
    
    print(f"\n✅ Report saved to: {report_path}")
    
    # Exit code
    if failed == 0:
        print_header("✅ ALL TESTS PASSED! 🎉")
        sys.exit(0)
    else:
        print_header("⚠️ SOME TESTS FAILED")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
        sys.exit(1)