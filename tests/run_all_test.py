# tests/run_all_tests.py

"""
Run all tests and generate report

Usage:
    python tests/run_all_tests.py
"""

import subprocess
import sys
from pathlib import Path

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(text.center(70))
    print("=" * 70)

def run_command(cmd, description):
    """Run a command and print results"""
    print(f"\n▶️  {description}")
    print(f"   Command: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=False,
            text=True,
            check=False
        )
        
        if result.returncode == 0:
            print(f"\n✅ {description} - PASSED")
            return True
        else:
            print(f"\n⚠️  {description} - FAILED")
            return False
            
    except Exception as e:
        print(f"\n❌ {description} - ERROR: {e}")
        return False

def main():
    """Run all tests"""
    
    print_header("🧪 RUNNING ALL TESTS")
    
    results = {}
    
    # Test 1: CPE Extractor
    print_header("TEST 1: CPE Extractor")
    results['cpe_extractor'] = run_command(
        [sys.executable, "-m", "pytest", "tests/test_cpe_extractor.py", "-v"],
        "Testing CPE Extractor"
    )
    
    # Test 2: API Endpoints
    print_header("TEST 2: API Endpoints")
    print("\n⚠️  Make sure server is running: python backend/app.py")
    input("Press Enter when server is ready...")
    
    results['api'] = run_command(
        [sys.executable, "-m", "pytest", "tests/test_api.py", "-v"],
        "Testing API Endpoints"
    )
    
    # Summary
    print_header("📊 TEST SUMMARY")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed
    
    print(f"\n📈 Results:")
    print(f"   Total Tests: {total}")
    print(f"   Passed: {passed} ✅")
    print(f"   Failed: {failed} ❌")
    
    print(f"\n📋 Details:")
    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"   {test_name:20s}: {status}")
    
    # Generate report
    print_header("📄 GENERATING REPORT")
    
    report_path = Path("test_results/test_report.txt")
    report_path.parent.mkdir(exist_ok=True)
    
    with open(report_path, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("CVE-CPE VULNERABILITY SCANNER - TEST REPORT\n")
        f.write("=" * 70 + "\n\n")
        
        f.write(f"Total Tests: {total}\n")
        f.write(f"Passed: {passed}\n")
        f.write(f"Failed: {failed}\n\n")
        
        f.write("Details:\n")
        for test_name, result in results.items():
            status = "PASSED" if result else "FAILED"
            f.write(f"  {test_name}: {status}\n")
    
    print(f"\n✅ Report saved to: {report_path}")
    
    # Exit code
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()