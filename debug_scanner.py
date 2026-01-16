# debug_scanner.py

"""
Debug script to check why CVEs are not showing
Run: python debug_scanner.py
"""

import pandas as pd
from pathlib import Path
import sys

sys.path.append('backend')
from cpe_extractor import CPEExtractor

def print_header(text):
    print("\n" + "=" * 80)
    print(text.center(80))
    print("=" * 80)

def check_dataset():
    """Check if dataset exists and has data"""
    print_header("1. CHECKING DATASET")
    
    csv_path = Path("data/processed/nvd_cve_cpe.csv")
    
    if not csv_path.exists():
        print("❌ Dataset not found at:", csv_path)
        print("\n💡 Solution:")
        print("   1. python utils/download_dataset.py")
        print("   2. python utils/preprocess_data.py")
        return False
    
    print("✅ Dataset found:", csv_path)
    
    # Load and check
    df = pd.read_csv(csv_path)
    print(f"✅ Total CVE records: {len(df):,}")
    
    # Show columns
    print(f"\n📋 Columns in dataset:")
    for i, col in enumerate(df.columns, 1):
        print(f"   {i:2d}. {col}")
    
    # Show sample
    print(f"\n📝 Sample record:")
    if len(df) > 0:
        first = df.iloc[0]
        for col in df.columns[:5]:  # First 5 columns
            value = str(first[col])[:100]
            print(f"   {col}: {value}")
    
    return True

def check_cpe_extraction():
    """Check if CPE extraction works"""
    print_header("2. CHECKING CPE EXTRACTION")
    
    extractor = CPEExtractor()
    
    test_cases = [
        ("WinRAR", "6.0"),
        ("Apache HTTP Server", "2.4.49"),
        ("OpenSSL", "1.0.1")
    ]
    
    for name, version in test_cases:
        result = extractor.extract_from_software_name(name, version)
        print(f"\n🔍 {name} {version}")
        print(f"   CPE: {result['cpe']}")
        print(f"   Vendor: {result['vendor']}")
        print(f"   Product: {result['product']}")

def check_cve_matching():
    """Check if CVE matching works"""
    print_header("3. CHECKING CVE MATCHING")
    
    csv_path = Path("data/processed/nvd_cve_cpe.csv")
    
    if not csv_path.exists():
        print("❌ Dataset not found")
        return
    
    df = pd.read_csv(csv_path)
    
    # Check what columns we have
    print("\n📋 Available columns:")
    for col in df.columns:
        print(f"   - {col}")
    
    # Try to find CPE column
    cpe_col = None
    for col in ['cpe', 'cpe23Uri', 'vulnerable_configuration', 'configurations']:
        if col in df.columns:
            cpe_col = col
            break
    
    if not cpe_col:
        print("\n⚠️ No CPE column found!")
        print("   This dataset might not have CPE information")
        print("   CVE matching will not work properly")
        return
    
    print(f"\n✅ CPE column found: '{cpe_col}'")
    
    # Check CPE content
    print(f"\n📊 CPE Statistics:")
    total_cpes = df[cpe_col].notna().sum()
    print(f"   Records with CPE: {total_cpes:,} / {len(df):,} ({total_cpes/len(df)*100:.1f}%)")
    
    # Show sample CPEs
    print(f"\n📝 Sample CPEs:")
    cpe_samples = df[cpe_col].dropna().head(5)
    for i, cpe in enumerate(cpe_samples, 1):
        cpe_str = str(cpe)[:100]
        print(f"   {i}. {cpe_str}")
    
    # Try to match WinRAR
    print(f"\n🔍 Testing match for 'winrar':")
    matches = df[df[cpe_col].str.contains('winrar', case=False, na=False)]
    print(f"   Found {len(matches)} CVEs containing 'winrar'")
    
    if len(matches) > 0:
        print(f"\n   Top 3 matches:")
        for i, (_, row) in enumerate(matches.head(3).iterrows(), 1):
            cve_id = row.get('cve_id', row.get('id', row.get('CVE-ID', 'N/A')))
            print(f"   {i}. {cve_id}")
    
    # Try Apache
    print(f"\n🔍 Testing match for 'apache':")
    matches = df[df[cpe_col].str.contains('apache', case=False, na=False)]
    print(f"   Found {len(matches)} CVEs containing 'apache'")

def check_column_mapping():
    """Check column mapping"""
    print_header("4. CHECKING COLUMN MAPPING")
    
    import json
    mapping_path = Path("data/processed/column_mapping.json")
    
    if not mapping_path.exists():
        print("⚠️ Column mapping not found")
        print("   This might cause issues")
        return
    
    with open(mapping_path, 'r') as f:
        mapping = json.load(f)
    
    print("✅ Column mapping found:")
    for key, value in mapping.items():
        status = "✅" if value else "❌"
        print(f"   {status} {key:15s}: {value}")

def test_full_flow():
    """Test the complete flow"""
    print_header("5. TESTING FULL FLOW")
    
    print("\n🧪 Testing complete scan flow for WinRAR 6.0...")
    
    # Step 1: Extract CPE
    from cpe_extractor import CPEExtractor
    extractor = CPEExtractor()
    
    result = extractor.extract_from_software_name("WinRAR", "6.0")
    cpe = result['cpe']
    print(f"\n   Step 1: CPE Extraction")
    print(f"   ✅ CPE: {cpe}")
    
    # Step 2: Load dataset
    csv_path = Path("data/processed/nvd_cve_cpe.csv")
    if not csv_path.exists():
        print(f"\n   ❌ Dataset not found")
        return
    
    df = pd.read_csv(csv_path)
    print(f"\n   Step 2: Load Dataset")
    print(f"   ✅ Loaded {len(df):,} records")
    
    # Step 3: Find CPE column
    cpe_col = None
    for col in ['cpe', 'cpe23Uri', 'vulnerable_configuration', 'configurations']:
        if col in df.columns:
            cpe_col = col
            break
    
    if not cpe_col:
        print(f"\n   ❌ No CPE column found in dataset!")
        print(f"   Available columns: {list(df.columns)}")
        return
    
    print(f"\n   Step 3: Find CPE Column")
    print(f"   ✅ Using column: '{cpe_col}'")
    
    # Step 4: Search
    product = cpe.split(':')[4] if ':' in cpe else ''
    print(f"\n   Step 4: Search for product: '{product}'")
    
    matches = df[df[cpe_col].str.contains(product, case=False, na=False)]
    print(f"   ✅ Found {len(matches)} matching CVEs")
    
    if len(matches) > 0:
        print(f"\n   📋 Top 5 CVEs:")
        for i, (_, row) in enumerate(matches.head(5).iterrows(), 1):
            # Try different column names for CVE ID
            cve_id = None
            for col in ['cve_id', 'id', 'CVE-ID', 'cveId']:
                if col in row and pd.notna(row[col]):
                    cve_id = row[col]
                    break
            
            severity = None
            for col in ['severity', 'baseSeverity', 'Severity']:
                if col in row and pd.notna(row[col]):
                    severity = row[col]
                    break
            
            print(f"   {i}. CVE: {cve_id} | Severity: {severity}")
    else:
        print(f"\n   ⚠️ No CVEs found!")
        print(f"   This means:")
        print(f"   - Dataset might not have CVEs for '{product}'")
        print(f"   - OR CPE format in dataset is different")
        print(f"   - OR product name doesn't match")

def main():
    """Run all checks"""
    print_header("🔍 CVE-CPE SCANNER DEBUGGER")
    
    print("\nThis script will help diagnose why CVEs are not showing.\n")
    
    # Check 1: Dataset
    has_dataset = check_dataset()
    
    if not has_dataset:
        print_header("⚠️ FIX REQUIRED")
        print("\n📝 Steps to fix:")
        print("   1. python utils/download_dataset.py")
        print("   2. python utils/preprocess_data.py")
        print("   3. Run this debug script again")
        return
    
    # Check 2: CPE Extraction
    check_cpe_extraction()
    
    # Check 3: CVE Matching
    check_cve_matching()
    
    # Check 4: Column Mapping
    check_column_mapping()
    
    # Check 5: Full Flow
    test_full_flow()
    
    # Summary
    print_header("📊 DIAGNOSIS SUMMARY")
    
    print("\n✅ Checks completed!")
    print("\n💡 If you still don't see CVEs in the web interface:")
    print("   1. Make sure server is running: python backend/app.py")
    print("   2. Check browser console for errors (F12)")
    print("   3. Try different software (Apache, OpenSSL, etc.)")
    print("   4. Dataset might not have CVEs for that specific software")

if __name__ == "__main__":
    main()