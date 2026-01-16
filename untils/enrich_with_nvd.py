# utils/enrich_with_nvd.py

"""
Enrich junction.csv CVEs with real data from NVD API
This will add:
- Real CVSS scores
- Severity levels  
- Descriptions
- Published dates
- References
"""

import pandas as pd
from pathlib import Path
import sys
import json
from datetime import datetime

# Add backend to path
sys.path.append('backend')
from nvd_api import NVDAPI, enrich_cves_from_nvd

def enrich_junction_data(api_key=None, limit=None):
    """
    Enrich junction.csv with NVD data
    
    Args:
        api_key: Optional NVD API key (recommended!)
        limit: Optional limit for testing (e.g., 100 CVEs)
    """
    
    print("=" * 80)
    print("🔧 ENRICHING CVE DATA WITH NVD API")
    print("=" * 80)
    print()
    
    # Load junction.csv
    junction_file = Path("data/processed/junction.csv")
    
    if not junction_file.exists():
        print("❌ ERROR: junction.csv not found!")
        print("   Run: python utils/preprocess_data_junction.py first")
        return False
    
    print("✅ Loading junction.csv...")
    df = pd.read_csv(junction_file)
    print(f"   Total records: {len(df):,}")
    
    # Get unique CVE IDs
    unique_cves = df['cve_id'].unique().tolist()
    print(f"   Unique CVEs: {len(unique_cves):,}")
    
    if limit:
        print(f"\n⚠️  LIMIT MODE: Processing only {limit} CVEs for testing")
        unique_cves = unique_cves[:limit]
    
    # Check for existing enriched data
    enriched_file = Path("data/processed/cve_details_nvd.json")
    
    existing_data = {}
    if enriched_file.exists():
        print(f"\n✅ Found existing enriched data")
        with open(enriched_file, 'r', encoding='utf-8') as f:
            existing_data = json.load(f)
        print(f"   Already have {len(existing_data):,} CVEs")
        
        # Filter out already processed CVEs
        unique_cves = [cve for cve in unique_cves if cve not in existing_data]
        print(f"   Need to fetch: {len(unique_cves):,} new CVEs")
    
    if not unique_cves:
        print("\n✅ All CVEs already enriched!")
        return True
    
    # Estimate time
    if not api_key:
        requests_per_30s = 5
        delay = 6  # seconds per request
    else:
        requests_per_30s = 50
        delay = 0.6
    
    estimated_time = (len(unique_cves) * delay) / 60
    print(f"\n⏱️  Estimated time: {estimated_time:.1f} minutes")
    
    if not api_key:
        print(f"\n💡 Speed up 10x with NVD API key!")
        print(f"   Get one at: https://nvd.nist.gov/developers/request-an-api-key")
        print(f"   Then run: python utils/enrich_with_nvd.py YOUR_API_KEY")
    
    # Confirm
    if not limit and len(unique_cves) > 100:
        print(f"\n⚠️  About to fetch {len(unique_cves):,} CVEs")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            print("Cancelled")
            return False
    
    # Fetch from NVD
    print("\n🚀 Starting NVD API fetch...")
    print("=" * 80)
    
    new_data = enrich_cves_from_nvd(unique_cves, api_key)
    
    # Merge with existing data
    all_data = {**existing_data, **new_data}
    
    # Save enriched data
    print(f"\n💾 Saving enriched data...")
    with open(enriched_file, 'w', encoding='utf-8') as f:
        json.dump(all_data, f, indent=2)
    print(f"   ✓ Saved to: {enriched_file}")
    print(f"   ✓ Total CVEs enriched: {len(all_data):,}")
    
    # Create enriched CSV for easy use
    print(f"\n📊 Creating enriched CSV...")
    
    records = []
    for cve_id, details in all_data.items():
        records.append({
            'cve_id': cve_id,
            'severity': details.get('severity', 'UNKNOWN'),
            'cvss_score': details.get('cvss_score', 0.0),
            'description': details.get('description', '')[:500],  # Limit length
            'published': details.get('published', ''),
            'modified': details.get('modified', ''),
            'vector_string': details.get('vector_string', ''),
            'weaknesses': '|'.join(details.get('weaknesses', [])),
            'references': details.get('references', [])[0] if details.get('references') else ''
        })
    
    df_enriched = pd.DataFrame(records)
    
    enriched_csv = Path("data/processed/cve_details_nvd.csv")
    df_enriched.to_csv(enriched_csv, index=False)
    print(f"   ✓ Saved to: {enriched_csv}")
    
    # Statistics
    print(f"\n" + "=" * 80)
    print("📊 ENRICHMENT STATISTICS")
    print("=" * 80)
    
    # Severity distribution
    severity_counts = df_enriched['severity'].value_counts()
    print(f"\n🎯 Severity Distribution:")
    for severity, count in severity_counts.items():
        pct = count / len(df_enriched) * 100
        print(f"   {severity:15s}: {count:6,} ({pct:5.1f}%)")
    
    # CVSS score stats
    print(f"\n📈 CVSS Scores:")
    print(f"   Average: {df_enriched['cvss_score'].mean():.2f}")
    print(f"   Median:  {df_enriched['cvss_score'].median():.2f}")
    print(f"   Max:     {df_enriched['cvss_score'].max():.2f}")
    print(f"   Min:     {df_enriched['cvss_score'].min():.2f}")
    
    # Top CVEs
    print(f"\n🔴 Top 10 Critical CVEs:")
    top_cves = df_enriched.nlargest(10, 'cvss_score')
    for i, (_, row) in enumerate(top_cves.iterrows(), 1):
        print(f"   {i:2d}. {row['cve_id']} - {row['severity']} (CVSS {row['cvss_score']})")
    
    # Summary
    print(f"\n" + "=" * 80)
    print("✅ ENRICHMENT COMPLETE!")
    print("=" * 80)
    
    print(f"\n📁 Output files:")
    print(f"   - {enriched_file} (JSON)")
    print(f"   - {enriched_csv} (CSV)")
    
    print(f"\n🎯 Next step:")
    print(f"   The server will now use real CVE data!")
    print(f"   python backend/app_junction.py")
    
    return True


def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Enrich CVE data with NVD API')
    parser.add_argument('--api-key', type=str, help='NVD API key (recommended)')
    parser.add_argument('--limit', type=int, help='Limit number of CVEs (for testing)')
    
    args = parser.parse_args()
    
    # Run enrichment
    success = enrich_junction_data(
        api_key=args.api_key,
        limit=args.limit
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()