# # utils/preprocess_data.py

# """
# Preprocess NVD CVE-CPE Dataset
# - Load CSV files
# - Clean data
# - Build CPE dictionary
# - Create indexed database
# """

# import pandas as pd
# from pathlib import Path
# import pickle
# import json

# def preprocess_nvd_data():
#     """Process NVD dataset for fast querying"""
    
#     print("=" * 80)
#     print("🔧 PREPROCESSING NVD DATASET")
#     print("=" * 80)
    
#     data_dir = Path("data/raw")
#     processed_dir = Path("data/processed")
#     processed_dir.mkdir(parents=True, exist_ok=True)
    
#     # Find CSV files
#     csv_files = list(data_dir.glob("*.csv"))
    
#     if not csv_files:
#         print("\n❌ ERROR: No CSV files found!")
#         print(f"Expected location: {data_dir}")
#         print("\n💡 Run download_dataset.py first:")
#         print("   python utils/download_dataset.py")
#         return False
    
#     print(f"\n📁 Found {len(csv_files)} CSV file(s)")
    
#     # Load main dataset
#     main_file = csv_files[0]
#     print(f"\n📖 Loading: {main_file.name}")
    
#     df = pd.read_csv(main_file, low_memory=False)
    
#     print(f"   ✓ Total records: {len(df):,}")
#     print(f"   ✓ Columns: {len(df.columns)}")
    
#     # Display columns
#     print(f"\n📋 Dataset columns:")
#     for i, col in enumerate(df.columns, 1):
#         null_pct = (df[col].isnull().sum() / len(df)) * 100
#         print(f"   {i:2d}. {col:30s} (nulls: {null_pct:5.1f}%)")
    
#     # Detect column names
#     column_map = detect_columns(df)
#     print(f"\n🔍 Detected column mapping:")
#     for key, val in column_map.items():
#         if val:
#             print(f"   ✓ {key:15s}: '{val}'")
#         else:
#             print(f"   ✗ {key:15s}: NOT FOUND")
    
#     # Clean data
#     print(f"\n🧹 Cleaning data...")
    
#     df_clean = df.copy()
    
#     # Remove nulls in critical columns
#     if column_map['cve_id']:
#         df_clean = df_clean[df_clean[column_map['cve_id']].notna()]
    
#     if column_map['cpe']:
#         df_clean = df_clean[df_clean[column_map['cpe']].notna()]
    
#     # Remove duplicates
#     before = len(df_clean)
#     if column_map['cve_id']:
#         df_clean = df_clean.drop_duplicates(subset=[column_map['cve_id']])
#     after = len(df_clean)
    
#     print(f"   ✓ Removed {before - after:,} duplicates")
#     print(f"   ✓ Clean records: {after:,}")
    
#     # Save processed CSV
#     output_csv = processed_dir / "nvd_cve_cpe.csv"
#     df_clean.to_csv(output_csv, index=False)
#     print(f"\n💾 Saved: {output_csv}")
    
#     # Build CPE dictionary
#     print(f"\n📚 Building CPE dictionary...")
#     cpe_dict = build_cpe_dictionary(df_clean, column_map)
    
#     # Save CPE dictionary
#     cpe_dict_file = processed_dir / "cpe_dictionary.pkl"
#     with open(cpe_dict_file, 'wb') as f:
#         pickle.dump(cpe_dict, f)
    
#     print(f"   ✓ CPE entries: {len(cpe_dict):,}")
#     print(f"   💾 Saved: {cpe_dict_file}")
    
#     # Build CVE index (CPE → CVEs mapping)
#     print(f"\n🔗 Building CVE index...")
#     cve_index = build_cve_index(df_clean, column_map)
    
#     # Save CVE index
#     cve_index_file = processed_dir / "cve_index.pkl"
#     with open(cve_index_file, 'wb') as f:
#         pickle.dump(cve_index, f)
    
#     print(f"   ✓ CPE → CVE mappings: {len(cve_index):,}")
#     print(f"   💾 Saved: {cve_index_file}")
    
#     # Save column mapping
#     mapping_file = processed_dir / "column_mapping.json"
#     with open(mapping_file, 'w') as f:
#         json.dump(column_map, f, indent=2)
    
#     print(f"   💾 Saved: {mapping_file}")
    
#     # Statistics
#     print(f"\n" + "=" * 80)
#     print("📊 DATASET STATISTICS")
#     print("=" * 80)
    
#     if column_map['severity']:
#         print(f"\n⚠️  Severity distribution:")
#         severity_counts = df_clean[column_map['severity']].value_counts()
#         for severity, count in severity_counts.items():
#             pct = (count / len(df_clean)) * 100
#             print(f"   {severity:15s}: {count:>8,} ({pct:5.1f}%)")
    
#     if column_map['cvss_score']:
#         print(f"\n📊 CVSS Score statistics:")
#         cvss_col = column_map['cvss_score']
#         cvss_clean = pd.to_numeric(df_clean[cvss_col], errors='coerce')
#         print(f"   Mean:   {cvss_clean.mean():.2f}")
#         print(f"   Median: {cvss_clean.median():.2f}")
#         print(f"   Max:    {cvss_clean.max():.2f}")
#         print(f"   Min:    {cvss_clean.min():.2f}")
    
#     # Summary
#     print(f"\n" + "=" * 80)
#     print("✅ PREPROCESSING COMPLETE!")
#     print("=" * 80)
    
#     print(f"\n📁 Output files:")
#     print(f"   1. {output_csv}")
#     print(f"   2. {cpe_dict_file}")
#     print(f"   3. {cve_index_file}")
#     print(f"   4. {mapping_file}")
    
#     print(f"\n🎯 Next: Start the web server")
#     print(f"   python backend/app.py")
    
#     return True

# def detect_columns(df):
#     """Detect actual column names in dataset"""
    
#     mappings = {
#         'cve_id': ['cve_id', 'cve', 'id', 'CVE-ID', 'cveId'],
#         'cpe': ['cpe', 'cpe23Uri', 'cpe_uri', 'vulnerable_configuration'],
#         'description': ['description', 'desc', 'summary', 'Description'],
#         'cvss_score': ['cvss_score', 'baseScore', 'cvss', 'cvssV3_baseScore'],
#         'severity': ['severity', 'baseSeverity', 'Severity'],
#         'published': ['published_date', 'publishedDate', 'published'],
#         'references': ['references', 'reference', 'url']
#     }
    
#     detected = {}
    
#     for key, possible_names in mappings.items():
#         found = None
#         for name in possible_names:
#             if name in df.columns:
#                 found = name
#                 break
#         detected[key] = found
    
#     return detected

# def build_cpe_dictionary(df, column_map):
#     """Build dictionary of CPE → product info"""
    
#     cpe_dict = {}
    
#     cpe_col = column_map['cpe']
#     if not cpe_col:
#         return cpe_dict
    
#     for cpe_string in df[cpe_col].dropna().unique():
#         if not cpe_string or cpe_string == '':
#             continue
        
#         # Handle multiple CPEs separated by | or ;
#         cpes = [c.strip() for c in str(cpe_string).replace(';', '|').split('|')]
        
#         for cpe in cpes:
#             if not cpe or 'cpe:' not in cpe.lower():
#                 continue
            
#             # Parse CPE 2.3 format
#             # cpe:2.3:part:vendor:product:version:...
#             try:
#                 parts = cpe.split(':')
#                 if len(parts) >= 5:
#                     cpe_dict[cpe] = {
#                         'vendor': parts[3],
#                         'product': parts[4],
#                         'version': parts[5] if len(parts) > 5 and parts[5] != '*' else ''
#                     }
#             except:
#                 continue
    
#     return cpe_dict

# def build_cve_index(df, column_map):
#     """Build index: CPE → [CVE IDs]"""
    
#     cve_index = {}
    
#     cpe_col = column_map['cpe']
#     cve_col = column_map['cve_id']
    
#     if not cpe_col or not cve_col:
#         return cve_index
    
#     for _, row in df.iterrows():
#         cpe_string = row.get(cpe_col)
#         cve_id = row.get(cve_col)
        
#         if pd.isna(cpe_string) or pd.isna(cve_id):
#             continue
        
#         # Handle multiple CPEs
#         cpes = [c.strip() for c in str(cpe_string).replace(';', '|').split('|')]
        
#         for cpe in cpes:
#             if not cpe or 'cpe:' not in cpe.lower():
#                 continue
            
#             if cpe not in cve_index:
#                 cve_index[cpe] = []
            
#             if cve_id not in cve_index[cpe]:
#                 cve_index[cpe].append(cve_id)
    
#     return cve_index

# if __name__ == "__main__":
#     import sys
#     success = preprocess_nvd_data()
#     sys.exit(0 if success else 1)

# utils/preprocess_data.py

"""
Preprocess NVD CVE-CPE Dataset with junction.csv
- Load junction.csv (CVE-ID, CPE mapping)
- Load CVE details (if available)
- Build indexes for fast querying
"""

import pandas as pd
from pathlib import Path
import pickle
import json
from collections import defaultdict

def preprocess_nvd_data():
    """Process NVD dataset with junction.csv"""
    
    print("=" * 80)
    print("🔧 PREPROCESSING NVD DATASET (junction.csv)")
    print("=" * 80)
    
    data_dir = Path("data/raw")
    processed_dir = Path("data/processed")
    processed_dir.mkdir(parents=True, exist_ok=True)
    
    # Find junction.csv
    junction_file = data_dir / "junction.csv"
    
    if not junction_file.exists():
        print(f"\n❌ ERROR: junction.csv not found!")
        print(f"Expected location: {junction_file}")
        print("\n💡 Make sure you have:")
        print("   data/raw/junction.csv")
        return False
    
    print(f"\n✅ Found junction.csv")
    
    # Load junction.csv
    print(f"\n📖 Loading junction.csv...")
    df_junction = pd.read_csv(junction_file, names=['cve_id', 'cpe'], header=None)
    
    print(f"   ✓ Total records: {len(df_junction):,}")
    print(f"\n📋 Sample records:")
    for i, row in df_junction.head(5).iterrows():
        print(f"   {row['cve_id']} → {row['cpe']}")
    
    # Clean data
    print(f"\n🧹 Cleaning data...")
    
    # Remove nulls
    before = len(df_junction)
    df_junction = df_junction.dropna()
    after = len(df_junction)
    print(f"   ✓ Removed {before - after:,} null records")
    
    # Remove duplicates
    before = len(df_junction)
    df_junction = df_junction.drop_duplicates()
    after = len(df_junction)
    print(f"   ✓ Removed {before - after:,} duplicate records")
    
    print(f"   ✓ Clean records: {len(df_junction):,}")
    
    # Build CPE dictionary
    print(f"\n📚 Building CPE dictionary...")
    cpe_dict = {}
    
    for cpe_string in df_junction['cpe'].unique():
        if not cpe_string or 'cpe:' not in str(cpe_string).lower():
            continue
        
        # Parse CPE 2.3 format
        # cpe:2.3:a:vendor:product:version:...
        try:
            parts = str(cpe_string).split(':')
            if len(parts) >= 5:
                cpe_dict[cpe_string] = {
                    'part': parts[2],      # a = application
                    'vendor': parts[3],
                    'product': parts[4],
                    'version': parts[5] if len(parts) > 5 and parts[5] != '*' else ''
                }
        except:
            continue
    
    print(f"   ✓ Unique CPEs: {len(cpe_dict):,}")
    
    # Build CVE index (CPE → CVE IDs)
    print(f"\n🔗 Building CVE index (CPE → CVEs)...")
    cve_index = defaultdict(list)
    
    for _, row in df_junction.iterrows():
        cpe = row['cpe']
        cve_id = row['cve_id']
        
        if cpe and cve_id:
            if cve_id not in cve_index[cpe]:
                cve_index[cpe].append(cve_id)
    
    # Convert to regular dict
    cve_index = dict(cve_index)
    
    print(f"   ✓ CPE → CVE mappings: {len(cve_index):,}")
    
    # Build reverse index (CVE → CPEs)
    print(f"\n🔄 Building reverse index (CVE → CPEs)...")
    cve_to_cpe = defaultdict(list)
    
    for _, row in df_junction.iterrows():
        cpe = row['cpe']
        cve_id = row['cve_id']
        
        if cpe and cve_id:
            if cpe not in cve_to_cpe[cve_id]:
                cve_to_cpe[cve_id].append(cpe)
    
    cve_to_cpe = dict(cve_to_cpe)
    
    print(f"   ✓ CVE → CPE mappings: {len(cve_to_cpe):,}")
    
    # Build product index (product_name → CPEs)
    print(f"\n📦 Building product index...")
    product_index = defaultdict(set)
    
    for cpe_string, cpe_info in cpe_dict.items():
        vendor = cpe_info['vendor'].lower()
        product = cpe_info['product'].lower()
        
        # Add to product index
        product_index[product].add(cpe_string)
        
        # Also add vendor:product combination
        vendor_product = f"{vendor}:{product}"
        product_index[vendor_product].add(cpe_string)
    
    # Convert sets to lists
    product_index = {k: list(v) for k, v in product_index.items()}
    
    print(f"   ✓ Product entries: {len(product_index):,}")
    
    # Check for additional CVE details
    print(f"\n🔍 Looking for CVE details file...")
    
    cve_details_files = list(data_dir.glob("*cve*.csv"))
    cve_details_files = [f for f in cve_details_files if f.name != 'junction.csv']
    
    df_cve_details = None
    
    if cve_details_files:
        print(f"   ✓ Found {len(cve_details_files)} CVE detail file(s)")
        
        # Use first file
        cve_file = cve_details_files[0]
        print(f"   📖 Loading: {cve_file.name}")
        
        try:
            df_cve_details = pd.read_csv(cve_file, low_memory=False)
            print(f"   ✓ Loaded {len(df_cve_details):,} CVE records")
            
            # Show columns
            print(f"\n   📋 Available columns:")
            for i, col in enumerate(df_cve_details.columns[:10], 1):
                print(f"      {i}. {col}")
            
        except Exception as e:
            print(f"   ⚠️  Could not load CVE details: {e}")
            df_cve_details = None
    else:
        print(f"   ⚠️  No CVE details file found")
        print(f"   Will create basic CVE database from junction.csv")
    
    # Create combined CVE database
    print(f"\n🗃️  Creating CVE database...")
    
    if df_cve_details is not None:
        # Merge junction with details
        # Detect CVE ID column
        cve_id_col = None
        for col in ['cve_id', 'id', 'CVE-ID', 'cveId']:
            if col in df_cve_details.columns:
                cve_id_col = col
                break
        
        if cve_id_col:
            # Add CPE to details
            df_cve_details['cpe_list'] = df_cve_details[cve_id_col].map(
                lambda cve: '|'.join(cve_to_cpe.get(cve, []))
            )
            
            cve_db = df_cve_details
            print(f"   ✓ Merged junction with CVE details")
        else:
            # Create from junction only
            cve_db = create_basic_cve_db(df_junction, cve_to_cpe)
    else:
        # Create from junction only
        cve_db = create_basic_cve_db(df_junction, cve_to_cpe)
    
    # Save all files
    print(f"\n💾 Saving processed files...")
    
    # 1. Save junction data
    junction_out = processed_dir / "junction.csv"
    df_junction.to_csv(junction_out, index=False)
    print(f"   ✓ {junction_out}")
    
    # 2. Save CVE database
    cve_db_out = processed_dir / "nvd_cve_cpe.csv"
    cve_db.to_csv(cve_db_out, index=False)
    print(f"   ✓ {cve_db_out}")
    
    # 3. Save CPE dictionary
    cpe_dict_out = processed_dir / "cpe_dictionary.pkl"
    with open(cpe_dict_out, 'wb') as f:
        pickle.dump(cpe_dict, f)
    print(f"   ✓ {cpe_dict_out}")
    
    # 4. Save CVE index
    cve_index_out = processed_dir / "cve_index.pkl"
    with open(cve_index_out, 'wb') as f:
        pickle.dump(cve_index, f)
    print(f"   ✓ {cve_index_out}")
    
    # 5. Save product index
    product_index_out = processed_dir / "product_index.pkl"
    with open(product_index_out, 'wb') as f:
        pickle.dump(product_index, f)
    print(f"   ✓ {product_index_out}")
    
    # 6. Save column mapping
    column_mapping = detect_columns(cve_db)
    mapping_out = processed_dir / "column_mapping.json"
    with open(mapping_out, 'w') as f:
        json.dump(column_mapping, f, indent=2)
    print(f"   ✓ {mapping_out}")
    
    # Statistics
    print(f"\n" + "=" * 80)
    print("📊 DATASET STATISTICS")
    print("=" * 80)
    
    print(f"\n📈 Records:")
    print(f"   Total CVEs: {len(cve_db):,}")
    print(f"   Unique CPEs: {len(cpe_dict):,}")
    print(f"   CPE → CVE mappings: {len(cve_index):,}")
    print(f"   Product entries: {len(product_index):,}")
    
    print(f"\n🏆 Top 10 products by CVE count:")
    product_cve_count = {}
    for product, cpes in list(product_index.items())[:100]:  # Check first 100
        total_cves = sum(len(cve_index.get(cpe, [])) for cpe in cpes)
        if total_cves > 0:
            product_cve_count[product] = total_cves
    
    top_products = sorted(product_cve_count.items(), key=lambda x: x[1], reverse=True)[:10]
    for i, (product, count) in enumerate(top_products, 1):
        print(f"   {i:2d}. {product:30s}: {count:,} CVEs")
    
    # Sample queries
    print(f"\n🔍 Sample queries:")
    test_products = ['winrar', 'apache', 'openssl', 'mysql', 'nginx']
    
    for product in test_products:
        if product in product_index:
            cpes = product_index[product]
            total_cves = sum(len(cve_index.get(cpe, [])) for cpe in cpes)
            print(f"   {product:15s}: {len(cpes):3d} CPEs, {total_cves:4d} CVEs")
        else:
            print(f"   {product:15s}: Not found")
    
    # Summary
    print(f"\n" + "=" * 80)
    print("✅ PREPROCESSING COMPLETE!")
    print("=" * 80)
    
    print(f"\n📁 Output files in: {processed_dir}/")
    print(f"\n🎯 Next step: Start the web server")
    print(f"   python backend/app.py")
    
    return True

def create_basic_cve_db(df_junction, cve_to_cpe):
    """Create basic CVE database from junction only"""
    
    print(f"   Creating basic CVE database from junction.csv...")
    
    # Get unique CVEs
    unique_cves = df_junction['cve_id'].unique()
    
    # Create basic records
    records = []
    for cve_id in unique_cves:
        cpes = cve_to_cpe.get(cve_id, [])
        
        records.append({
            'cve_id': cve_id,
            'cpe_list': '|'.join(cpes),
            'cpe_count': len(cpes),
            'description': f'CVE {cve_id}',  # Placeholder
            'cvss_score': 0.0,  # Unknown
            'severity': 'UNKNOWN'  # Unknown
        })
    
    df = pd.DataFrame(records)
    print(f"   ✓ Created basic database with {len(df):,} CVEs")
    
    return df

def detect_columns(df):
    """Detect actual column names in dataset"""
    
    mappings = {
        'cve_id': ['cve_id', 'cve', 'id', 'CVE-ID', 'cveId'],
        'cpe': ['cpe_list', 'cpe', 'cpe23Uri', 'cpe_uri', 'vulnerable_configuration'],
        'description': ['description', 'desc', 'summary', 'Description'],
        'cvss_score': ['cvss_score', 'baseScore', 'cvss', 'cvssV3_baseScore'],
        'severity': ['severity', 'baseSeverity', 'Severity'],
        'published': ['published_date', 'publishedDate', 'published'],
        'references': ['references', 'reference', 'url']
    }
    
    detected = {}
    
    for key, possible_names in mappings.items():
        found = None
        for name in possible_names:
            if name in df.columns:
                found = name
                break
        detected[key] = found
    
    return detected

if __name__ == "__main__":
    import sys
    success = preprocess_nvd_data()
    sys.exit(0 if success else 1)