# utils/download_dataset.py

"""
Download NVD CVE-CPE Dataset from Kaggle
Dataset: https://www.kaggle.com/datasets/nikhilarora1729/nvd-cve-cpe-dataset-till-february-2025
"""

import kaggle
from pathlib import Path
import sys

def download_nvd_dataset():
    """Download and extract NVD CVE-CPE dataset"""
    
    print("=" * 80)
    print("📥 DOWNLOADING NVD CVE-CPE DATASET")
    print("=" * 80)
    
    # Dataset info
    dataset_name = "nikhilarora1729/nvd-cve-cpe-dataset-till-february-2025"
    output_dir = Path("data/raw")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n📦 Dataset: {dataset_name}")
    print(f"📁 Output: {output_dir}")
    print("\n⏰ This may take 5-10 minutes depending on internet speed...\n")
    
    try:
        # Download
        kaggle.api.dataset_download_files(
            dataset_name,
            path=str(output_dir),
            unzip=True
        )
        
        print("\n" + "=" * 80)
        print("✅ DOWNLOAD COMPLETED!")
        print("=" * 80)
        
        # List downloaded files
        print("\n📁 Downloaded files:")
        total_size = 0
        for file in sorted(output_dir.iterdir()):
            size_mb = file.stat().st_size / (1024 * 1024)
            total_size += size_mb
            print(f"  ✓ {file.name:<40} {size_mb:>10.2f} MB")
        
        print(f"\n📊 Total size: {total_size:.2f} MB")
        print(f"📊 Total files: {len(list(output_dir.glob('*.csv')))}")
        
        # Next steps
        print("\n" + "=" * 80)
        print("🎯 NEXT STEPS")
        print("=" * 80)
        print("\n1. Process the data:")
        print("   python utils/preprocess_data.py")
        print("\n2. Start the server:")
        print("   python backend/app.py")
        print("\n3. Open browser:")
        print("   http://localhost:5000")
        
        return True
        
    except FileNotFoundError:
        print("\n❌ ERROR: Kaggle API not configured!")
        print("\n💡 Setup Instructions:")
        print("   1. Go to https://www.kaggle.com")
        print("   2. Click your avatar → Settings")
        print("   3. API → Create New API Token")
        print("   4. Copy kaggle.json to:")
        print("      Windows: C:\\Users\\YourName\\.kaggle\\")
        print("      Linux/Mac: ~/.kaggle/")
        print("\n5. Run this script again")
        return False
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\n💡 Troubleshooting:")
        print("   1. Check internet connection")
        print("   2. Verify Kaggle API setup")
        print("   3. Run: kaggle datasets list")
        print("   4. Try manual download:")
        print(f"      https://www.kaggle.com/datasets/{dataset_name}")
        return False

if __name__ == "__main__":
    success = download_nvd_dataset()
    sys.exit(0 if success else 1)