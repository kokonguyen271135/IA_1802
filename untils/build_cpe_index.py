# untils/build_cpe_index.py

"""
Build Semantic CPE Index using sentence-transformers + FAISS.

Sources:
  1. Curated list of ~100 common software CPEs (hardcoded below)
  2. CPE strings extracted from NVD cache files (data/cache/nvd/)

Output:
  models/cpe_index.faiss  — FAISS inner-product index (cosine on normalised vectors)
  models/cpe_meta.pkl     — metadata list of CPE entries

At query time, encode a software name and do a nearest-neighbour search.
"""

import json
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent

# ── Curated CPE list ─────────────────────────────────────────────────────────
# Format: (vendor, product, human_display_name)
COMMON_CPES = [
    # Compression
    ("rarlab",              "winrar",                     "WinRAR"),
    ("7-zip",               "7-zip",                      "7-Zip"),
    ("winzip",              "winzip",                     "WinZip"),
    # Web servers
    ("apache",              "http_server",                "Apache HTTP Server"),
    ("apache",              "tomcat",                     "Apache Tomcat"),
    ("nginx",               "nginx",                      "Nginx"),
    ("microsoft",           "iis",                        "Microsoft IIS"),
    # Databases
    ("mysql",               "mysql",                      "MySQL"),
    ("oracle",              "mysql",                      "Oracle MySQL"),
    ("postgresql",          "postgresql",                 "PostgreSQL"),
    ("mongodb",             "mongodb",                    "MongoDB"),
    ("redis",               "redis",                      "Redis"),
    ("elastic",             "elasticsearch",              "Elasticsearch"),
    ("sqlite",              "sqlite",                     "SQLite"),
    ("microsoft",           "sql_server",                 "Microsoft SQL Server"),
    ("oracle",              "database_server",            "Oracle Database"),
    # Security / TLS
    ("openssl",             "openssl",                    "OpenSSL"),
    ("openbsd",             "openssh",                    "OpenSSH"),
    ("mozilla",             "nss",                        "Mozilla NSS"),
    # Languages / runtimes
    ("python",              "python",                     "Python"),
    ("php",                 "php",                        "PHP"),
    ("oracle",              "jre",                        "Oracle Java JRE"),
    ("oracle",              "jdk",                        "Oracle Java JDK"),
    ("nodejs",              "node.js",                    "Node.js"),
    ("golang",              "go",                         "Go"),
    ("rust-lang",           "rust",                       "Rust"),
    # Frameworks / libraries
    ("apache",              "log4j",                      "Apache Log4j"),
    ("apache",              "struts",                     "Apache Struts"),
    ("pivotal_software",    "spring_framework",           "Spring Framework"),
    ("springframework",     "spring_boot",                "Spring Boot"),
    ("curl",                "curl",                       "cURL"),
    ("haxx",                "libcurl",                    "libcURL"),
    ("libpng",              "libpng",                     "libpng"),
    ("zlib",                "zlib",                       "zlib"),
    ("git-scm",             "git",                        "Git"),
    # CMS
    ("wordpress",           "wordpress",                  "WordPress"),
    ("drupal",              "drupal",                     "Drupal"),
    ("joomla",              "joomla!",                    "Joomla"),
    # Browsers
    ("mozilla",             "firefox",                    "Mozilla Firefox"),
    ("google",              "chrome",                     "Google Chrome"),
    ("microsoft",           "edge",                       "Microsoft Edge"),
    ("apple",               "safari",                     "Apple Safari"),
    ("microsoft",           "internet_explorer",          "Internet Explorer"),
    # OS
    ("linux",               "linux_kernel",               "Linux Kernel"),
    ("canonical",           "ubuntu_linux",               "Ubuntu Linux"),
    ("debian",              "debian_linux",               "Debian Linux"),
    ("redhat",              "enterprise_linux",           "Red Hat Enterprise Linux"),
    ("centos",              "centos",                     "CentOS"),
    ("microsoft",           "windows_10",                 "Microsoft Windows 10"),
    ("microsoft",           "windows_11",                 "Microsoft Windows 11"),
    ("microsoft",           "windows_server_2019",        "Microsoft Windows Server 2019"),
    ("microsoft",           "windows_server_2022",        "Microsoft Windows Server 2022"),
    ("apple",               "macos",                      "Apple macOS"),
    ("apple",               "mac_os_x",                   "Apple Mac OS X"),
    ("google",              "android",                    "Google Android"),
    ("apple",               "iphone_os",                  "Apple iOS"),
    # Microsoft Office suite
    ("microsoft",           "office",                     "Microsoft Office"),
    ("microsoft",           "word",                       "Microsoft Word"),
    ("microsoft",           "excel",                      "Microsoft Excel"),
    ("microsoft",           "outlook",                    "Microsoft Outlook"),
    ("microsoft",           "exchange_server",            "Microsoft Exchange Server"),
    ("microsoft",           "powershell",                 "Microsoft PowerShell"),
    ("microsoft",           "visual_studio_code",         "Visual Studio Code"),
    # Adobe
    ("adobe",               "acrobat_reader",             "Adobe Acrobat Reader"),
    ("adobe",               "acrobat",                    "Adobe Acrobat"),
    ("adobe",               "flash_player",               "Adobe Flash Player"),
    ("adobe",               "photoshop",                  "Adobe Photoshop"),
    # Virtualisation / containers
    ("vmware",              "workstation",                "VMware Workstation"),
    ("vmware",              "vcenter_server",             "VMware vCenter Server"),
    ("vmware",              "esxi",                       "VMware ESXi"),
    ("docker",              "docker",                     "Docker"),
    ("kubernetes",          "kubernetes",                 "Kubernetes"),
    # Network
    ("cisco",               "ios",                        "Cisco IOS"),
    ("cisco",               "ios_xe",                     "Cisco IOS XE"),
    ("cisco",               "adaptive_security_appliance_software", "Cisco ASA"),
    ("juniper",             "junos",                      "Juniper JunOS"),
    # Other popular tools
    ("elastic",             "kibana",                     "Kibana"),
    ("wireshark",           "wireshark",                  "Wireshark"),
    ("putty",               "putty",                      "PuTTY"),
    ("filezilla-project",   "filezilla",                  "FileZilla"),
    ("zoom",                "zoom",                       "Zoom"),
    ("slack",               "slack",                      "Slack"),
    ("notepad-plus-plus",   "notepad++",                  "Notepad++"),
]


def extract_from_cache(cache_dir: Path) -> list:
    """Extract unique (vendor, product) pairs from CVE cache CPE fields."""
    seen    = set()
    entries = []
    for f in sorted(cache_dir.glob("*.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
            for cpe_str in d.get("cpes", []):
                parts = cpe_str.split(":")
                if len(parts) < 5:
                    continue
                vendor  = parts[3]
                product = parts[4]
                key = f"{vendor}:{product}"
                if key in seen:
                    continue
                seen.add(key)
                display = (
                    f"{vendor} {product}"
                    .replace("_", " ")
                    .replace(".", " ")
                    .title()
                )
                entries.append({
                    "cpe_name": cpe_str,
                    "vendor":   vendor,
                    "product":  product,
                    "display":  display,
                })
        except Exception:
            pass
    return entries


def build_entries() -> list:
    """Merge curated + cache-extracted CPE entries (deduped by vendor:product)."""
    seen    = set()
    entries = []

    # 1. Curated list first (highest quality)
    for vendor, product, display in COMMON_CPES:
        key = f"{vendor}:{product}"
        if key in seen:
            continue
        seen.add(key)
        entries.append({
            "cpe_name": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
            "vendor":   vendor,
            "product":  product,
            "display":  display,
        })

    # 2. Cache-extracted CPEs
    cache_dir = ROOT / "data/cache/nvd"
    if cache_dir.exists():
        cache_entries = extract_from_cache(cache_dir)
        added = 0
        for e in cache_entries:
            key = f"{e['vendor']}:{e['product']}"
            if key not in seen:
                seen.add(key)
                entries.append(e)
                added += 1
        print(f"  Added {added} CPEs from cache")

    print(f"  Total unique entries: {len(entries)}")
    return entries


def main():
    print("=" * 60)
    print("BUILD SEMANTIC CPE INDEX")
    print("=" * 60)

    # Dependency check
    try:
        from sentence_transformers import SentenceTransformer
        import faiss
        import numpy as np
    except ImportError as e:
        print(f"\n[ERROR] Missing package: {e}")
        print("Install: pip install sentence-transformers faiss-cpu")
        sys.exit(1)

    # Build entry list
    print("\n[1/3] Building CPE entry list...")
    entries = build_entries()

    # Encode with sentence-transformers
    print(f"\n[2/3] Encoding {len(entries)} display names...")
    print("  Model: all-MiniLM-L6-v2  (~90 MB, downloads once)")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    texts = [e["display"] for e in entries]
    emb   = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)
    emb   = emb.astype("float32")

    # Build FAISS index (inner product = cosine similarity on normalised vecs)
    print(f"\n[3/3] Building FAISS index (dim={emb.shape[1]})...")
    dim   = emb.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(emb)
    print(f"  Vectors indexed: {index.ntotal}")

    # Save
    model_dir  = ROOT / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    index_path = model_dir / "cpe_index.faiss"
    meta_path  = model_dir / "cpe_meta.pkl"

    faiss.write_index(index, str(index_path))
    with open(meta_path, "wb") as f:
        pickle.dump({"entries": entries, "model_name": "all-MiniLM-L6-v2"}, f)

    print(f"\nSaved:")
    print(f"  {index_path}  ({index_path.stat().st_size // 1024} KB)")
    print(f"  {meta_path}")

    # Quick sanity check
    print("\nSanity check (top-3 for 'Apache HTTP Server 2.4'):")
    q   = model.encode(["Apache HTTP Server 2.4"], normalize_embeddings=True).astype("float32")
    D, I = index.search(q, 3)
    for score, idx in zip(D[0], I[0]):
        e = entries[idx]
        print(f"  {score:.3f}  {e['display']}  [{e['vendor']}:{e['product']}]")

    print("\nDone! The backend will auto-load the index on next startup.")


if __name__ == "__main__":
    main()
