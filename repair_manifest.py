import json
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parent
manifest_path = root / "release_manifest.json"

# 1. Ensure rules directory and a default YARA rule exist
rules_dir = root / "rules"
rules_dir.mkdir(exist_ok=True)
default_rule = rules_dir / "default.yar"
if not default_rule.exists():
    default_rule.write_text(
        'rule Default_Heuristic {\n    strings:\n        $s1 = "MALSHOT_TEST"\n    condition:\n        $s1\n}\n',
        encoding="utf-8"
    )
    print("[+] Created missing YARA rule: rules/default.yar")

import sqlite3

sig_db = root / "signatures.db"
if sig_db.exists():
    try:
        with sqlite3.connect(sig_db) as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except Exception:
        pass

# 2. List of core files to hash (immutable engine assets)
files_to_hash = [
    "signatures.db",
    "onnxruntime.dll",
    "libcrypto-3-x64.dll",
    "lstm_malware.onnx",
]

# Add all YARA rule files
for rule_file in rules_dir.rglob("*.yar*"):
    files_to_hash.append(str(rule_file.relative_to(root)))

# 3. Calculate SHA-256 hashes
file_map = {}
for rel_path in files_to_hash:
    full_path = root / rel_path
    if full_path.exists() and full_path.is_file():
        hasher = hashlib.sha256()
        with open(full_path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                hasher.update(chunk)
        normalized_key = rel_path.replace("\\", "/")
        file_map[normalized_key] = hasher.hexdigest()
        print(f"  - Hashed {normalized_key}")
    else:
        print(f"  ! Warning: Asset not found on disk: {rel_path}")

# 4. Build multi-compatible JSON manifest
# Satisfies struct { Algorithm string; Assets map[string]string } in main.go
manifest_data = {
    "algorithm": "SHA-256",
    "assets": file_map,
    "files": file_map,
    "hashes": file_map,
    **file_map
}

with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest_data, f, indent=4)

print(f"\n[+] Successfully generated repaired manifest at: {manifest_path}")