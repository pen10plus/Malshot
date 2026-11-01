import os
import stat
import shutil
import sqlite3
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"


def require_file(path):
    if not path.is_file():
        raise FileNotFoundError(f"required release asset is missing: {path}")
    return path


def copy_required(source, destination):
    require_file(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_empty_local_state(path):
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE scan_cache (
                file_path TEXT PRIMARY KEY,
                mtime INTEGER,
                size_bytes INTEGER,
                file_hash TEXT,
                status TEXT,
                last_scanned INTEGER
            );
            CREATE TABLE quarantine_vault (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT,
                vault_path TEXT,
                detection_source TEXT,
                timestamp INTEGER
            );
            """
        )


def main():
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir()

    copy_required(ROOT / "malshot.exe", DIST / "malshot.exe")
    copy_required(ROOT / "signatures.db", DIST / "signatures.db")
    create_empty_local_state(DIST / "local_state.db")

    rules = ROOT / "rules"
    if not rules.is_dir():
        raise FileNotFoundError(f"required YARA rules directory is missing: {rules}")
    shutil.copytree(rules, DIST / "rules")

    copy_required(ROOT / "lstm_malware.onnx", DIST / "lstm_malware.onnx")
    copy_required(ROOT / "onnxruntime.dll", DIST / "onnxruntime.dll")
    copy_required(ROOT / "libcrypto-3-x64.dll", DIST / "libcrypto-3-x64.dll")
    vault = DIST / "quarantine_vault"
    vault.mkdir()
    if os.name == "nt":
        os.chmod(vault, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    assets = [
        DIST / "onnxruntime.dll",
        DIST / "libcrypto-3-x64.dll",
        DIST / "lstm_malware.onnx",
        DIST / "signatures.db",
    ]
    assets.extend(sorted((DIST / "rules").rglob("*.yar")))
    assets.extend(sorted((DIST / "rules").rglob("*.yara")))
    manifest = {
        "algorithm": "SHA-256",
        "assets": {
            str(path.relative_to(DIST)).replace("\\", "/"): sha256(path)
            for path in assets
        },
    }
    (DIST / "release_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"[OK] Release assembled at {DIST}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, sqlite3.Error) as error:
        raise SystemExit(f"[ERROR] {error}")
