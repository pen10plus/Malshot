import hashlib
import os
import sqlite3


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(BASE_DIR, "test_scan_target")
TEST_FILE = os.path.join(TARGET_DIR, "eicar_dummy.txt")
SIGNATURES_DB = os.path.join(BASE_DIR, "signatures.db")
TEST_CONTENT = b"MALSHOT OFFLINE TEST SIGNATURE STRING."


def main():
    os.makedirs(TARGET_DIR, exist_ok=True)

    with open(TEST_FILE, "wb") as test_file:
        test_file.write(TEST_CONTENT)

    digest = hashlib.sha256()
    with open(TEST_FILE, "rb") as test_file:
        for chunk in iter(lambda: test_file.read(1024 * 1024), b""):
            digest.update(chunk)
    file_hash = digest.hexdigest()

    with sqlite3.connect(SIGNATURES_DB) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO known_threats
                (sha256_hash, threat_name, severity, date_added)
            VALUES (?, ?, ?, strftime('%s', 'now'))
            """,
            (file_hash, "Test.MalShot.Dummy", 10),
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    # Synchronize release_manifest.json with updated signatures.db hash
    db_hasher = hashlib.sha256()
    with open(SIGNATURES_DB, "rb") as f:
        while chunk := f.read(1024 * 1024):
            db_hasher.update(chunk)
    db_digest = db_hasher.hexdigest()

    import json
    for manifest_path in [os.path.join(BASE_DIR, "release_manifest.json"), os.path.join(BASE_DIR, "dist", "release_manifest.json")]:
        if os.path.isfile(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "assets" in data and "signatures.db" in data["assets"]:
                data["assets"]["signatures.db"] = db_digest
            if "files" in data and "signatures.db" in data["files"]:
                data["files"]["signatures.db"] = db_digest
            if "signatures.db" in data:
                data["signatures.db"] = db_digest
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

    print("Dummy file created:", TEST_FILE)
    print("SHA-256:", file_hash)
    print()
    print("Signature injected successfully as Test.MalShot.Dummy.")
    print("Run MalShot against this directory to observe the detection alert:")
    print("  malshot.exe", os.path.join(".", "test_scan_target"))


if __name__ == "__main__":
    main()
