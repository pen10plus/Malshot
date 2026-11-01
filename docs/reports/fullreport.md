# MALSHOT DEFENDER: COMPREHENSIVE PROJECT STATE REPORT (FULLREPORT)

**Document Version:** 1.0.0  
**Generated On:** October 20, 2026  
**Repository Root:** `c:\Users\AW\Desktop\files`  
**Target Platform:** Windows 10/11 x64 (Native Go 1.22 + CGO/MSYS2 UCRT64 + Fyne GUI)  
**Binary Output:** `malshot.exe` (27.4 MB, built with `-tags deepinspection`)

---

## 1. Executive Summary

MalShot is an offline-first Windows desktop antimalware scanner designed to provide high-throughput local file inspection, known-signature matching, native YARA heuristics, machine learning zero-day detection (ONNX/LSTM), and an encrypted quarantine vault backed by Windows DPAPI.

The system is currently in an **advanced, fully integrated evaluation prototype state**:
- Core file discovery, streaming SHA-256 calculation, and database caching are **100% operational**.
- Windows DPAPI cryptographic key management and AES-256-GCM chunked quarantine are **100% operational**, including authenticated restoration.
- The Fyne desktop user interface is **functional across Dashboard, Scanner, and Vault views**, with thread-safe UI updates and generational scan token isolation.
- Native deep inspection (YARA 4.3.2 + ONNX Runtime 1.31) is **fully compiled into `malshot.exe`** and passes all E2E integration tests.

However, several **critical gaps and limitations** remain before production readiness:
1. **LSTM Model Limitation:** The shipped `lstm_malware.onnx` file is a **147-byte mock graph** (`ReduceMean` node), not a real trained neural network. Furthermore, there is an input tensor dimension mismatch between the Python training script (`[batch, 4096, 1]`) and the Go inference engine (`[1, 4096]`).
2. **Database Data:** The signature database (`signatures.db`) currently contains **only 1 dummy test signature** (`Test.MalShot.Dummy`). The 248,000+ records in the root database are local scan cache entries, not virus signatures.
3. **UI Incomplete Component:** The **"Settings & Intel"** tab in the desktop application is an un-implemented placeholder.
4. **Code Signing & Hardening:** Binaries (`malshot.exe`, `onnxruntime.dll`, `libcrypto-3-x64.dll`) lack Windows Authenticode signatures, and the quarantine vault defaults to a relative path rather than an ACL-restricted `%ProgramData%` root.

---

## 2. Component Health Matrix

| Subsystem / Feature | Current State | Confidence | Key Evidence & Notes |
|---|---|---|---|
| **Core File Walker** | Working | High | Recursive `filepath.WalkDir`, symlink filtering, permission error handling. |
| **Streaming SHA-256 Hashing** | Working | High | Bounded 1 MiB chunk streaming via `io.Copy`; zero RAM blowup on large files. |
| **Clean File Scan Cache** | Working | High | Re-verifies file SHA-256 alongside mtime/size to prevent cache collision tampering. |
| **SQLite Concurrency & Pools** | Working | High | WAL mode enabled, 30s busy timeout, single connection per DB prevents locking. |
| **Windows DPAPI Integration** | Working | High | `CryptProtectData` / `CryptUnprotectData` with `CRYPTPROTECT_UI_FORBIDDEN` & `LocalFree`. |
| **Quarantine Encryption** | Working | High | AES-256-GCM chunked encryption (1 MiB chunks) with unique `crypto/rand` nonces. |
| **Quarantine Restoration** | Working | High | `RestoreFile` authenticates `MSQ2` chunks, decrypts, and updates audit table. |
| **Release Manifest Verification** | Working | High | `verifyReleaseManifest` validates SHA-256 of all native assets on engine boot. |
| **Fyne UI - Dashboard View** | Working | High | Circular progress ring, quick scan, pause/resume/stop, stats cards, live log. |
| **Fyne UI - Dedicated Scanner View** | Working | High | Dedicated scan view with folder picker, mode selector, and real-time threat list. |
| **Fyne UI - Quarantine Vault View** | Working | High | Incident list, refresh button, and "Restore Selected File" button. |
| **Fyne UI - Settings & Intel** | **NOT Working** | Low | Hardcoded placeholder: `"Settings & threat intel coming soon"`. |
| **Deep Inspection CGO Engine** | Working | High | Compiled with YARA 4.3.2 and ONNX Runtime; passes native smoke and E2E tests. |
| **LSTM Zero-Day Detection** | **Partial / Mock** | Medium | Inference engine works, but model is a 147-byte mock; tensor shape mismatch exists. |
| **Signature Database Data** | **Partial / Stub** | Low | Database engine works, but contains only 1 test signature (`Test.MalShot.Dummy`). |
| **Local Cache Database Data** | Working | High | Root `local_state.db` contains 248,085 cached file entries (91.4 MB). |
| **Authenticode Code Signing** | **NOT Working** | None | Executables and DLLs are unsigned. |

---

## 3. User Interface (UI) Detailed Evaluation

The GUI is developed in Go using **Fyne v2.6.3** with a customized modern dark cybersecurity aesthetic (`colBackground = #0B0F19`, `colPanel = #111827`, accent cyan `#00F0FF`, danger red `#EF4444`).

### 3.1 Working UI Elements
1. **Custom Header & Status Bar (`shell.go`):**
   - Application logo and title with a green "SECURE" badge.
   - Real-time bottom status bar showing active CPU worker count (`ActiveCores/TotalCores`), engine status, signature readiness, and deep inspection diagnostic errors.
2. **Dashboard View (`dashboard.go`):**
   - **Target Directory Selection:** Shows current absolute directory path; includes a functional "📂 Browse Folder" native directory picker dialog.
   - **Circular Progress Ring (`circular_progress.go`):** Custom canvas widget rendering an animated radial progress ring with percentage readout.
   - **Player Controls:**
     - `▶ Quick Scan` button initiates scanning.
     - `⏸ Pause` / `Resume` toggle utilizing `sync.Cond` to freeze walker and worker goroutines without killing state.
     - `⏹ Stop` button cancels context safely.
   - **Mode Toggle:** Checkbox to toggle "Deep Inspection Mode (YARA + ONNX)" dynamically.
   - **4 Live Metric Cards:**
     - `Total Scanned`: Real-time incrementing file count and total data volume (MB/GB).
     - `Items in Quarantine`: Total count of files successfully encrypted and moved to the vault.
     - `Threats Detected`: Cumulative counter of signature, heuristic, and ML detections.
     - `Zero-Day Blocked`: Distinct counter for ML confidence detections (`score >= 0.80`).
   - **Real-Time Threat List (`detected_list.go`):**
     - Displays path, threat classification, detection source, and a direct `Quarantine` action button per detected item.
   - **Live Log Feed (`widgets.go`):** Monospace scrolling console showing scanner events (`[CLEAN]`, `[ALERT]`, `[SKIP]`).
3. **Dedicated Scanner View (`scanner_view.go`):**
   - Standalone scanning console with larger circular progress indicator.
   - Current file scanning label (truncated monospace path display).
   - Radio selector for `Quick Scan` vs `Deep Inspection (YARA + ONNX)`.
   - Real-time detected file list with one-click quarantine buttons.
4. **Quarantine Vault View (`vault.go`):**
   - Tabular list rendering all incidents recorded in `local_state.db:quarantine_vault`.
   - Displays: Original Path, Detection Source, and Timestamp (RFC3339).
   - "Refresh" button to reload incidents asynchronously.
   - **"Restore Selected File" Button:** Triggers background AES-GCM decryption, verifies data integrity, writes back original file, removes vault payload, and deletes the DB record.
5. **Thread Safety & Race Prevention:**
   - All UI updates from worker channels are marshaled to the main GUI thread via `fyne.Do()`.
   - Generational scan tokens (`generation uint64`) ensure that events from an aborted or previous scan cannot pollute a newly started scan.

### 3.2 Non-Working / Incomplete UI Elements
1. **"Settings & Intel" View:**
   - In `internal/ui/shell.go:54`, the tab is wired to `placeholder("Settings & threat intel coming soon")`.
   - None of the planned configuration options (changing confidence threshold, tuning worker count, scheduling automatic scans, inspecting YARA rule paths) are implemented in the UI.

---

## 4. LSTM & Machine Learning Capability (Deep Dive)

The project includes an end-to-end concept for detecting novel zero-day malware by inspecting the first 4,096 bytes of binary files using an LSTM neural network exported to ONNX Runtime.

### 4.1 What Is Working
- **Native ONNX Runtime Bindings:** The project integrates `github.com/yalue/onnxruntime_go` (v1.16.0) communicating with `onnxruntime.dll` (v1.31.0, 17.2 MB).
- **Session Lifecycle Management (`analyzer.go`):**
  - Thread-safe initialization (`InitONNX`) with singleton environment setup (`ort.InitializeEnvironment()`).
  - Thread-safe per-session execution mutex (`state.mu.Lock()`).
  - Clean destruction (`DestroyONNX`) destroying input/output tensors and releasing unmanaged C++ sessions without orphaned memory handles.
- **Engine Worker Pipeline Integration (`worker.go`):**
  - When Deep Inspection is enabled, `scanFile()` executes `deep.scan(path)`.
  - If the LSTM score meets or exceeds `confidenceThreshold` (default `0.80`), the file is flagged as `ML.ZeroDay.LSTM` (or `Deep.Threat.Hybrid` if matched alongside YARA).
  - The E2E pipeline test (`TestDeepInspectionPipeline`) successfully loads the ONNX runtime, executes inference, and obtains a numeric confidence score.

### 4.2 What Is NOT Working / Critical Limitations
1. **Mock Model File (`lstm_malware.onnx`):**
   - The file `lstm_malware.onnx` in root and `dist/` is only **147 bytes**.
   - Binary inspection of the protobuf graph reveals:
     ```text
     graph: malshot-e2e
     node: ReduceMean(axes=[0, 1, 2], keepdims=1)
     ```
   - **It is NOT a trained LSTM.** It is a synthetic single-node graph created solely to test that ONNX Runtime loads without crashing in automated CI runs.
   - It computes the average value of the first 4,096 input bytes. Because of this, it cannot detect real malware patterns or classify zero-day exploits.
2. **Tensor Shape Incompatibility Contract:**
   - In `internal/scanner/analyzer.go:131`:
     ```go
     input, err := ort.NewTensor(ort.NewShape(1, lstmSequenceLength), make([]float32, lstmSequenceLength))
     // Creates a 2D tensor of shape [1, 4096]
     ```
   - In `train_lstm.py:119-126`:
     ```python
     example = torch.zeros(1, SEQUENCE_LENGTH, 1, device=device)
     torch.onnx.export(
         model, example, output,
         input_names=["input"], output_names=["output"],
         dynamic_axes={"input": {0: "batch"}, "output": {0: "batch"}},
         opset_version=17,
     )
     # Exports a 3D tensor of shape [batch, 4096, 1]
     ```
   - **Contract Breach:** If an engineer trains a real model using `train_lstm.py` and places it in MalShot, the Go engine will fail with a runtime shape mismatch error because `analyzer.go` passes a 2-dimensional tensor `[1, 4096]` to a model expecting a 3-dimensional tensor `[batch, 4096, 1]`.

---

## 5. Database Data & Persistence Evaluation

MalShot utilizes two distinct SQLite 3 database files configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and a 30,000 ms busy timeout (`PRAGMA busy_timeout=30000`).

### 5.1 Signatures Database (`signatures.db`)
- **Location:** `c:\Users\AW\Desktop\files\signatures.db` (and `dist\signatures.db`)
- **Schema:**
  ```sql
  CREATE TABLE known_threats (
      sha256_hash TEXT PRIMARY KEY,
      threat_name TEXT,
      severity INTEGER,
      date_added INTEGER
  );
  CREATE INDEX idx_known_threats_sha256_hash ON known_threats (sha256_hash);
  ```
- **Current Data Status:** **ONLY 1 RECORD PRESENT!**
  - Record: `('Test.MalShot.Dummy', sha256='d440c94f1c1f75b28da1737e93f77df230b490f23d463b2a3a5f4f8149eb4037', severity=10)`
  - Source: Injected by `test_malshot.py` to verify detection against `test_scan_target/eicar_dummy.txt`.
- **Limitation:** The script `db_manager.py` contains a complete importer for the MalwareBazaar live threat feed (`https://bazaar.abuse.ch/export/csv/recent/`), but this has not been run into the shipped database. In an offline environment, MalShot will not detect any real-world malware hashes unless this database is populated.

### 5.2 Local State Database (`local_state.db`)
- **Location:** `c:\Users\AW\Desktop\files\local_state.db` (Size: **91.4 MB**)
- **Schema:**
  ```sql
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
  ```
- **Current Data Status:**
  - `scan_cache`: **248,085 rows** (pre-cached clean file hashes from prior system scan benchmarks).
  - `quarantine_vault`: **0 rows** (all test quarantines were either cleared or restored).
- **Distribution Database (`dist/local_state.db`):**
  - Size: 20 KB.
  - `scan_cache`: **0 rows** (correctly initialized empty for clean end-user deployment).
  - `quarantine_vault`: **0 rows**.

---

## 6. Security & Cryptographic Subsystems

### 6.1 Windows DPAPI Key Management (`dpapi_windows.go`)
- **Master Key Generation:** A 32-byte cryptographically secure random AES key is generated via Go's `crypto/rand`.
- **Protection:** Encrypted using Windows Data Protection API (`CryptProtectData`) with `CRYPTPROTECT_UI_FORBIDDEN`.
- **Storage:** Saved to `quarantine_vault/vault.key`.
- **Memory Hygiene:** After creating the AES cipher block in RAM, the raw plaintext byte array is immediately cleared using `zeroBytes()`.
- **Migration:** Automatically migrates and securely shreds legacy unencrypted `.quarantine.key` files.

### 6.2 Quarantine Encryption & Containment (`quarantine.go`)
- **Cipher:** AES-256-GCM authenticated encryption.
- **Chunked Processing:** Processes target files in bounded 1 MiB streams, eliminating out-of-memory vulnerabilities when quarantining multi-gigabyte files.
- **Nonce Freshness:** Generates a new 12-byte random nonce for every individual 1 MiB chunk to eliminate AES-GCM nonce reuse risks.
- **Payload Structure:** Prefixed with 4-byte magic bytes `MSQ2` followed by chunk length prefixes, nonces, and GCM authentication tags.
- **Path Traversal Protection:** Target paths are sanitized with `filepath.Clean()`. Destination vault filenames are generated with timestamp-nonce hashes. The code verifies that destination paths remain strictly inside the vault root.

### 6.3 Authenticated Restoration (`RestoreFile`)
- Full round-trip decryption is implemented and tested.
- Validates the `MSQ2` file header and verifies all GCM authentication tags chunk-by-chunk.
- Writes to a temporary `.restore-*.tmp` file, calls `Sync()`, and atomically renames to the destination path before removing the vault file and deleting the database audit record.

---

## 7. Deep Inspection & Native CGO Integration

MalShot supports dual-compilation modes via Go build tags:

1. **Standard Build (`//go:build !deepinspection`):**
   - Compiles `deep_backend_stub.go`.
   - The scanner operates solely on SHA-256 signature lookups and the local cache. If the user enables Deep Inspection, the engine returns a clean warning without crashing.
2. **Deep Inspection Build (`//go:build deepinspection`):**
   - Compiles `deep_backend_native.go` and `analyzer.go`.
   - Links against `yara-4.3.2` and `onnxruntime.dll`.
   - Requires CGO, GCC, and `pkg-config` (available via MSYS2 UCRT64).
   - Links OpenSSL (`-lssl -lcrypto`) for YARA crypto modules.
   - **Current Executable Verification:** Inspection of `malshot.exe` (27.4 MB) confirms it was compiled with `-tags deepinspection`.

---

## 8. Verified Test Results & Health Checks

During this evaluation, the test suite was executed against the active repository using PowerShell and MSYS2:

| Test / Command | Scope | Result | Observed Output |
|---|---|---|---|
| `go test ./...` | Unit tests across all packages | **PASS** | `malshot: 3.0s`, `internal/scanner: 7.1s`, `internal/ui: 9.7s` |
| `go test -race ./internal/...` | Concurrency & race detector | **PASS** | 0 data races detected |
| `go vet ./...` | Static analysis & Go linter | **PASS** | 0 warnings or compiler issues |
| `TestYaraMarkerSmoke` | Native CGO YARA compiler & matcher | **PASS** | `[YARA] Threat detected in sample.bin (1.32s)` |
| `TestDeepInspectionPipeline` | Full E2E Cache -> Hash -> YARA -> ONNX -> Vault | **PASS** | YARA matched, LSTM scored (0.0012), Quarantined (1.93s) |
| Manifest Integrity Verification | SHA-256 validation of all release assets | **PASS** | All 6 core dependencies match release manifest |
| Python Compilation Check | Syntax validation of automation scripts | **PASS** | `db_manager.py`, `package_release.py`, `test_malshot.py` compiled clean |

---

## 9. Comprehensive Elements Working vs. Not Working

### Elements That Are WORKING:
- [x] **File Walker & Enumeration:** Recursive scanning, directory filtering, skipping unreadable paths without crashing.
- [x] **Streaming SHA-256 Hashing:** Low-memory chunked hashing across small and multi-gigabyte files.
- [x] **Anti-Tamper Scan Cache:** Prevents file modification bypass by verifying hash alongside mtime/size.
- [x] **Concurrent Worker Pool:** Scalable worker goroutines matching CPU core count, job channels, pause/resume/stop lifecycle.
- [x] **SQLite Database Layer:** WAL mode, 30s busy timeout, bounded connection pooling preventing database locks.
- [x] **Quarantine Cryptography:** AES-256-GCM chunked encryption, fresh per-chunk nonces, atomic temporary file publication.
- [x] **Windows DPAPI Integration:** Hardware/OS-backed master key encryption, automatic memory zeroing of plaintext keys.
- [x] **Quarantine Restoration:** Authenticated decryption of `.malshot` payloads back to original paths with DB cleanup.
- [x] **Release Manifest Security:** SHA-256 integrity verification of native DLLs, YARA rules, and ONNX models on boot.
- [x] **Desktop Dashboard UI:** Real-time circular progress bar, live stat cards, player controls, log view, folder picker.
- [x] **Desktop Dedicated Scanner View:** Scan mode selection (Quick vs Deep), active scan path indicator, threat listing.
- [x] **Desktop Quarantine Vault View:** Listing of quarantined files with metadata and working one-click restore.
- [x] **Native YARA Engine:** Compiling `.yar`/`.yara` rules from disk and evaluating files at native CGO speeds.
- [x] **Native ONNX Runtime Engine:** Native C++ session execution via `onnxruntime.dll` with clean tensor allocation/destruction.
- [x] **Release Packaging:** Python automation (`package_release.py`) creating standalone `dist/` directory with all assets.

### Elements That Are NOT WORKING / Gaps:
- [ ] **Real LSTM Model Weights:** Shipped `lstm_malware.onnx` is only a 147-byte mock (`ReduceMean` operation); does not perform real AI detection.
- [ ] **ML Tensor Shape Alignment:** Exporter (`train_lstm.py`) produces 3D tensor `[batch, 4096, 1]`, while Go engine (`analyzer.go`) expects 2D tensor `[1, 4096]`.
- [ ] **Populated Signature Feed:** `signatures.db` contains only 1 dummy test record; live MalwareBazaar signatures have not been populated.
- [ ] **Settings & Threat Intel UI:** The fourth navigation view in the desktop app is a hardcoded placeholder message.
- [ ] **Quarantine Directory Isolation:** Vault defaults to working directory `quarantine_vault` rather than `%ProgramData%\MalShot\Vault` with explicit Windows DACLs.
- [ ] **Authenticode Binary Signing:** Windows executables and DLLs are unsigned; Windows Defender SmartScreen will alert on execution.
- [ ] **In-App Threat Intel Updates:** No GUI button or automated background service to fetch signature or rule updates.
- [ ] **Formal Native Memory Leak Certification:** Native YARA and ONNX libraries lack formal validation under Windows Application Verifier or Dr. Memory.

---

## 10. Recommended Remediation & Action Plan

To transition MalShot from an advanced prototype to a production-grade security deployment, the following steps are recommended:

1. **Fix the ML Contract & Train a Real Model:**
   - Update `analyzer.go:131` to initialize shape `ort.NewShape(1, lstmSequenceLength, 1)` or adjust `train_lstm.py` to squeeze the channel dimension to `[batch, 4096]`.
   - Run `train_lstm.py` against a real dataset of clean binaries and malware samples to produce legitimate model weights (~500 KB to 2 MB).
2. **Seed the Threat Signature Database:**
   - Run `python db_manager.py` in an environment with internet access to import the recent ~200,000+ MalwareBazaar threat hashes into `dist/signatures.db`.
3. **Implement the Settings & Intel UI View:**
   - Replace the placeholder in `internal/ui/shell.go` with controls for:
     - Setting custom zero-day confidence thresholds (slider from 50% to 95%).
     - Changing scan thread concurrency.
     - One-click trigger for updating threat signatures from MalwareBazaar.
4. **Harden the Quarantine Vault Path:**
   - Modify `quarantineRoot()` in `internal/scanner/quarantine.go` to resolve to `%ProgramData%\MalShot\Vault` on Windows, and apply explicit Windows security descriptors (DACL allowing only `SYSTEM` and `Administrators`).
5. **Code Signing:**
   - Integrate an Authenticode code-signing step into `package_release.py` using a valid code-signing certificate for `malshot.exe` and `*.dll`.
