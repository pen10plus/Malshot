# MalShot Defender

## Project Overview

MalShot is an offline-first Windows malware scanning application implemented
in Go with a Fyne desktop UI, SQLite state/signature databases, YARA
heuristic scanning, and ONNX Runtime inference.

The application is designed to scan files locally, minimize repeat work with
a content-validated cache, identify known threats through SHA-256 signatures,
perform optional deep inspection, and isolate detected files in an encrypted
quarantine vault.

## Current Project Status

**Current rating: Conditionally verified; not yet unconditionally production
ready.**

The core Go scanner, UI, cache hardening, SQLite concurrency behavior, YARA
integration, ONNX inference, and quarantine workflow have been implemented and
tested successfully.

The remaining production blockers are:

1. A formal native heap leak proof has not been completed because Dr. Memory,
   Windows Application Verifier, GFlags/UMDH, and Valgrind are not installed
   in the current environment.

The latest native lifecycle stress tests passed with zero race warnings and
zero CGO pointer-checking warnings.

## Technology Stack

| Area | Technology |
|---|---|
| Primary language | Go 1.22 |
| Desktop UI | Fyne v2.6.3 |
| Database | SQLite through `go-sqlite3` |
| Database mode | WAL with busy timeout |
| Known-threat detection | SHA-256 indexed SQLite lookup |
| Heuristic engine | YARA 4.3.2 runtime; Go binding v4.3.4 |
| ML inference | ONNX Runtime through `onnxruntime_go` |
| Native compilation | CGO with GCC/MSYS2 MinGW |
| Encryption | AES-256-GCM |
| Asset preparation | Python helper scripts |
| Supported target | Windows desktop |

## High-Level Workflow

### Phase 1: Discovery and Cache

The scanner recursively walks a selected directory with `filepath.WalkDir`.
Only regular files are submitted for analysis. Directory entries that cannot
be inspected are logged and skipped so one inaccessible file does not stop the
entire walk.

The scan cache is stored in `local_state.db`. A clean result is no longer
trusted only from path, size, and modification time. The current implementation
also hashes the candidate file and compares the actual SHA-256 digest with the
stored cache digest.

This prevents an attacker from replacing a file while preserving its path,
size, and modification timestamp to bypass the clean cache.

### Phase 2: SHA-256 Signature Detection

New or modified files are hashed using streaming I/O rather than loading the
whole file into memory. The lowercase SHA-256 digest is looked up with a
parameterized indexed query in `signatures.db`.

Known threat records contain:

- SHA-256 hash
- Threat name
- Severity
- Date added

### Phase 3: YARA Inspection

The deep-inspection build uses the Go YARA binding to compile `.yar` and
`.yara` rule files and scan files for matching rules.

YARA compiler and rule resources are explicitly destroyed after use. The
temporary marker rule used during verification successfully detected:

```text
MALSHOT_DEEP_INSPECTION_TEST
```

### Phase 4: ONNX LSTM Inference

The deep-inspection build initializes ONNX Runtime, creates a fixed-size
4,096-byte float input tensor, reads byte values from the target file, and
returns a confidence score from the model.

The verified E2E test successfully initialized ONNX Runtime and produced a
confidence score of approximately:

```text
0.0012
```

ONNX session state is protected by a mutex. Tensor destruction and session
cleanup are performed by `DestroyONNX`.

### Phase 5: Quarantine

Flagged files are moved into `quarantine_vault` after:

1. Execution permissions are revoked.
2. The source is opened and read in bounded chunks.
3. AES-256-GCM encryption is applied.
4. A fresh cryptographic nonce is generated for every encrypted chunk.
5. The encrypted temporary file is synchronized and atomically renamed.
6. An audit record is inserted into the local database.
7. The original file is removed.

The current implementation uses bounded 1 MiB chunks, avoiding the previous
whole-file `os.ReadFile` memory-exhaustion behavior.

### Current Quarantine Key Protection

The protected key file is:

```text
quarantine_vault\vault.key
```

It contains a DPAPI-protected blob. Windows `CryptProtectData` and
`CryptUnprotectData` are used with `CRYPTPROTECT_UI_FORBIDDEN`. The plaintext
32-byte key is returned only during active quarantine initialization and is
zeroed immediately after the AES cipher is initialized.

Legacy installations containing:

```text
quarantine_vault\.quarantine.key
```

are migrated to `vault.key` on first access and removed after successful
protection.

## Application Components

### Main Application

[main.go](C:/Users/AW/Desktop/files/main.go)

Responsibilities:

- Resolves the application and database paths.
- Opens the scanner engine.
- Starts the Fyne desktop application.
- Closes the scanner databases on shutdown.

### Scanner Engine

[engine.go](C:/Users/AW/Desktop/files/internal/scanner/engine.go)

Responsibilities:

- Enforces one active scan at a time.
- Resets scan statistics before each scan.
- Creates worker and walker goroutines.
- Coordinates cancellation.
- Waits for active work before database shutdown.
- Emits file analysis events to the UI.

### File Walker

[walker.go](C:/Users/AW/Desktop/files/internal/scanner/walker.go)

Responsibilities:

- Recursive directory traversal.
- Regular-file filtering.
- Cache checks.
- Discovery and skipped-file counters.
- Context cancellation handling.

### Worker Pipeline

[worker.go](C:/Users/AW/Desktop/files/internal/scanner/worker.go)

Responsibilities:

- Streaming file hashing.
- Signature database lookup.
- Post-hash metadata verification.
- Clean-cache updates.
- Threat and analysis event reporting.

### Database Layer

[db.go](C:/Users/AW/Desktop/files/internal/scanner/db.go)

Responsibilities:

- Opens local and signature databases.
- Enables SQLite WAL mode.
- Configures busy timeouts.
- Limits connection pools to reduce writer contention.
- Executes parameterized queries.
- Manages scan cache and quarantine audit records.

### Native Analyzer

[analyzer.go](C:/Users/AW/Desktop/files/internal/scanner/analyzer.go)

Build tag:

```text
deepinspection
```

Responsibilities:

- YARA compiler initialization.
- YARA rule collection and compilation.
- YARA file scanning.
- ONNX Runtime environment initialization.
- Tensor/session lifecycle management.
- LSTM byte-sequence inference.

### Quarantine

[quarantine.go](C:/Users/AW/Desktop/files/internal/scanner/quarantine.go)

Responsibilities:

- Source permission restriction.
- Vault creation.
- Per-installation key generation.
- Chunked AES-256-GCM encryption.
- Atomic encrypted payload publication.
- Audit database insertion.
- Original file removal.

### Statistics

[stats.go](C:/Users/AW/Desktop/files/internal/scanner/stats.go)

Counters use Go atomic types for:

- Total discovered files
- Skipped files
- Analyzed files
- Threats
- Processed bytes

Statistics are reset for each scan lifecycle.

### Fyne User Interface

[dashboard.go](C:/Users/AW/Desktop/files/internal/ui/dashboard.go)

Current UI areas:

- Dashboard
- Scanner placeholder view
- Quarantine Vault
- Settings and threat-intelligence placeholder

Dashboard capabilities:

- Quick scan selection
- Deep inspection selection
- Scan progress
- Total scanned display
- Threat display
- Zero-day display placeholder
- Quarantine count display placeholder
- Activity log
- Status ring

UI safety features:

- Background scan event consumption.
- `fyne.Do` for UI-thread updates.
- Scan buttons disabled while a scan is active.
- Generation tokens suppress stale events from an earlier scan.
- Asynchronous quarantine database loading.

## Databases

### local_state.db

Contains:

```text
scan_cache
quarantine_vault
```

`scan_cache` stores:

- File path
- Modification time
- File size
- SHA-256 hash
- Status
- Last scanned time

`quarantine_vault` stores:

- Incident ID
- Original path
- Vault path
- Detection source
- Timestamp

### signatures.db

Contains the indexed `known_threats` table:

- `sha256_hash`
- `threat_name`
- `severity`
- `date_added`

All application queries use SQL parameters for paths, hashes, detection
sources, and metadata.

## Security Capabilities

Implemented security controls:

- Parameterized SQLite queries.
- SHA-256 content validation for clean-cache decisions.
- Streaming file hashing.
- Bounded quarantine encryption.
- Fresh `crypto/rand` nonce per encrypted chunk.
- Vault-root containment validation.
- Atomic encrypted payload publication.
- Restrictive vault and key-file permissions.
- SQLite busy timeout.
- Bounded SQLite connection pools.
- Single active scan enforcement.
- Context cancellation.
- Native session cleanup paths.
- UI stale-event suppression.
- Race detector coverage.

Not yet implemented:

- Authenticated quarantine restore/decryption.
- Key rotation and key version metadata.
- Signed YARA rule verification.
- Digitally signed release executable.
- Formal native heap leak certification.

## Test and Verification Results

### Standard Go Tests

```text
go test ./...
```

Result: PASS.

### Race Tests

```text
go test -race ./internal/scanner ./internal/ui
```

Result: PASS with no race warnings.

### Static Verification

```text
go vet ./...
```

Result: PASS.

### Python Helper Verification

```text
python -m py_compile db_manager.py package_release.py test_malshot.py
```

Result: PASS.

### Native Deep-Inspection Tests

Environment:

- `CGO_ENABLED=1`
- GCC from MSYS2 UCRT64
- pkg-config
- YARA 4.3.2
- OpenSSL linker flags `-lssl -lcrypto`

Command:

```text
go test -count=1 -v -race -tags deepinspection ./...
```

Result: PASS.

Verified:

- Temporary YARA marker rule.
- YARA threat match.
- ONNX initialization.
- ONNX inference.
- Cache validation.
- SHA-256 signature lookup.
- Quarantine encryption.
- Quarantine removal.
- Concurrent SQLite writes.
- UI package tests.
- Zero race detector warnings.

### Native Lifecycle Stress

Repeated YARA, ONNX, and quarantine lifecycle tests passed with:

```text
GODEBUG=cgocheck=1
-race
```

Observed:

- CGO pointer-checking warnings: 0
- Race warnings: 0
- Native initialization failures: 0
- Native cleanup test failures: 0

This is strong lifecycle evidence, but not a formal native heap leak proof.

### Formal Native Leak Verification

Not completed because the following tools are unavailable:

- Dr. Memory
- Windows Application Verifier
- GFlags/UMDH
- Valgrind

A formal native leak verification run should use Windows Application Verifier
or Dr. Memory against a dedicated smoke executable.

## Mandatory Test Case Status

| Test case | Status | Current capability |
|---|---|---|
| TC-SEC-01 Path traversal | PASS | Cleaned source paths and vault-root containment |
| TC-SEC-02 AES nonce collision | PASS at implementation level | Fresh random nonce for each encrypted chunk |
| TC-PERF-01 Large file memory use | PASS by design | Streaming hash and bounded 1 MiB quarantine chunks |
| TC-CONC-01 SQLite lock under load | PASS | Eight-worker concurrent write regression test |
| TC-UI-01 Rapid restart | PASS | Single-scan guard, cancellation, generation filtering |
| TC-ERR-01 Missing assets | PASS for initialization errors | Explicit YARA/ONNX initialization errors |

Remaining test limitations:

- No real multi-gigabyte test has been completed.
- No long-duration SQLite contention test has been completed.
- No formal native leak verifier report exists.
- DPAPI integration tests cover protect/unprotect round-tripping, missing-key
  generation, and legacy-key migration.

## Release Package

Expected release contents:

```text
dist\malshot.exe
dist\signatures.db
dist\local_state.db
dist\rules\
dist\lstm_malware.onnx
dist\onnxruntime.dll
dist\libcrypto-3-x64.dll
dist\quarantine_vault\
```

The release asset smoke test confirmed that these assets are present.

The current executable is not Authenticode-signed.

## Build and Run

### Standard Build

The project provides [build.bat](C:/Users/AW/Desktop/files/build.bat).

The build requires:

- Go
- GCC/MinGW
- CGO enabled
- YARA development libraries
- ONNX Runtime development libraries
- OpenSSL libraries where required by YARA

### Deep-Inspection Build

The deep-inspection implementation is compiled with:

```text
-tags deepinspection
```

Required runtime assets:

- YARA rules directory
- ONNX model
- ONNX Runtime DLL
- OpenSSL runtime DLL where required

### Launch

The application accepts an optional scan target:

```text
malshot.exe
malshot.exe C:\Path\To\Scan
```

When no argument is supplied, the default target is the current directory.

## Operational Limitations

1. Deep inspection is build-tagged and requires native runtime assets.
2. The release executable is not digitally signed.
3. The normal dashboard does not yet expose a complete error summary for
   inaccessible files and partial directory-walk failures.
4. Some dashboard values, including zero-day and quarantine counters, require
   additional production event wiring.
5. The formal native memory leak proof remains outstanding.
6. There is no complete automated Python test suite.
7. The release smoke test validates asset presence but does not replace a
   signed installer or deployment validation.

## Recommended Next Steps

### Priority 1: Formal Native Leak Testing

Install Windows Application Verifier or Dr. Memory and test repeated:

- `InitYara`
- `ScanWithYara`
- YARA cleanup
- `InitONNX`
- `ScanWithLSTM`
- `DestroyONNX`
- Repeated quarantine operations

Capture the verifier report and retain it as a release artifact.

### Priority 2: Release Security

- Authenticode-sign `malshot.exe`.
- Sign or integrity-protect model and rule assets.
- Add a CI job that builds with CGO and the `deepinspection` tag.
- Add a native DLL dependency smoke test.
- Validate missing and corrupted assets through the UI.

### Priority 3: Functional Completeness

- Wire deep YARA and ONNX phases directly into the production engine modes.
- Add user-visible scan failure and partial-scan summaries.
- Add real large-file performance testing.
- Add long-duration SQLite contention testing.
- Add quarantine restore/decryption with key versioning.

## Final Assessment

MalShot currently provides a functioning local malware-scanning foundation with:

- Recursive discovery
- Content-aware clean caching
- SHA-256 signature detection
- YARA rule scanning
- ONNX model inference
- Chunked AES-256-GCM quarantine
- SQLite audit logging
- Concurrent worker processing
- Fyne desktop visualization
- Cancellation and shutdown coordination

The project is suitable for continued development, integration testing, and
controlled internal evaluation. It should not yet be treated as a fully
production-ready malware defense product until DPAPI key protection, formal
native leak verification, code signing, and the remaining release-level tests
are completed.
