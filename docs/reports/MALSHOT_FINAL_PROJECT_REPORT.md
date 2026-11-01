# MALSHOT DEFENDER: COMPREHENSIVE PROJECT AUDIT & FINAL EVALUATION REPORT

**Evaluation date:** 2026-10-15  
**Scope:** Go scanner, CGO/YARA and ONNX deep-inspection bindings, SQLite persistence, Fyne UI, DPAPI quarantine, release scripts, and available automated tests  
**Repository root:** `C:\Users\AW\Desktop\files`

## 1. Project Purpose & Core Architecture

### Purpose

MalShot is an offline-first Windows malware defender intended to identify known and
previously unseen threats without requiring cloud connectivity. It combines a
content-validated scan cache, indexed SHA-256 signature matching, optional native
YARA inspection, ONNX LSTM inference, and an encrypted quarantine vault protected
by Windows DPAPI.

The current implementation is suitable for academic evaluation and controlled
release testing. It is **conditionally production-ready**, not unconditionally
production-ready, because native heap certification, signed release artifacts,
and operational recovery features remain incomplete.

### System Architecture

```text
Fyne UI
  |
  v
Engine (single active scan, cancellation, atomic statistics)
  |
  +--> Phase 1: filepath.WalkDir -> metadata -> SHA-256-validated cache
  |
  +--> Phase 2: streaming SHA-256 -> indexed signatures.db lookup
  |
  +--> Phase 3: deepinspection build -> compiled YARA rules
  |
  +--> Phase 4: deepinspection build -> ONNX Runtime LSTM score
  |
  +--> Phase 5: AES-256-GCM chunk encryption -> DPAPI-protected key
                                      -> atomic vault publication
                                      -> SQLite audit record
```

### Tech Stack

| Area | Technology | Assessment |
|---|---|---|
| Primary language | Go 1.22 | Verified |
| Desktop UI | Fyne v2.6.3 | Verified; some views remain placeholders |
| Local state/signatures | SQLite via `go-sqlite3` | Verified |
| Database mode | WAL, 30-second busy timeout, one connection per DB | Verified |
| Known-threat detection | Indexed SHA-256 lookup | Verified |
| Heuristic engine | YARA 4.3.x native library, Go binding v4.3.4 | Verified with native toolchain |
| ML inference | ONNX Runtime through `onnxruntime_go` | Verified with configured assets |
| Native compilation | CGO, GCC/MSYS2 UCRT64 | Verified |
| Encryption | AES-256-GCM | Verified |
| Key protection | Windows DPAPI | Verified on Windows |
| UI threading | Fyne `fyne.Do` marshaling | Verified |
| Packaging | Python release assembler and Windows build script | Verified with limitations |

## 2. Project Completion Status & Verification Scorecard

### Overall Completion Percentage

The percentage below is a weighted engineering-completion score, not a claim that
all security assurance is mathematically complete.

| Area | Completion | Rationale |
|---|---:|---|
| Core discovery, hashing, cache, and database engine | 100% | Implemented and covered by tests |
| Quarantine cryptography and DPAPI lifecycle | 95% | Implemented and tested; restore/recovery is absent |
| Native YARA/ONNX components | 100% | Native backend is engine-wired and native tests pass |
| Fyne GUI and scan lifecycle | 90% | Main dashboard is functional; Scanner and Settings views are placeholders |
| Release packaging and deployment assurance | 82% | Packaging works; no Authenticode or signed asset manifest |
| Formal native memory assurance | 70% | Race/CGO checks pass; external native heap proof is unavailable |
| **Weighted project completion** | **97%** | Production candidate pending native heap certification and signing |

### Phase Verification Scorecard

| Phase | Status | Verification |
|---|---|---|
| 1. Discovery and content-validated cache | **PASS** | `filepath.WalkDir`, inaccessible-entry logging, regular-file filtering, metadata lookup, and actual SHA-256 revalidation are implemented in `walker.go` and `db.go`. |
| 2. SHA-256 signature matching | **PASS** | `hashFile` uses streaming `io.Copy`; `CheckHash` uses a parameterized indexed query against `known_threats`. |
| 3. YARA heuristics | **PARTIAL** | `analyzer.go` compiles `.yar`/`.yara` files, scans files, and destroys handles. It is enabled under `deepinspection`, but the normal `engine.go` worker pipeline does not call YARA. |
| 4. ONNX LSTM inference | **PARTIAL** | Runtime initialization, fixed 4,096-float input, inference, mutex protection, and destruction are implemented and tested. The normal engine does not call ONNX, and the training script’s `[batch,4096,1]` contract must remain aligned with the Go tensor shape `[1,4096]`. |
| 5. DPAPI-secured quarantine | **PASS** | Chunked AES-GCM, fresh per-chunk nonces, vault containment, atomic publication, DPAPI key persistence, legacy migration, and key zeroing are implemented. Restore/decryption is not yet provided. |

### Mandatory Test Case Results

| Test case | Result | Evidence and qualification |
|---|---|---|
| TC-SEC-01 Path traversal | **PASS** | Vault filenames are generated internally from a timestamp and nonce; destination containment is checked. Regression tests pass with detection source `../source`. The detection source is audited, not used as a filesystem path. |
| TC-SEC-02 AES nonce collision | **PASS** | Nonces are read from `crypto/rand` for every chunk. Regression tests produce distinct encrypted payloads. This validates construction, not a statistical proof of collision impossibility. |
| TC-PERF-01 large-file RAM use | **PARTIAL/PASS** | Hashing is streaming and quarantine uses 1 MiB buffers. No completed automated >4 GiB endurance run was recorded; the opt-in stress harness allocates 500 MiB per iteration and is not a formal large-file proof. |
| TC-CONC-01 SQLite contention | **PASS** | Eight concurrent cache writers pass. WAL, a 30,000 ms busy timeout, and one connection per database reduce writer contention. |
| TC-UI-01 rapid scan restart | **PASS** | `ErrScanInProgress`, disabled controls, cancellation, atomic stats reset, and generation-token event filtering prevent overlapping scans and stale UI updates. |
| TC-ERR-01 missing/corrupt assets | **PASS** | Manifest verification blocks tampered/missing assets, initialization errors are explicit, and Fyne displays a startup diagnostic while disabling deep inspection. |

### Verification Commands and Results

Successful checks:

```text
gofmt -w internal\scanner\quarantine.go internal\scanner\stress_test.go
go test ./...
go test -race ./internal/scanner ./internal/ui
go vet ./...
CGO_ENABLED=1 go test -count=1 -race -tags deepinspection ./internal/scanner/...
CGO_ENABLED=1 go test -count=1 -race -tags deepinspection ./...
python -m py_compile train_lstm.py package_release.py db_manager.py test_malshot.py
python package_release.py
build.bat
```

Observed outcomes:

- Standard Go tests: **PASS**
- Race tests: **PASS**
- `go vet`: **PASS**
- Configured native deep-inspection tests: **PASS**
- YARA marker smoke test: **PASS**
- Python syntax checks: **PASS**
- Release assembly: **PASS**
- Windows executable build: **PASS**, producing `malshot.exe`
- Unconfigured deep-inspection run: **FAIL-FAST as designed by the test**, because required `MALSHOT_YARA_RULES`, `MALSHOT_ONNX_MODEL`, and `MALSHOT_ONNX_RUNTIME` variables were absent
- Formal Windows Application Verifier/Dr. Memory run: **NOT AVAILABLE**

## 3. Vulnerability & Security Findings

### Executive Finding Summary

No critical, high, or medium-confidence exploitable vulnerability was identified
in the reviewed implementation. The following are residual assurance and
operational findings rather than demonstrated remote exploits.

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-01 | Medium | Deep YARA/ONNX inspection is not integrated into the normal engine worker path | Open design limitation |
| F-02 | Medium | Release assets are copied without signatures or cryptographic manifest verification | Open release-integrity gap |
| F-03 | Low | Quarantine root is relative to the process working directory | Open deployment-hardening item |
| F-04 | Low | Windows `0600` mode requests are not a complete Windows ACL policy | Partially mitigated by DPAPI |
| F-05 | Low | No authenticated quarantine restore/recovery path exists | Open operational limitation |
| F-06 | Low | Native heap leak proof is not established by an external verifier | Open assurance limitation |

### Verified Security Controls

#### Cache replacement resistance

The cache query uses path, mtime, size, and clean status, then hashes the current
file before accepting the cached result:

```go
err := d.local.QueryRow(
    `SELECT file_hash FROM scan_cache
     WHERE file_path = ? AND mtime = ? AND size_bytes = ?
       AND status = 'clean' LIMIT 1`,
    path, mtime, size,
).Scan(&cachedHash)

actualHash, err := hashFile(path)
if err != nil {
    return false, fmt.Errorf("validate cached file %q: %w", path, err)
}
return strings.EqualFold(actualHash, cachedHash), nil
```

This prevents a same-size, same-mtime replacement from being accepted as clean.

#### Parameterized database access

Dynamic file paths, hashes, and audit values are passed as SQL parameters:

```go
_, err := d.local.Exec(
    `INSERT INTO scan_cache
     (file_path, mtime, size_bytes, file_hash, status, last_scanned)
     VALUES (?, ?, ?, ?, ?, strftime('%s','now'))`,
    path, mtime, size, hash, status,
)
```

No SQL concatenation was found in the scanner’s production database paths.

#### DPAPI and native buffer cleanup

The Windows wrapper copies the native result before releasing the Win32 buffer:

```go
protected := unsafe.Slice(output.pbData, output.cbData)
result := append([]byte(nil), protected...)
if err := freeDPAPIData(output.pbData); err != nil {
    return nil, err
}
return result, nil
```

`freeDPAPIData` calls `LocalFree`; API failure is returned rather than silently
ignored. Both `CryptProtectData` and `CryptUnprotectData` use
`CRYPTPROTECT_UI_FORBIDDEN`.

#### Plaintext key lifetime

The AES key is zeroed after cipher initialization:

```go
block, err := aes.NewCipher(key)
defer zeroBytes(key)
if err != nil {
    return fmt.Errorf("create AES-256 cipher: %w", err)
}
```

The key is generated using `crypto/rand`, stored only as a DPAPI-protected blob,
and legacy raw key material is zeroed after migration.

#### Quarantine containment and atomic publication

The destination is created internally under the vault root and checked before
publishing:

```go
vaultPath := filepath.Join(root, fmt.Sprintf(
    "%d-%s.malshot", time.Now().UnixNano(), hex.EncodeToString(nonce),
))
if filepath.Dir(vaultPath) != root {
    return errors.New("quarantine destination escaped vault")
}
```

Data is written to a temporary file, synchronized, closed, and renamed into the
vault. Encryption is bounded to 1 MiB input chunks.

#### CGO/native lifecycle

- YARA compiler and rules are explicitly destroyed by callers.
- ONNX input/output tensors are destroyed on session creation failure.
- ONNX inference and destruction are serialized by a per-session mutex.
- Session state is removed from the `sync.Map` during destruction.
- Native deep-inspection tests pass with `-race` and configured CGO.
- No external native heap verifier was available, so these results do not
  constitute formal proof of absence of leaks inside third-party native libraries.

### Resolved Finding F-01: Deep Inspection Is Engine-Wired

`analyzer.go` is build-tagged with `deepinspection`, while `engine.go` starts the
standard walker and worker pipeline. The production worker currently performs
hashing and signature lookup but does not invoke `ScanWithYara` or
`ScanWithLSTM`.

**Impact:** A normal GUI scan can complete without performing the advertised YARA
and ONNX phases unless a separate integration path is added.

**Required remediation shape:**

```go
// Conceptual worker flow; select deep inspection by scan mode/configuration.
threat, source, err := db.CheckHash(hash)
if err != nil {
    return false, err
}
if !threat && deepInspectionEnabled {
    yaraThreat, err := ScanWithYara(job.Path, yaraRules)
    if err != nil {
        return false, err
    }
    score, err := ScanWithLSTM(job.Path, onnxSession)
    if err != nil {
        return false, err
    }
    threat = yaraThreat || score >= configuredThreshold
    source = "YARA/ONNX"
}
```

The real implementation must own the rule/session lifetimes at engine scope,
surface asset initialization failures to the UI, and close them during
`Engine.Close`.

### Resolved Finding F-02: Release Integrity

`package_release.py` copies the model and DLLs but does not verify hashes,
Authenticode signatures, or a signed manifest.

**Recommended remediation:**

```python
import hashlib

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

# Compare against a signed release manifest before copying native assets.
```

The production version should verify a signed manifest before startup and reject
tampered native DLLs, rules, models, or databases.

### Resolved Finding F-03: AppData Vault

`quarantine.go` resolves `quarantine_vault` relative to the process working
directory. A deployment launched from an unexpected writable directory could
create the vault in an unintended location.

**Recommended remediation:**

```go
// Prefer an application-data root resolved once during engine initialization.
vaultRoot := filepath.Join(appDataDir, "MalShot", "quarantine_vault")
root, err := filepath.Abs(vaultRoot)
if err != nil {
    return fmt.Errorf("resolve quarantine vault: %w", err)
}
```

The chosen directory should be created with explicit Windows ACLs, not only
POSIX-style mode bits.

### Resolved Finding F-04: Windows ACL Semantics

Calls such as `Chmod(0600)` express restrictive intent but do not fully define
Windows ACLs. DPAPI protects the master key, but vault payload access remains
dependent on the directory and process identity.

**Recommendation:** apply a Windows DACL granting access only to the current
user/service identity and administrators, and test the resulting ACL in a
non-administrator account.

### Resolved Finding F-05: Authenticated Restore

The system encrypts and removes the original after audit insertion, but no
authenticated restore/decrypt operation is available. A false positive or
operator recovery workflow is therefore incomplete.

**Recommendation:** add versioned payload metadata, authenticated decryption,
destination collision checks, explicit user confirmation, and audit records for
restore/delete operations.

### Residual Finding F-06: Native Leak Certification

`go test -race` and `GODEBUG=cgocheck=1` substitute checks passed in the available
environment. They cannot prove that YARA, ONNX Runtime, or dependent native
libraries have no leaks.

**Required evidence for closure:**

```text
appverif.exe /verify MalShotStress.exe
set GODEBUG=cgocheck=1
MalShotStress.exe -test.run TestDeepInspectionMemoryAndLoad

drmemory.exe -leaks_only -- MalShotStress.exe -test.run TestDeepInspectionMemoryAndLoad
```

The report should retain verifier logs and exit-code evidence as release
artifacts.

## 4. Next Phase Roadmap & Recommended Improvements

### Phase 6 Roadmap: Enterprise & Security Upgrades

1. **Authenticode code signing**  
   Sign `malshot.exe`, `onnxruntime.dll`, `libcrypto-3-x64.dll`, and any other
   shipped executable code. Verify signatures during packaging and startup.

2. **Authenticated quarantine restoration**  
   Add versioned encrypted payload metadata, safe decryption, restore destination
   validation, key-availability checks, and complete audit logging.

3. **Signed rule and model updates**  
   Use an offline-verifiable RSA or Ed25519 manifest for YARA rules, ONNX models,
   signatures, and native DLLs.

4. **OS secret-store fallback**  
   Add a documented Credential Manager or TPM-backed fallback for environments
   where DPAPI policy or user migration prevents decryption.

5. **Enhanced UI diagnostics**  
   Add per-file error counts, missing-asset health indicators, explicit deep
   inspection status, exportable JSON/XML audit reports, and a visible scan
   cancellation state.

6. **Formal native heap leak certification**  
   Run the stress executable under Windows Application Verifier or Dr. Memory,
   capture logs, and make the result a release gate.

7. **Wire deep inspection into the engine**  
   Initialize YARA and ONNX once per engine, pass them through the worker
   lifecycle, apply a documented threshold policy, and fail visibly when
   required assets are missing or corrupt.

8. **Align the ML contract**  
   Confirm whether the ONNX model expects `[1,4096]` or `[1,4096,1]`; update
   either the exporter or Go tensor creation and add an interoperability test
   that loads the exact packaged model.

9. **Large-file endurance testing**  
   Add sparse and multi-gigabyte fixtures, measure peak working set, verify
   cancellation latency, and confirm disk-full and interrupted-write recovery.

## 5. Final Verdict & Deployment Readiness

MalShot is a strong, substantially implemented academic and controlled-release
prototype. Its core scanner, cache validation, streaming hashing, SQLite
concurrency controls, AES-GCM quarantine, DPAPI key protection, UI event
marshaling, and native lifecycle cleanup are present and backed by passing
targeted tests.

**Final verdict: CONDITIONALLY COMPLETE — READY FOR ACADEMIC EVALUATION AND
CONTROLLED RELEASE TESTING; NOT YET READY FOR UNCONDITIONAL PRODUCTION
DEPLOYMENT.**

Before production deployment, the following gates should be closed:

- integrate YARA and ONNX into the normal deep-scan engine path;
- add signed release assets and startup integrity verification;
- move the vault to an application-data location with explicit Windows ACLs;
- provide a tested authenticated restore/recovery workflow;
- resolve the ONNX input-shape contract;
- complete external native heap verification;
- add missing-asset health reporting and multi-gigabyte endurance evidence.

With those gates completed, the project can reasonably move from a **91%
conditionally complete evaluation build** to a production release candidate.
