# MalShot Defender: B.Tech (Hons) Thesis Outline

## Proposed Title

**Design and Evaluation of MalShot: An Offline-First Malware Detection and
Quarantine System Using Go, YARA, ONNX LSTM Inference, SQLite, and Windows
DPAPI**

## Front Matter

- Title page
- Certificate and declaration
- Acknowledgements
- Abstract
- List of figures
- List of tables
- Abbreviations and terminology

## Chapter 1: Introduction

### 1.1 Background

- Growth of commodity malware and zero-day threats.
- Limits of cloud-only antivirus workflows.
- Need for local, low-latency, privacy-preserving analysis.

### 1.2 Problem Statement

- Detect known threats efficiently through signatures.
- Detect suspicious unknown content through heuristics and ML.
- Quarantine files without exposing user data or losing auditability.

### 1.3 Aim and Objectives

- Build an offline-first Windows malware scanner.
- Combine SHA-256 intelligence, YARA rules, and ONNX inference.
- Provide concurrent scanning with bounded resource use.
- Protect quarantine data and keys with Windows DPAPI.

### 1.4 Scope and Constraints

- Windows desktop target.
- Local databases and local model/rule assets.
- No claim of replacing enterprise endpoint detection and response.
- Native CGO and model-runtime dependencies.

### 1.5 Contributions

- Content-bound clean-file cache.
- Concurrent Go scanning pipeline.
- Native YARA/ONNX integration.
- Chunked AES-256-GCM quarantine.
- DPAPI-protected vault master key.

### 1.6 Chapter Organization

Summarize Chapters 2 through 6.

## Chapter 2: Literature Review

### 2.1 Malware Detection Taxonomy

- Signature-based detection.
- Static heuristics.
- Behavioral and sandbox analysis.
- ML and deep-learning approaches.

### 2.2 File Hash Intelligence

- SHA-256 properties.
- Indexed lookup complexity.
- MalwareBazaar-style threat feeds.

### 2.3 YARA

- Rule structure and matching semantics.
- Strengths and false-positive considerations.
- Native library and binding lifecycle.

### 2.4 Recurrent Neural Networks

- LSTM gates and sequence modeling.
- Byte-level representation.
- Sliding windows and padding.

### 2.5 ONNX Interoperability

- Framework-independent model deployment.
- Runtime ABI and native resource management.

### 2.6 Secure Quarantine

- AES-GCM authenticated encryption.
- Nonce uniqueness.
- Windows DPAPI key protection.

### 2.7 Research Gap

Explain the gap between high-performance local scanning, deep inspection, and
secure offline quarantine in a unified desktop workflow.

## Chapter 3: System Architecture and DPAPI Mechanics

### 3.1 Requirements

- Offline operation.
- Fast repeated scans.
- Safe concurrency.
- Explicit error handling.
- Recoverable quarantine audit.

### 3.2 Component Architecture

Include a diagram showing:

```text
Fyne UI
   |
Engine and Context Cancellation
   |
Walker -> Worker Pool -> Hash Database
                    -> YARA
                    -> ONNX Runtime
                    -> Quarantine
```

### 3.3 Five-Phase Pipeline

Describe discovery/cache, signature lookup, YARA, ONNX, and remediation.

### 3.4 SQLite Design

- `local_state.db`
- `signatures.db`
- WAL mode
- Parameterized queries
- Connection-pool limits

### 3.5 Windows DPAPI Mechanics

- `CryptProtectData`.
- `CryptUnprotectData`.
- `CRYPTPROTECT_UI_FORBIDDEN`.
- Protected `vault.key`.
- Legacy `.quarantine.key` migration.
- `LocalFree` cleanup.
- Plaintext key zeroing.

### 3.6 Threat Model

- Same-user file replacement.
- Malicious rule/model replacement.
- Quarantine directory tampering.
- Database contention and corruption.
- Native library failure.

## Chapter 4: Implementation Details and CGO Memory Model

### 4.1 Go Concurrency Model

- Goroutines.
- Channels.
- Context cancellation.
- Wait groups.
- Atomic statistics.

### 4.2 Content-Validated Cache

Explain why path, size, and mtime alone are insufficient and how SHA-256
validation closes the bypass.

### 4.3 Streaming and Bounded Memory

- Streaming SHA-256.
- 1 MiB quarantine chunks.
- YARA file scanning.
- 4,096-byte ONNX input sequence.

### 4.4 YARA Binding

- Compiler creation.
- Rule compilation.
- Synchronous callback pointer lifetime.
- Rule/compiler destruction.

### 4.5 ONNX Binding

- Tensor creation.
- Session state map.
- Inference mutex.
- Destruction sequencing.

### 4.6 DPAPI and Cryptography

- Random 32-byte AES key.
- DPAPI-protected persistence.
- AES-256-GCM nonce handling.
- Ciphertext authentication.
- In-memory hygiene.

### 4.7 Fyne UI Thread Isolation

- `fyne.Do`.
- Generation tokens.
- Async vault refresh.
- Scan button lifecycle.

## Chapter 5: Empirical Results and Benchmark Comparisons

### 5.1 Experimental Environment

Document CPU, RAM, Windows version, Go version, GCC/MSYS2, YARA, ONNX Runtime,
and model version.

### 5.2 Correctness Tests

- Standard Go tests.
- Race tests.
- Go vet.
- Python syntax checks.
- DPAPI round-trip tests.
- Legacy migration tests.

### 5.3 Deep Inspection Tests

- Temporary YARA marker rule.
- ONNX inference output range.
- Full five-phase E2E test.

### 5.4 Security Test Cases

Report TC-SEC-01 through TC-ERR-01 with methods and results.

### 5.5 Performance Benchmarks

Measure:

- Cold scan time.
- Cached scan time.
- Throughput by file size.
- Peak RSS for large files.
- SQLite lock wait time.
- Quarantine throughput.

### 5.6 Comparison Baselines

Compare against:

- Hash-only scanner.
- Serial Go scanner.
- No-cache scanner.
- YARA-only configuration.

### 5.7 Native Memory Verification

Document race/cgocheck stress results and, when available, Application
Verifier or Dr. Memory reports. Do not claim formal leak proof without native
tool evidence.

### 5.8 Threats to Validity

- Dataset representativeness.
- Model calibration.
- False positives.
- Windows-only measurements.
- Native library version differences.

## Chapter 6: Conclusion and Future Scope

### 6.1 Findings

Summarize achieved capabilities and measured results.

### 6.2 Limitations

- Model training data.
- Formal native heap verification.
- Code signing and trusted asset distribution.
- Restore workflow.

### 6.3 Future Work

- DPAPI key rotation and recovery.
- Signed rules and model manifests.
- Behavioral monitoring.
- Explainable model outputs.
- Incremental feed updates.
- Enterprise policy integration.

### 6.4 Final Conclusion

Position MalShot as a defensible offline scanning foundation rather than a
complete replacement for commercial endpoint protection.

## References and Appendices

- Go, Fyne, SQLite, YARA, ONNX Runtime, PyTorch, and Microsoft DPAPI sources.
- Database schema.
- API and threat-model tables.
- Test logs.
- Benchmark raw data.
- Release checklist.
