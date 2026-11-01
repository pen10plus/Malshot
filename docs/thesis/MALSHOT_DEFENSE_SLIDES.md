# MalShot Defender: 15-Slide Defense Deck

## Slide 1 — Title

**MalShot Defender: Offline-First Malware Detection and Secure Quarantine**

- Student name
- Department and Quantum University
- Supervisor
- Academic year

Talking point: Introduce the problem of privacy-preserving local malware
detection.

## Slide 2 — Motivation

Visual layout:

```text
Cloud-only detection -> latency, connectivity, privacy concerns
Local detection      -> fast response, offline operation, user control
```

Talking points:

- Threats continue when disconnected.
- Local analysis avoids uploading sensitive files.

## Slide 3 — Objectives

- Detect known malware through SHA-256 intelligence.
- Detect suspicious content with YARA.
- Score unknown patterns with ONNX LSTM inference.
- Quarantine safely with authenticated encryption and DPAPI.
- Maintain responsive UI and bounded resources.

## Slide 4 — System Architecture

Visual:

```text
Fyne UI
  -> Scanner Engine
      -> Discovery and Cache
      -> Worker Pool
          -> SQLite Hash Lookup
          -> YARA
          -> ONNX
          -> DPAPI + AES-GCM Vault
```

Talking point: Emphasize separation of UI, orchestration, detection, and
remediation.

## Slide 5 — Five-Phase Workflow

Show a horizontal five-step pipeline:

```text
Discover -> Hash -> YARA -> ONNX -> Quarantine
```

Mention skip-cache behavior and event-driven progress.

## Slide 6 — Content-Validated Caching

Visual comparison:

```text
Unsafe: path + size + mtime
MalShot: path + size + mtime + SHA-256 validation
```

Talking point: Explain how same-metadata replacement attacks are rejected.

## Slide 7 — YARA Deep Inspection

- Rule compilation from `.yar`/`.yara`.
- Temporary marker rule test.
- Synchronous callback lifetime.
- Explicit compiler and rules cleanup.

Metric: YARA 4.3.2 native test passed.

## Slide 8 — ONNX LSTM Inference

Visual:

```text
4096 bytes -> normalized float sequence -> 2-layer LSTM -> probability
```

- Input window: 4,096 bytes.
- Output: threat confidence between 0 and 1.
- Verified sample confidence: approximately 0.0012.

## Slide 9 — DPAPI and Quarantine Security

Visual:

```text
Random 32-byte key
        |
CryptProtectData
        |
vault.key
        |
CryptUnprotectData -> AES-256-GCM -> chunked vault payload
```

Talking points:

- Raw master key is not stored on disk.
- DPAPI output buffers are released with `LocalFree`.
- Decrypted key memory is zeroed after cipher initialization.

## Slide 10 — Concurrency and UI Safety

- Worker pool with context cancellation.
- SQLite WAL and bounded connection pool.
- Atomic scan counters.
- `fyne.Do` for UI updates.
- Generation tokens prevent stale restart events.

## Slide 11 — Security Test Cases

Table:

| Case | Result |
|---|---|
| Path traversal | Pass |
| Nonce generation | Pass |
| Large-file design | Pass by bounded implementation |
| SQLite concurrency | Pass |
| Rapid restart | Pass |
| Missing assets | Explicit failure |

## Slide 12 — Native Verification

- CGO enabled.
- GCC/MSYS2 and pkg-config.
- YARA 4.3.2.
- `-race` and `GODEBUG=cgocheck=1`.
- No race or CGO pointer warnings in stress runs.

Qualification: formal native heap proof requires Application Verifier or Dr.
Memory.

## Slide 13 — Empirical Results

Display measured project results:

- Standard Go tests: pass.
- Race suite: pass.
- Deep-inspection suite: pass.
- YARA marker detection: pass.
- ONNX inference: pass.
- DPAPI round-trip and migration tests: pass.
- Release asset smoke test: pass.

Leave benchmark-specific latency and throughput values for measured data.

## Slide 14 — Limitations and Future Work

- Formal native heap leak report.
- Authenticode signing.
- Signed rule/model manifests.
- Multi-gigabyte benchmark.
- Quarantine restore and key rotation.
- Larger, calibrated malware dataset.

## Slide 15 — Conclusion and Questions

Key conclusion:

MalShot demonstrates a modular offline malware-scanning architecture combining
fast signatures, YARA, ML inference, secure quarantine, and responsive UI
engineering.

Closing prompts:

- Why offline-first?
- How is the cache protected?
- Why DPAPI?
- How were native resources verified?
