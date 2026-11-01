# MalShot — Offline Malware Defender & Threat Analyzer

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?logo=windows)](https://github.com/)
[![Security](https://img.shields.io/badge/Quarantine-AES--256--GCM%20%2B%20DPAPI-success)](#quarantine-vault--security-model)
[![Signatures](https://img.shields.io/badge/Threat%20Signatures-30%2C700%2B-red)](#threat-intelligence--signature-engine)
[![Deep Learning](https://img.shields.io/badge/Inference-ONNX%20BiLSTM%20%7C%20Colab%20GPU-blueviolet)](#deep-inspection-pipeline)

**MalShot** is an offline-first, high-performance endpoint security scanner and zero-day threat analyzer. Designed for air-gapped workstations, critical infrastructure, and privacy-sensitive security operations centers (SOC), MalShot executes multi-threaded static and behavioral malware detection completely locally without transmitting telemetry or payload data to third-party cloud vendors.

---

##  Key Highlights

- **Offline-First Security**: Operates autonomously without requiring active internet connectivity. All databases, models, and heuristics are self-contained.
- **3-Tier Hybrid Detection Pipeline**:
  1. **Tier 1 (Streaming Hash Matching)**: Indexed SHA-256 lookup against 30,700+ verified malware signatures.
  2. **Tier 2 (Compiled YARA Heuristics)**: Static pattern matching for APTs, ransomware, packers, and downloaders.
  3. **Tier 3 (Neural BiLSTM Deep Learning)**: ONNX Runtime neural opcode sequence classification for zero-day threat detection.
- **Hardware-Protected Quarantine**: AES-256-GCM streaming encryption with master keys secured by the **Windows Data Protection API (DPAPI)**.
- **Optional Cloud GPU Acceleration**: High-speed remote inference bridge to Google Colab GPU instances for heavy workloads.
- **Sleek Desktop & Web Interface**: Clean dark-mode desktop GUI built with Fyne plus a standalone Web SOC console (`dashboard.html`).

---

##  Detection Architecture

```
                       [ Target Files / Folders ]
                                   │
                                   ▼
                 ┌───────────────────────────────────┐
                 │    Concurrent Directory Walker    │
                 │   (Symlink & Traversal Guarded)   │
                 └─────────────────┬─────────────────┘
                                   │
                                   ▼
                 ┌───────────────────────────────────┐
                 │     Local State SQLite Cache      │
                 │  (Validated mtime, size & hash)   │
                 └─────────┬───────────────────┬─────┘
                           │ (Cache Hit)       │ (Unscanned / Modified)
                           ▼                   ▼
                     [ Clean Skip ]     [ Worker Pool ]
                                               │
               ┌───────────────────────────────┴───────────────────────────────┐
               ▼                                                               ▼
 ┌───────────────────────────┐                                   ┌───────────────────────────┐
 │ Tier 1: SHA-256 Hash Match│                                   │ Tier 2: YARA Rules Engine │
 │ 30,700+ Known Signatures  │                                   │ Heuristic Pattern Search  │
 └─────────────┬─────────────┘                                   └─────────────┬─────────────┘
               │                                                               │
               └───────────────────────────────┬───────────────────────────────┘
                                               │ (Deep Inspection Enabled)
                                               ▼
                                 ┌───────────────────────────┐
                                 │ Tier 3: Neural BiLSTM     │
                                 │ ONNX / Colab GPU Inference│
                                 └─────────────┬─────────────┘
                                               │
                                               ▼
                                  { Threat Detected? }
                                       │       │
                                  Yes  │       │  No
                                       ▼       ▼
                     ┌───────────────────────┐ ┌───────────────┐
                     │ Hardware-Protected    │ │ Update Cache  │
                     │ AES-256-GCM DPAPI     │ │ Status: Clean │
                     │ Quarantine Vault      │ └───────────────┘
                     └───────────────────────┘
```

---

##  Quick Start

### 1. Prerequisites

- **Go**: Version 1.22 or later installed.
- **Operating System**: Windows 10/11 x64 (recommended) or Linux x64.
- **CGO Toolchain** (optional, for native deep inspection):
  - On Windows: [MSYS2](https://www.msys2.org/) with `mingw-w64-x86_64-gcc` and `mingw-w64-x86_64-yara`.
  - On Linux: `gcc`, `libyara-dev`, `libssl-dev`.

### 2. Building from Source

#### Standard Build (Pure Go + SQLite)
Compiles quickly without native CGO dependencies; operates Tier 1 signature matching and quarantine:
```bash
go build -trimpath -ldflags="-s -w" -o malshot.exe .
```

#### Native Deep Inspection Build (YARA + ONNX Deep Learning)
- **Windows**:
  ```cmd
  build.bat
  ```
- **Linux**:
  ```bash
  chmod +x build.sh
  ./build.sh
  ```

### 3. Launching MalShot

#### Desktop GUI Mode
Double-click `malshot.exe` or execute from terminal:
```bash
./malshot.exe
```

#### Targeted CLI Directory Scan
Scan a specific folder directly:
```bash
./malshot.exe C:\Target\Directory
```

#### Launching the Web SOC Console
MalShot provides an interactive Web SOC Console for live telemetry and threat inspection:
```bash
python colab_bridge.py --dashboard
```

---

##  Quarantine Vault & Security Model

MalShot ensures that suspicious or infected executables cannot execute or alter host system files:

1. **Atomic Relocation & Encryption**: Malicious files are read in bounded 1 MiB streams, encrypted using **AES-256-GCM** with fresh cryptographic nonces, and saved under `quarantine_vault/`.
2. **Windows DPAPI Integration**: The 256-bit symmetric key is protected via Windows `CryptProtectData` (`CRYPTPROTECT_UI_FORBIDDEN`). The plaintext key resides in RAM only during active encryption/decryption cycles and is zeroed out immediately after use.
3. **Path Traversal Defense**: File paths are strictly cleaned and constrained to avoid escaping the vault boundary.
4. **Safe Restoration**: Quarantined items can be authenticated and restored to their original paths through the Quarantine Manager.

---

##  Threat Intelligence & Signature Engine

The included `signatures.db` is pre-populated with **30,700+ verified malware signatures** collected from open threat intelligence feeds:

- **MalwareBazaar** (Rolling 30-day feeds and full malware family databases)
- **ThreatFox** (Payload and botnet indicators)
- **URLhaus** (Verified malicious payloads)
- **ESET Research & Mandiant** (Enterprise APT indicators)
- **VX-Underground** (Historical indicators and family signatures)

### Updating Threat Intelligence
To synchronize threat intelligence feeds offline or online, use `db_manager.py`:
```bash
# Initialize and sync latest threat feeds into signatures.db:
python db_manager.py --sync

# Query a specific hash:
python db_manager.py --query <sha256_hash>
```

---

##  Google Colab GPU Bridge

For resource-constrained workstations, MalShot can offload neural BiLSTM inference to a remote GPU via the Colab Bridge:

1. Open [`MalShot_Colab_Compute.ipynb`](file:///MalShot_Colab_Compute.ipynb) in Google Colab and start a GPU runtime.
2. Run all cells to launch the GPU inference server via `ngrok` or `localtunnel`.
3. Set your bridge endpoint:
   ```bash
   set MALSHOT_COLAB_URL=https://<your-colab-endpoint>.ngrok-free.app
   ```
4. Run `malshot.exe` — deep learning inference will automatically stream to the remote GPU.

---

##  Verification & Automated Testing

MalShot includes a comprehensive test suite covering concurrency, encryption round-trips, cache validation, and UI event safety.

```bash
# Run all unit tests:
go test -v ./...

# Run race condition detector:
go test -race ./internal/scanner ./internal/ui

# Run full tagged deep-inspection test suite:
go test -v -race -tags deepinspection ./internal/scanner
```

---

## Repository Layout

```
MalShot/
├── .github/
│   └── workflows/
│       └── ci.yml               # Automated GitHub Actions CI/CD pipeline
├── docs/
│   ├── architecture/            # Interactive visualizer & architecture HTML
│   ├── reports/                 # Security audits & verification reports
│   └── thesis/                  # Defense slides & project thesis outlines
├── data/
│   └── cybersecurity_threat_intel_qa.json  # Threat intel QA dataset
├── internal/
│   ├── scanner/                 # Engine, hashing, worker pool, quarantine & DPAPI
│   └── ui/                      # Fyne desktop GUI, telemetry widgets & controls
├── rules/                       # Curated YARA heuristic signature rules
├── build.bat                    # Windows CGO / MinGW64 build script
├── build.sh                     # Linux / POSIX build script
├── build_and_store_rules.py     # YARA rules compiler & database ingest
├── colab_bridge.py              # Cloud GPU remote inference bridge & Web SOC
├── dashboard.html               # Interactive Web SOC console
├── db_manager.py                # Threat intelligence feeder & SQLite manager
├── go.mod / go.sum              # Go module definitions
├── libcrypto-3-x64.dll          # OpenSSL cryptographic library (Windows x64)
├── lstm_malware.onnx            # Neural BiLSTM malware classification model
├── main.go                      # MalShot main entry point
├── main_test.go                 # End-to-end integration tests
├── onnxruntime.dll              # ONNX Runtime engine (Windows x64)
├── package_release.py           # Production release packager & manifest builder
├── release_manifest.json        # Cryptographic integrity manifest for engine assets
├── signatures.db                # SQLite database with 30,700+ threat signatures
├── test_malshot.py              # EICAR dummy test injector & validator
└── train_lstm.py                # Neural BiLSTM training & ONNX export script
```

---

## License

MalShot is released under the [MIT License](LICENSE).
You are free to use, modify, and distribute this software for educational, research, and commercial purposes.
