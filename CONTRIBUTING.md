# Contributing to MalShot

Thank you for your interest in contributing to MalShot! We welcome contributions from the cybersecurity, open-source, and machine learning communities.

---

## 🛠️ Development Environment Setup

### Prerequisites

1. **Go Toolchain**: Go 1.22 or later ([golang.org](https://go.dev/dl/)).
2. **CGO Compiler (for deep inspection)**:
   - **Windows**: MSYS2 with UCRT64 or MinGW64 toolchain (`gcc`, `pkg-config`, `libyara`, `openssl`).
   - **Linux**: GCC / Clang, `libyara-dev`, `libssl-dev`, `pkg-config`.
3. **Python (for threat intel & model utilities)**: Python 3.10+ with `requests`, `onnxruntime`, `torch` (optional).

### Setup Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/<your-org-or-username>/MalShot.git
   cd MalShot
   ```

2. **Verify Go dependencies**:
   ```bash
   go mod download
   go mod verify
   ```

3. **Run tests**:
   ```bash
   # Pure Go unit and UI tests:
   go test -v ./...

   # Native deep-inspection tests (requires CGO and libyara):
   go test -v -race -tags deepinspection ./internal/scanner
   ```

---

## 🏗️ Building MalShot

### Standard Build (Heuristics & Signature Engine)
```bash
go build -trimpath -ldflags="-s -w" -o malshot.exe .
```

### Deep Inspection Build (YARA + ONNX Deep Learning)
- **Windows**: Run `build.bat` from an MSYS2-enabled terminal or command prompt.
- **Linux / macOS**: Run `./build.sh`.

---

## 🧪 Testing Standards

Before submitting a Pull Request, verify all quality gates pass:

1. **Go Code Quality**:
   ```bash
   go vet ./...
   go test -race ./...
   ```
2. **Python Syntax**:
   ```bash
   python -m py_compile db_manager.py colab_bridge.py package_release.py
   ```
3. **Release Asset Validation**:
   ```bash
   python package_release.py
   ```

---

## 🤝 Pull Request Process

1. Fork the repository and create your feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Write clean, idiomatic code with tests covering new functionality.
3. Commit using clear, conventional messages (e.g., `feat: ...`, `fix: ...`, `docs: ...`).
4. Ensure all CI checks and tests pass.
5. Submit your Pull Request detailing the problem solved and test results.

---

## 📜 Code Style & Philosophy

- **Offline-First & Privacy**: Scanner operations must never exfiltrate scanned user files or plaintext telemetry without explicit configuration.
- **Memory Safety**: Clean up native resources (YARA compilers/rules, ONNX sessions) via explicit `Destroy()` calls.
- **Concurrency Safety**: Synchronize shared state; always test with the `-race` detector enabled.
