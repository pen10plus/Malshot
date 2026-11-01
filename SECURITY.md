# Security Policy

MalShot is designed with defense-in-depth, offline-first security principles. We take the security of our application and the protection of user endpoints seriously.

---

## 🔒 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## 🛡️ Security Architecture & Mitigations

MalShot implements several critical security guardrails:

1. **Hardware-Backed Quarantine Vault**:
   - Quarantined payloads are encrypted using **AES-256-GCM** with fresh per-chunk nonces.
   - On Windows, the master vault key is secured using the **Windows Data Protection API (DPAPI)** via `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`.
   - The plaintext key is held in memory only during active crypto operations and immediately zeroed out after use.

2. **Path Traversal Protection**:
   - All quarantine operations strictly validate paths against the vault root, preventing path traversal attacks (e.g. `../../sensitive.dll`).

3. **Offline Privacy**:
   - MalShot runs completely offline by default. No file content, hash telemetry, or user metadata is transmitted over the network unless explicitly connecting to a user-configured Google Colab GPU endpoint.

4. **Resource Bounding & Memory Safety**:
   - Streaming hash computations and chunked 1 MiB stream encryption avoid buffer exhaustion when handling multi-gigabyte files.
   - Bounded SQLite connection pools prevent worker contention and file-lock denial of service.

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability in MalShot:

1. **Do not open a public issue.**
2. Send a detailed report to the security maintainers via **GitHub Private Vulnerability Reporting** or email: `security@malshot.internal`.
3. Include:
   - Type of issue (e.g., buffer overflow, logic flaw, key leak)
   - Step-by-step reproduction instructions or proof-of-concept
   - Impact assessment
4. We acknowledge receipt within 48 hours and aim to provide a security patch or mitigation within 14 days.
