# MALSHOT DEFENDER: GOOGLE COLAB COMPUTE INTEGRATION GUIDE

This guide details how to leverage **Google Colab's Free & Pro GPU Compute** (NVIDIA Tesla T4, V100, or A100) directly within MalShot for:
1. **High-Speed GPU Model Training & Fine-Tuning**
2. **Exporting Synchronized `lstm_malware.onnx` Models**
3. **Live Remote GPU Zero-Day Scanning (Cloud Compute Offloading)**

---

## 1. Quick Start: Opening the Notebook in Google Colab

1. Open your browser and navigate to [Google Colab](https://colab.research.google.com/).
2. Select **Upload** and upload [`MalShot_Colab_Compute.ipynb`](file:///c:/Users/AW/Desktop/files/MalShot_Colab_Compute.ipynb) from this repository.
3. In the top navigation menu, select:
   **Runtime > Change runtime type > Hardware accelerator > T4 GPU**
4. Click **Connect** (top right) to allocate your GPU instance.

---

## 2. Operational Workflow A: Training & Exporting the ONNX Model

1. **Run Cells 1 through 5** sequentially in the notebook:
   - Cell 1 checks your GPU allocation (`!nvidia-smi`).
   - Cell 2 installs dependencies (`torch`, `onnx`, `onnxruntime-gpu`).
   - Cell 3 compiles the `MalwareLSTM` neural network with input shape `[batch, 4096]`.
   - Cell 4 optimizes model weights using Adam optimizer and GPU tensor cores.
   - Cell 5 exports the verified `lstm_malware.onnx` model adhering to MalShot's native Go contract.
2. **Run Cell 6** (`files.download("lstm_malware.onnx")`) to download the generated model directly to your machine.
3. Copy the downloaded `lstm_malware.onnx` into your MalShot root directory.
4. Run `python repair_manifest.py` to synchronize SHA-256 release hashes.

---

## 3. Operational Workflow B: Live Remote Colab GPU Scanning

You can use Colab as an active, high-throughput GPU inference engine for MalShot:

### Step 1: Start the Remote Server on Colab
1. In `MalShot_Colab_Compute.ipynb`, execute **Cell 7**.
2. The notebook launches a FastAPI server on port 8000 and connects it to a secure, zero-config Cloudflare Tunnel.
3. Colab will display your public endpoint:
   ```text
   ===========================================================================
   [+] GOOGLE COLAB COMPUTE TUNNEL ACTIVE!
   [+] Public Colab URL: https://example-subdomain.trycloudflare.com
   ===========================================================================
   ```

### Step 2: Connect MalShot to Google Colab Compute

You can connect MalShot to your Colab GPU instance using any of the following methods:

#### Method 1: MalShot Desktop UI (Settings Tab)
1. Launch MalShot: `.\malshot.exe`
2. Click on the **Settings & Intel** tab.
3. In the **Google Colab Cloud Compute Bridge** box, enter your Colab tunnel URL.
4. Click **Test GPU Connection**.
5. Once verified, MalShot will route zero-day deep inspection queries directly to Colab's GPU!

#### Method 2: PowerShell Environment Variable
Set the environment variable in your terminal before launching MalShot:
```powershell
$env:MALSHOT_COLAB_URL = "https://example-subdomain.trycloudflare.com"
.\malshot.exe
```

#### Method 3: Command-Line Bridge Tool (`colab_bridge.py`)
Use the included CLI bridge utility:
```powershell
# 1. Health check & GPU telemetry:
python colab_bridge.py --url https://example-subdomain.trycloudflare.com --health

# 2. Remote scan a file using Colab's GPU:
python colab_bridge.py --url https://example-subdomain.trycloudflare.com --scan .\test_scan_target\eicar_dummy.txt

# 3. Download the latest trained ONNX model directly:
python colab_bridge.py --url https://example-subdomain.trycloudflare.com --download-model
```

---

## 4. API Specification for Colab Compute Server

| Method | Endpoint | Description | Sample Request / Response |
|---|---|---|---|
| `GET` | `/health` | Hardware & Model Telemetry | Returns `{ "status": "healthy", "device": "Tesla T4", "vram_gb": 15.1, "model": "MalwareLSTM-v2" }` |
| `POST` | `/scan` | Single-File GPU Inference | Request: `{ "bytes": [0.21, 0.44, ...], "file_name": "target.exe" }`<br>Response: `{ "confidence_score": 0.884, "is_threat": true, "inference_time_ms": 1.1 }` |
| `GET` | `/download-model` | Stream Trained ONNX Model | Returns binary stream of `lstm_malware.onnx` |

---

## 5. Security & Privacy Safeguards
- **Zero Raw File Uploads:** Only the normalized 4,096-byte opcode window is sent to the compute server; full documents and file bodies are never transmitted.
- **End-to-End TLS Encryption:** Cloudflare Tunnel automatically provides TLS 1.3 encryption between MalShot and your Colab session.
- **Graceful Fallback:** If the Colab runtime is stopped or internet connectivity drops, MalShot automatically falls back to local CPU inference (`onnxruntime.dll`) without interrupting scans.
