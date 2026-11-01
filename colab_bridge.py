"""MalShot Google Colab Compute Bridge.

Provides bidirectional integration between the local MalShot defender and a Google Colab GPU runtime.

Features:
- Health check and GPU telemetry inspection of the remote Colab instance.
- Remote zero-day inference offloading to Colab's NVIDIA GPU.
- Automatic synchronization of newly trained ONNX models from Colab into MalShot.
- Local mock server for testing Colab endpoints offline.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Ensure UTF-8 console output for Indic scripts and Unicode across Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_TIMEOUT = 10.0


def check_colab_health(colab_url: str) -> dict:
    """Queries the Colab server's /health endpoint and returns GPU/runtime metadata."""
    url = f"{colab_url.rstrip('/')}/health"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "MalShot-ColabBridge/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {"status": "ok", "data": data}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def remote_scan_file(colab_url: str, file_path: Path) -> dict:
    """Reads the first 4096 bytes of a local file and submits it to Colab for GPU inference."""
    if not file_path.is_file():
        return {"status": "error", "error": f"file not found: {file_path}"}

    with file_path.open("rb") as f:
        data = f.read(4096)

    # Normalize bytes to float list [4096]
    opcodes = [b / 255.0 for b in data]
    if len(opcodes) < 4096:
        opcodes.extend([0.0] * (4096 - len(opcodes)))

    payload = json.dumps({"bytes": opcodes, "file_name": file_path.name}).encode("utf-8")
    url = f"{colab_url.rstrip('/')}/scan"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "User-Agent": "MalShot-ColabBridge/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    start_time = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            duration_ms = (time.perf_counter() - start_time) * 1000
            result = json.loads(resp.read().decode("utf-8"))
            result["roundtrip_ms"] = round(duration_ms, 2)
            return {"status": "ok", "result": result}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def download_model_from_colab(colab_url: str, output_path: Path) -> dict:
    """Downloads the trained lstm_malware.onnx directly from the Colab instance."""
    url = f"{colab_url.rstrip('/')}/download-model"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "MalShot-ColabBridge/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            content = resp.read()
            if len(content) < 100:
                return {"status": "error", "error": "downloaded model payload is too small"}
            output_path.write_bytes(content)
            return {
                "status": "ok",
                "bytes_written": len(content),
                "path": str(output_path.resolve()),
            }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def query_colab_qa(colab_url: str, question: str, context: str) -> dict:
    """Submits a question and context to the fine-tuned Indic-mALBERT QA model on Colab."""
    url = f"{colab_url.rstrip('/')}/qa"
    payload = json.dumps({"question": question, "context": context}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "User-Agent": "MalShot-ColabBridge/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    start_time = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            duration_ms = (time.perf_counter() - start_time) * 1000
            result = json.loads(resp.read().decode("utf-8"))
            result["roundtrip_ms"] = round(duration_ms, 2)
            return {"status": "ok", "result": result}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def run_local_mock_colab_server(port: int = 8088) -> None:
    """Runs a lightweight local HTTP server replicating Colab's compute API for offline testing."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class ColabMockHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                resp = {
                    "backend": "Google Colab (Local Mock)",
                    "device": "NVIDIA GeForce RTX (Emulated)",
                    "cuda_available": True,
                    "model_loaded": True,
                    "model_version": "v2.1-lstm-onnx",
                }
                self.wfile.write(json.dumps(resp).encode("utf-8"))
            elif self.path == "/download-model":
                local_model = Path(__file__).resolve().parent / "lstm_malware.onnx"
                if local_model.is_file():
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.end_headers()
                    self.wfile.write(local_model.read_bytes())
            elif self.path in ("/", "/dashboard", "/ui"):
                dashboard_file = Path(__file__).resolve().parent / "dashboard.html"
                if dashboard_file.is_file():
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(dashboard_file.read_bytes())
                else:
                    self.send_response(404)
                    self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path == "/scan":
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len)
                try:
                    payload = json.loads(body.decode("utf-8"))
                    opcodes = payload.get("bytes", [])
                    file_name = payload.get("file_name", "unknown")
                    # Calculate simple heuristic score for mock
                    avg = sum(opcodes) / len(opcodes) if opcodes else 0.0
                    score = min(0.99, max(0.01, float(avg * 0.4)))
                    resp = {
                        "file_name": file_name,
                        "confidence_score": round(score, 4),
                        "is_threat": score >= 0.80,
                        "inference_time_ms": 1.25,
                        "device": "cuda:0",
                    }
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(resp).encode("utf-8"))
                except Exception as exc:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(exc)}).encode("utf-8"))
            elif self.path == "/qa":
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len)
                try:
                    payload = json.loads(body.decode("utf-8"))
                    question = payload.get("question", "")
                    context = payload.get("context", "")
                    # Mock extractive answer selection
                    q_lower = question.lower()
                    if "ransomware" in q_lower or "रैनसमवेयर" in question:
                        answer = "AES-256 / RSA-4096 file encryption and Shadow Copy deletion"
                    elif "yara" in q_lower or "यारा" in question:
                        answer = "malware signatures, byte patterns, and regex heuristics"
                    elif "zero-day" in q_lower or "zero day" in q_lower or "जीरो-डे" in question:
                        answer = "LSTM sequence model and behavioral anomaly heuristics"
                    elif len(context) > 20:
                        answer = context[:60].strip()
                    else:
                        answer = "Isolated sandbox execution and dynamic opcode analysis"
                    resp = {
                        "question": question,
                        "answer": answer,
                        "confidence": 0.942,
                        "model": "rohitsroch/indic-mALBERT-squad-v2 (mock)",
                        "inference_time_ms": 14.8,
                    }
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(resp).encode("utf-8"))
                except Exception as exc:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(exc)}).encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            # Suppress noisy standard HTTP logs
            pass

    server = HTTPServer(("127.0.0.1", port), ColabMockHandler)
    print(f"[*] MalShot Mock Colab Server listening on http://127.0.0.1:{port}")
    print("[*] Set MALSHOT_COLAB_URL=http://127.0.0.1:8088 to connect.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping mock Colab server.")


def main() -> None:
    parser = argparse.ArgumentParser(description="MalShot Google Colab Compute Bridge")
    parser.add_argument("--url", help="Google Colab Tunnel URL (e.g. https://xxx.trycloudflare.com)")
    parser.add_argument("--health", action="store_true", help="Check Colab GPU health and connectivity")
    parser.add_argument("--scan", type=Path, help="Submit a file for remote Colab GPU inference")
    parser.add_argument("--qa", action="store_true", help="Ask a question using the fine-tuned Indic-mALBERT QA model")
    parser.add_argument("--question", type=str, help="Question text (English or Indic languages like Hindi)")
    parser.add_argument("--context", type=str, help="Context text / security report / article snippet")
    parser.add_argument("--download-model", action="store_true", help="Download trained ONNX model from Colab")
    parser.add_argument("--output", type=Path, default=Path("lstm_malware.onnx"), help="Target path for model download")
    parser.add_argument("--mock-server", action="store_true", help="Run local mock Colab server for offline testing")
    parser.add_argument("--dashboard", action="store_true", help="Launch the MalShot Modern Web Console Dashboard in browser")
    parser.add_argument("--port", type=int, default=8088, help="Port for local mock server")

    args = parser.parse_args()

    if args.dashboard:
        import webbrowser
        dashboard_file = Path(__file__).resolve().parent / "dashboard.html"
        print(f"[*] Launching MalShot Web Dashboard: {dashboard_file}")
        webbrowser.open(f"file://{dashboard_file.resolve()}")
        return

    if args.mock_server:
        run_local_mock_colab_server(args.port)
        return

    colab_url = args.url or os.getenv("MALSHOT_COLAB_URL")
    if not colab_url:
        print("[ERROR] Please provide --url or set MALSHOT_COLAB_URL environment variable.")
        sys.exit(1)

    if args.health:
        print(f"[*] Checking Colab GPU health at: {colab_url}")
        res = check_colab_health(colab_url)
        if res["status"] == "ok":
            print("[+] Connection SUCCESSFUL!")
            print(json.dumps(res["data"], indent=2))
        else:
            print(f"[-] Connection FAILED: {res.get('error')}")
            sys.exit(1)

    elif args.scan:
        print(f"[*] Sending {args.scan} to Colab GPU for inference...")
        res = remote_scan_file(colab_url, args.scan)
        if res["status"] == "ok":
            data = res["result"]
            print(f"[+] Scan Result for: {data.get('file_name')}")
            print(f"    Confidence Score : {data.get('confidence_score')}")
            print(f"    Threat Verdict   : {'[ALERT] MALWARE' if data.get('is_threat') else '[CLEAN] SAFE'}")
            print(f"    Inference Time   : {data.get('inference_time_ms')} ms (Roundtrip: {data.get('roundtrip_ms')} ms)")
            print(f"    Compute Device   : {data.get('device')}")
        else:
            print(f"[-] Scan FAILED: {res.get('error')}")
            sys.exit(1)

    elif args.qa:
        if not args.question:
            print("[ERROR] --qa requires --question '<your question>'")
            sys.exit(1)
        context = args.context or "MalShot inspects binary files using LSTM deep learning and YARA signatures to detect malware and threat indicators."
        print(f"[*] Querying Indic-mALBERT QA at: {colab_url}")
        print(f"    Question: {args.question}")
        print(f"    Context : {context[:80]}...")
        res = query_colab_qa(colab_url, args.question, context)
        if res["status"] == "ok":
            data = res["result"]
            inf_time = data.get("inference_time_ms") or data.get("latency_ms") or "N/A"
            model_name = data.get("model") or "rohitsroch/indic-mALBERT-squad-v2 (fine-tuned)"
            print("[+] QA Result:")
            print(f"    Answer         : {data.get('answer')}")
            print(f"    Confidence     : {data.get('confidence')}")
            print(f"    Inference Time : {inf_time} ms (Roundtrip: {data.get('roundtrip_ms')} ms)")
            print(f"    Model          : {model_name}")
        else:
            print(f"[-] QA Query FAILED: {res.get('error')}")
            sys.exit(1)

    elif args.download_model:
        print(f"[*] Downloading ONNX model from Colab to {args.output}...")
        res = download_model_from_colab(colab_url, args.output)
        if res["status"] == "ok":
            print(f"[+] Successfully downloaded {res['bytes_written']} bytes to {res['path']}")
        else:
            print(f"[-] Download FAILED: {res.get('error')}")
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
