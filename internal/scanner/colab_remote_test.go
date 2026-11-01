package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestColabRemoteScanAndHealth(t *testing.T) {
	// Create mock Colab HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(colabHealthResp{
				Status:        "healthy",
				Backend:       "Google Colab GPU",
				Device:        "Tesla T4",
				VramGb:        15.1,
				CudaAvailable: true,
			})
		case "/scan":
			var req colabScanReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if len(req.Bytes) != 4096 {
				http.Error(w, "expected 4096 bytes", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(colabScanResp{
				FileName:        req.FileName,
				ConfidenceScore: 0.942,
				IsThreat:        true,
				InferenceTimeMs: 1.15,
				Device:          "cuda:0",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// 1. Test Health Check
	meta, err := CheckColabHealth(server.URL)
	if err != nil {
		t.Fatalf("CheckColabHealth failed: %v", err)
	}
	if meta != "Google Colab GPU (Tesla T4, 15.1 GB vRAM)" {
		t.Fatalf("unexpected health meta: %s", meta)
	}

	// 2. Test Scan
	tmpDir := t.TempDir()
	sampleFile := filepath.Join(tmpDir, "sample_colab.bin")
	if err := os.WriteFile(sampleFile, []byte("MALSHOT_COLAB_TEST_BYTES"), 0600); err != nil {
		t.Fatal(err)
	}

	score, err := ScanWithColab(sampleFile, server.URL)
	if err != nil {
		t.Fatalf("ScanWithColab failed: %v", err)
	}
	if score != 0.942 {
		t.Fatalf("expected score 0.942, got %f", score)
	}
}
