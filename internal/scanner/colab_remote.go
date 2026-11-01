package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const colabSequenceLength = 4096

type colabScanReq struct {
	Bytes    []float32 `json:"bytes"`
	FileName string    `json:"file_name"`
}

type colabScanResp struct {
	FileName        string  `json:"file_name"`
	ConfidenceScore float32 `json:"confidence_score"`
	IsThreat        bool    `json:"is_threat"`
	InferenceTimeMs float64 `json:"inference_time_ms"`
	Device          string  `json:"device"`
}

type colabHealthResp struct {
	Status        string  `json:"status"`
	Backend       string  `json:"backend"`
	Device        string  `json:"device"`
	VramGb        float64 `json:"vram_gb"`
	CudaAvailable bool    `json:"cuda_available"`
}

// ScanWithColab reads the first 4096 bytes and sends them to a Google Colab GPU endpoint.
func ScanWithColab(filePath string, colabURL string) (float32, error) {
	if colabURL == "" {
		return 0, errors.New("Colab URL is empty")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("open file for Colab scan: %w", err)
	}
	defer file.Close()

	opcodes := make([]float32, colabSequenceLength)
	for i := range opcodes {
		var b [1]byte
		if _, err := file.Read(b[:]); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return 0, fmt.Errorf("read file for Colab scan: %w", err)
		}
		opcodes[i] = float32(b[0]) / 255.0
	}

	payload, err := json.Marshal(colabScanReq{
		Bytes:    opcodes,
		FileName: filepath.Base(filePath),
	})
	if err != nil {
		return 0, fmt.Errorf("marshal Colab request: %w", err)
	}

	targetURL := strings.TrimRight(colabURL, "/") + "/scan"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(targetURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("connect to Colab GPU: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Colab GPU returned HTTP status %d", resp.StatusCode)
	}

	var result colabScanResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode Colab response: %w", err)
	}

	fmt.Printf("[Colab-GPU] Score for %s: %.4f (device: %s, infer: %.2fms)\n",
		filePath, result.ConfidenceScore, result.Device, result.InferenceTimeMs)
	return result.ConfidenceScore, nil
}

// CheckColabHealth verifies connectivity and returns metadata from the remote Google Colab GPU.
func CheckColabHealth(colabURL string) (string, error) {
	if colabURL == "" {
		return "", errors.New("Colab URL is empty")
	}
	targetURL := strings.TrimRight(colabURL, "/") + "/health"
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return "", fmt.Errorf("reach Colab: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Colab returned HTTP status %d", resp.StatusCode)
	}

	var health colabHealthResp
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return "", fmt.Errorf("parse Colab health: %w", err)
	}

	return fmt.Sprintf("%s (%s, %.1f GB vRAM)", health.Backend, health.Device, health.VramGb), nil
}
