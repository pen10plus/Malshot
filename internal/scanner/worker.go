package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

func worker(jobs <-chan FileJob, db *Database, deep *deepBackend, deepEnabled bool, threshold float32, emit func(string, int64, bool, *DetectedFile), failed func(), checkPause func(context.Context) error, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		if checkPause != nil {
			if err := checkPause(ctx); err != nil {
				break
			}
		}
		threat, detected, err := scanFile(job, db, deep, deepEnabled, threshold)
		if err != nil {
			log.Printf("[WARN] cannot scan %q: %v", job.Path, err)
			failed()
			continue
		}
		emit(job.Path, job.Size, threat, detected)
	}
}

func scanFile(job FileJob, db *Database, deep *deepBackend, deepEnabled bool, threshold float32) (bool, *DetectedFile, error) {
	hash, err := hashFile(job.Path)
	if err != nil {
		return false, nil, fmt.Errorf("hash file: %w", err)
	}
	threat, threatName, err := db.CheckHash(hash)
	if err != nil {
		return false, nil, err
	}
	var detected *DetectedFile
	status := "clean"
	if threat {
		status = "threat"
		detected = &DetectedFile{
			Path:            job.Path,
			ThreatName:      threatName,
			DetectionSource: "SHA-256 Signature Match",
			Size:            job.Size,
			Timestamp:       time.Now().Unix(),
		}
		fmt.Printf("[ALERT] THREAT DETECTED: %s | Threat: %s\n", job.Path, threatName)
	} else if deepEnabled && deep != nil {
		yaraThreat, score, deepErr := deep.scan(job.Path)
		if deepErr != nil {
			log.Printf("[WARN] deep inspection for %q: %v", job.Path, deepErr)
		} else if yaraThreat || score >= threshold {
			threat = true
			status = "threat"
			source := "YARA Heuristic Match"
			name := "Heuristic.YARA.Threat"
			if yaraThreat && score >= threshold {
				source = "YARA + ONNX LSTM"
				name = fmt.Sprintf("Deep.Threat.Hybrid (score: %.3f)", score)
			} else if score >= threshold {
				source = "ONNX LSTM Inference"
				name = fmt.Sprintf("ML.ZeroDay.LSTM (score: %.3f)", score)
			}
			detected = &DetectedFile{
				Path:            job.Path,
				ThreatName:      name,
				DetectionSource: source,
				Score:           score,
				Size:            job.Size,
				Timestamp:       time.Now().Unix(),
			}
			fmt.Printf("[ALERT] DEEP THREAT DETECTED: %s | %s | score %.4f\n", job.Path, source, score)
		}
	}

	if !threat {
		fmt.Printf("[CLEAN] %s\n", job.Path)
	}

	latest, err := os.Stat(job.Path)
	if err != nil {
		return threat, detected, fmt.Errorf("verify file after hashing: %w", err)
	}
	if latest.ModTime().UnixNano() == job.MTime && latest.Size() == job.Size {
		if !threat {
			if err := db.UpdateCache(job.Path, job.MTime, job.Size, hash, status); err != nil {
				return threat, detected, err
			}
		}
	} else {
		log.Printf("[WARN] %q changed while hashing; result not cached", job.Path)
	}
	return threat, detected, nil
}

