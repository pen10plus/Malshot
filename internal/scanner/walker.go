package scanner

import (
	"context"
	"io/fs"
	"log"
	"path/filepath"
	"sync"
)

// FileJob contains the file metadata captured before hashing.
type FileJob struct {
	Path  string
	Size  int64
	MTime int64
}

// StartScan walks rootPath and sends uncached regular files to fileChan.
// The caller owns fileChan and must close it after this function returns.
func (d *Database) StartScan(ctx context.Context, rootPath string, fileChan chan<- FileJob, wg *sync.WaitGroup) {
	d.startScan(ctx, rootPath, fileChan, wg, nil, nil, nil)
}

func (d *Database) startScan(ctx context.Context, rootPath string, fileChan chan<- FileJob, wg *sync.WaitGroup, onDiscovered, onSkipped func(), pauseCheck func(context.Context) error) {
	wg.Add(1)
	defer wg.Done()
	if err := d.walkFiles(ctx, rootPath, fileChan, onDiscovered, onSkipped, pauseCheck); err != nil && ctx.Err() == nil {
		log.Printf("[WARN] directory walk failed: %v", err)
	}
}

func (d *Database) walkFiles(ctx context.Context, root string, files chan<- FileJob, onDiscovered, onSkipped func(), pauseCheck func(context.Context) error) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if pauseCheck != nil {
			if err := pauseCheck(ctx); err != nil {
				return err
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			log.Printf("[WARN] cannot access %q: %v", path, walkErr)
			if entry == nil || entry.IsDir() {
				return nil
			}
			return nil
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			log.Printf("[WARN] cannot inspect %q: %v", path, err)
			return nil
		}
		mtime := info.ModTime().UnixNano()
		size := info.Size()
		if onDiscovered != nil {
			onDiscovered()
		}
		cached, err := d.CheckCache(path, mtime, size)
		if err != nil {
			log.Printf("[WARN] cache lookup for %q: %v", path, err)
			return nil
		}
		if cached {
			log.Printf("[SKIPPED] %s", path)
			if onSkipped != nil {
				onSkipped()
			}
			return nil
		}
		select {
		case files <- FileJob{Path: path, MTime: mtime, Size: size}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}
