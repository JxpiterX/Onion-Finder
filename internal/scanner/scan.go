package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"onion-finder/internal/model"
)

// ChunkSize: size (in bytes) of each block read when scanning large files.
// NumWorkers: number of concurrent goroutines processing files.
// ChunkOverlap: number of bytes reused between chunks to avoid cutting
// onion strings across chunk boundaries.
const (
	ChunkSize    = 1024 * 1024 // 1 MB per chunk
	NumWorkers   = 8           // parallel workers
	ChunkOverlap = 128         // safety overlap between chunks
)

// onionRegex matches Tor v3 onion addresses:
// - base32 charset [a-z2-7]
// - minimum length relaxed to 56+ characters
// - case-insensitive
var onionRegex = regexp.MustCompile(`(?i)[a-z2-7]{56,}\.onion`)

// knownGenericOnions contains well-known public onion services
// that are commonly embedded in browsers, extensions or rule lists.
// These onions are excluded to avoid false positives.
var knownGenericOnions = map[string]bool{
	"duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion": true,
	"reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion": true,
	"facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion": true,
	"archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion": true,
}

// FileJob represents a unit of work processed by a worker.
// Each job corresponds to one file on disk.
type FileJob struct {
	Path string      // full filesystem path
	Info os.FileInfo // file metadata (size, permissions, etc.)
}

// isGenericOnion checks whether an onion address belongs
// to the known public/generic deny-list.
func isGenericOnion(value string) bool {
	value = strings.ToLower(value)
	return knownGenericOnions[value]
}

/*
====================================================
 Exclusion helpers
====================================================
*/

// buildExcludedPaths returns system directories that should
// not be scanned.
func buildExcludedPaths(mountRoot string) []string {
	mountRoot = filepath.Clean(mountRoot)

	return []string{
		filepath.Join(mountRoot, "Windows"),
		filepath.Join(mountRoot, "Program Files"),
		filepath.Join(mountRoot, "Program Files (x86)"),
		filepath.Join(mountRoot, "PerfLogs"),
	}
}

// isExcludedPath checks whether a path is under an excluded directory.
func isExcludedPath(path string, excluded []string) bool {
	path = strings.ToLower(filepath.Clean(path))

	for _, excl := range excluded {
		excl = strings.ToLower(filepath.Clean(excl))
		if strings.HasPrefix(path, excl) {
			return true
		}
	}
	return false
}

/*
====================================================
 File scanning logic
====================================================
*/

// scanFile scans a single file for onion addresses.
// It detects encoding (UTF-16LE vs others) and chooses
// the appropriate scanning strategy.
func scanFile(path string) []model.Onion {
	results := []model.Onion{}
	seen := make(map[string]bool)

	file, err := os.Open(path)
	if err != nil {
		return results
	}
	defer file.Close()

	// Read a small sample to detect encoding
	firstChunk := make([]byte, 4096)
	n, _ := file.Read(firstChunk)
	if n == 0 {
		return results
	}
	file.Seek(0, 0)

	isUTF16LE := detectUTF16LE(firstChunk[:n])

	if isUTF16LE {
		// Decode entire file as UTF-16LE text
		data, err := os.ReadFile(path)
		if err != nil {
			return results
		}

		content := decodeUTF16LE(data)
		matches := onionRegex.FindAllString(content, -1)

		for _, match := range matches {
			value := strings.ToLower(match)

			if isGenericOnion(value) {
				continue
			}

			if !seen[value] {
				seen[value] = true
				results = append(results, model.Onion{
					Value: value,
					Path:  path,
				})
			}
		}
	} else {
		// Binary / large file → chunked scanning
		results = scanFileChunked(file, path)
	}

	return results
}

// scanFileChunked scans files incrementally using overlapping chunks
// to handle large and binary files efficiently.
func scanFileChunked(file *os.File, path string) []model.Onion {
	results := []model.Onion{}
	seen := make(map[string]bool)

	buffer := make([]byte, ChunkSize+ChunkOverlap)
	overlap := make([]byte, 0)

	for {
		n, err := file.Read(buffer[len(overlap):])
		if n == 0 {
			break
		}

		copy(buffer, overlap)
		totalLen := len(overlap) + n

		matches := scanChunk(buffer[:totalLen])
		for _, match := range matches {
			value := strings.ToLower(match)

			if isGenericOnion(value) {
				continue
			}

			if !seen[value] {
				seen[value] = true
				results = append(results, model.Onion{
					Value: value,
					Path:  path,
				})
			}
		}

		if err != nil {
			break
		}

		// Preserve overlap for next chunk
		if totalLen > ChunkOverlap {
			overlap = make([]byte, ChunkOverlap)
			copy(overlap, buffer[totalLen-ChunkOverlap:totalLen])
		}
	}

	return results
}

// scanChunk extracts onion addresses from a raw byte slice.
func scanChunk(data []byte) []string {
	results := []string{}

	// Direct regex on raw bytes
	matches := onionRegex.FindAll(data, -1)
	for _, match := range matches {
		results = append(results, string(match))
	}

	// Extract only valid onion characters (useful for binary blobs)
	cleaned := extractOnionChars(data)
	matches2 := onionRegex.FindAllString(cleaned, -1)
	results = append(results, matches2...)

	return results
}

// extractOnionChars filters a byte stream to retain only characters
// valid in onion addresses, replacing others with separators.
func extractOnionChars(data []byte) string {
	var buf bytes.Buffer
	buf.Grow(len(data) / 2)

	for _, b := range data {
		if b == 0x00 {
			continue
		}

		if isValidOnionChar(b) {
			if b >= 'A' && b <= 'Z' {
				b += 32 // normalize to lowercase
			}
			buf.WriteByte(b)
		} else {
			if buf.Len() > 0 && buf.Bytes()[buf.Len()-1] != ' ' {
				buf.WriteByte(' ')
			}
		}
	}

	return buf.String()
}

// isValidOnionChar checks if a byte belongs to the onion charset.
func isValidOnionChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '2' && b <= '7') ||
		b == '.'
}

// detectUTF16LE heuristically detects UTF-16LE encoding.
func detectUTF16LE(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// BOM check
	if data[0] == 0xFF && data[1] == 0xFE {
		return true
	}

	// Heuristic: many null bytes in odd positions
	nullCount := 0
	sampleSize := min(len(data), 200)
	for i := 1; i < sampleSize; i += 2 {
		if data[i] == 0x00 {
			nullCount++
		}
	}

	return nullCount > sampleSize/4
}

// decodeUTF16LE decodes UTF-16LE byte data into a UTF-8 Go string.
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	start := 0
	if data[0] == 0xFF && data[1] == 0xFE {
		start = 2
	}

	if (len(data)-start)%2 != 0 {
		data = data[:len(data)-1]
	}

	u16 := make([]uint16, (len(data)-start)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(data[start+i*2]) |
			uint16(data[start+i*2+1])<<8
	}

	return string(utf16.Decode(u16))
}

/*
====================================================
 Main scanning pipeline
====================================================
*/

// ScanForOnions scans a mounted filesystem and extracts Tor .onion
// addresses using a worker pool.
//
// High-level flow:
// 1. Walk the filesystem
// 2. Send files to a job channel
// 3. Workers scan files in parallel
// 4. Results are deduplicated and collected safely
func ScanForOnions(root string) ([]model.Onion, error) {

	// Final results slice (shared between workers)
	results := []model.Onion{}

	// Mutex protecting concurrent access to results + seen map
	resultsMux := sync.Mutex{}

	// Global deduplication map: onion_value|path
	seen := make(map[string]bool)

	// Buffered channel used as a job queue
	jobs := make(chan FileJob, 100)

	// WaitGroup used to wait for all workers to finish
	wg := sync.WaitGroup{}

	// Build exclusion list (system directories, not relevant for DFIR)
	excluded := buildExcludedPaths(root)

	// Atomic counter for progress reporting
	var filesProcessed uint64
	start := time.Now()

	/*
		----------------------------------------------------
		 Progress reporting goroutine
		----------------------------------------------------
	*/
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				resultsMux.Lock()
				onionCount := len(results)
				resultsMux.Unlock()

				fmt.Printf(
					"[*] Scanning... files processed: %d | onions found: %d | elapsed: %s\n",
					atomic.LoadUint64(&filesProcessed),
					onionCount,
					time.Since(start).Truncate(time.Minute),
				)

			case <-done:
				return
			}
		}
	}()

	/*
		----------------------------------------------------
		 Worker pool
		----------------------------------------------------
	*/
	for i := 0; i < NumWorkers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			// Each worker continuously reads from the job channel
			for job := range jobs {

				// Scan one file for onion addresses
				onions := scanFile(job.Path)

				// Increment processed file counter atomically
				atomic.AddUint64(&filesProcessed, 1)

				// Merge results safely
				resultsMux.Lock()
				for _, onion := range onions {
					key := onion.Value + "|" + onion.Path
					if !seen[key] {
						seen[key] = true
						results = append(results, onion)
					}
				}
				resultsMux.Unlock()
			}
		}()
	}

	/*
		----------------------------------------------------
		 Filesystem traversal
		----------------------------------------------------
	*/
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Skip excluded directories
		if isExcludedPath(path, excluded) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Detect onion addresses in filenames
		filename := filepath.Base(path)
		matches := onionRegex.FindAllString(filename, -1)
		if len(matches) > 0 {
			resultsMux.Lock()
			for _, match := range matches {
				value := strings.ToLower(match)

				if isGenericOnion(value) {
					continue
				}

				key := value + "|" + path
				if !seen[key] {
					seen[key] = true
					results = append(results, model.Onion{
						Value: value,
						Path:  path,
					})
				}
			}
			resultsMux.Unlock()
		}

		// Do not send directories to workers
		if d.IsDir() {
			return nil
		}

		// Skip very large files (>500MB) ???
		info, err := d.Info()
		if err != nil || info.Size() > 500*1024*1024 {
			return nil
		}

		// Send file to worker pool
		jobs <- FileJob{Path: path, Info: info}
		return nil
	})

	// Close job channel and wait for workers
	close(jobs)
	wg.Wait()

	// Stop progress goroutine
	close(done)

	fmt.Printf(
		"[+] Scan finished: %d files processed | %d onions found | total time: %s\n",
		filesProcessed,
		len(results),
		time.Since(start).Truncate(time.Minute),
	)

	return results, err
}
