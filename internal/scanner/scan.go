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

// ChunkSize: size (in bytes) of each block read when scanning large files
// NumWorkers: number of concurrent goroutines processing files. Set to 16 based on Arsenal Image Mounter decompression thread limits
// ChunkOverlap: number of bytes reused between chunks to avoid cutting onion strings across chunk boundaries
const (
	ChunkSize    = 1024 * 1024 // 1 MB per chunk
	NumWorkers   = 16          // parallel workers (optimal for E01 decompression)
	ChunkOverlap = 128         // safety overlap between chunks
)

var activeWorkers int32
var maxActiveWorkers int32

// onionRegex matches Tor v3 onion addresses
var onionRegex = regexp.MustCompile(`(?i)[a-z2-7]{56,}\.onion`)

// These onions are excluded to avoid false positives in forensic analysis
var knownGenericOnions = map[string]bool{
	"duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion": true,
	"reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion": true,
	"facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion": true,
	"archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion": true,
}

// FileJob represents a unit of work processed by a worker
// Each job corresponds to one file on disk that needs to be scanned
type FileJob struct {
	Path string      // full filesystem path to the file
	Info os.FileInfo // file metadata (size, permissions, modification time, etc)
}

// isGenericOnion checks whether an onion address belongs to the known public/generic deny-list
func isGenericOnion(value string) bool {
	value = strings.ToLower(value)
	return knownGenericOnions[value]
}

// updateMax updates the maximum value reached by activeWorkers
func updateMax(current int32) {
	for {
		old := atomic.LoadInt32(&maxActiveWorkers)
		if current <= old {
			return
		}
		if atomic.CompareAndSwapInt32(&maxActiveWorkers, old, current) {
			return
		}
	}
}

/*
====================================================
 Exclusion helpers
====================================================
*/

// buildExcludedPaths returns system directories that should not be scanned during forensic analysis
// These directories typically contain OS files with no user activity
func buildExcludedPaths(mountRoot string) []string {
	mountRoot = filepath.Clean(mountRoot)

	return []string{
		filepath.Join(mountRoot, "Windows"),
		filepath.Join(mountRoot, "Program Files"),
		filepath.Join(mountRoot, "Program Files (x86)"),
		filepath.Join(mountRoot, "PerfLogs"),
	}
}

// isExcludedPath checks whether a path is under an excluded directory
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
// the appropriate scanning strategy to avoid missing matches.
func scanFile(path string) []model.Onion {
	results := []model.Onion{}
	seen := make(map[string]bool) // local deduplication within this file

	file, err := os.Open(path)
	if err != nil {
		return results // silently skip unreadable files
	}
	defer file.Close()

	// Read a small sample to detect encoding
	firstChunk := make([]byte, 4096)
	n, _ := file.Read(firstChunk)
	if n == 0 {
		return results // empty file
	}
	file.Seek(0, 0) // reset to beginning

	isUTF16LE := detectUTF16LE(firstChunk[:n])

	if isUTF16LE {
		// UTF-16LE text file: decode entire file and search as string
		data, err := os.ReadFile(path)
		if err != nil {
			return results
		}

		content := decodeUTF16LE(data)
		matches := onionRegex.FindAllString(content, -1)

		for _, match := range matches {
			value := strings.ToLower(match)

			if isGenericOnion(value) {
				continue // skip known generic onions
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
		// Binary or large file → use chunked scanning with overlap
		results = scanFileChunked(file, path)
	}

	return results
}

// scanFileChunked scans files incrementally using overlapping chunks
// to handle large and binary files efficiently without loading entire file in memory.
// Overlap prevents splitting onion addresses across chunk boundaries.
func scanFileChunked(file *os.File, path string) []model.Onion {
	results := []model.Onion{}
	seen := make(map[string]bool)

	buffer := make([]byte, ChunkSize+ChunkOverlap)
	overlap := make([]byte, 0)

	for {
		// Read next chunk, appending after overlap bytes
		n, err := file.Read(buffer[len(overlap):])
		if n == 0 {
			break // end of file
		}

		// Prepend overlap from previous chunk
		copy(buffer, overlap)
		totalLen := len(overlap) + n

		// Scan this chunk for onion addresses
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
			break // read error or EOF
		}

		// Preserve overlap for next chunk to avoid splitting onion addresses
		if totalLen > ChunkOverlap {
			overlap = make([]byte, ChunkOverlap)
			copy(overlap, buffer[totalLen-ChunkOverlap:totalLen])
		}
	}

	return results
}

// scanChunk extracts onion addresses from a raw byte slice.
// Uses two strategies:
// 1. Direct regex on raw bytes (catches clean text)
// 2. Extract valid onion chars only, then regex (catches binary-embedded onions)
func scanChunk(data []byte) []string {
	results := []string{}

	// Strategy 1: Direct regex on raw bytes
	matches := onionRegex.FindAll(data, -1)
	for _, match := range matches {
		results = append(results, string(match))
	}

	// Strategy 2: Extract only valid onion characters (useful for binary blobs)
	cleaned := extractOnionChars(data)
	matches2 := onionRegex.FindAllString(cleaned, -1)
	results = append(results, matches2...)

	return results
}

// extractOnionChars filters a byte stream to retain only characters
// valid in onion addresses ([a-z2-7.]), replacing others with spaces.
// This helps extract onions embedded in binary data or mixed encodings.
func extractOnionChars(data []byte) string {
	var buf bytes.Buffer
	buf.Grow(len(data) / 2) // preallocate buffer

	for _, b := range data {
		if b == 0x00 {
			continue // skip null bytes
		}

		if isValidOnionChar(b) {
			// Normalize uppercase to lowercase
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			buf.WriteByte(b)
		} else {
			// Replace invalid chars with space (word separator)
			if buf.Len() > 0 && buf.Bytes()[buf.Len()-1] != ' ' {
				buf.WriteByte(' ')
			}
		}
	}

	return buf.String()
}

// isValidOnionChar checks if a byte belongs to the onion charset:
// base32 ([a-z2-7]) or dot (.)
func isValidOnionChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '2' && b <= '7') ||
		b == '.'
}

// detectUTF16LE heuristically detects UTF-16LE encoding.
// Uses two methods:
// 1. Check for UTF-16LE BOM (0xFF 0xFE)
// 2. Heuristic: many null bytes in odd positions (typical of ASCII in UTF-16LE)
func detectUTF16LE(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// Check for BOM (Byte Order Mark)
	if data[0] == 0xFF && data[1] == 0xFE {
		return true
	}

	// Heuristic: UTF-16LE has nulls in odd byte positions for ASCII text
	nullCount := 0
	sampleSize := min(len(data), 200)
	for i := 1; i < sampleSize; i += 2 {
		if data[i] == 0x00 {
			nullCount++
		}
	}

	// If >25% of odd bytes are null, likely UTF-16LE
	return nullCount > sampleSize/4
}

// decodeUTF16LE decodes UTF-16LE byte data into a UTF-8 Go string.
// Handles BOM if present and ensures even byte count.
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	start := 0
	// Skip BOM if present
	if data[0] == 0xFF && data[1] == 0xFE {
		start = 2
	}

	// Ensure even byte count (UTF-16 uses 2 bytes per character)
	if (len(data)-start)%2 != 0 {
		data = data[:len(data)-1]
	}

	// Convert bytes to uint16 slice (little-endian)
	u16 := make([]uint16, (len(data)-start)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(data[start+i*2]) |
			uint16(data[start+i*2+1])<<8
	}

	// Decode UTF-16 to UTF-8 string
	return string(utf16.Decode(u16))
}

/*
====================================================
 Main scanning pipeline
====================================================
*/

// ScanForOnions scans a mounted filesystem and extracts Tor .onion
// addresses using a worker pool architecture.
//
// High-level flow:
// 1. Walk the filesystem (main goroutine)
// 2. Send files to a buffered job channel
// 3. Workers pull jobs from channel and scan files in parallel
// 4. Results are deduplicated and collected safely with mutex
// 5. Progress is reported every minute
//
// Concurrency design:
// - NumWorkers goroutines scan files in parallel
// - Buffered channel (100 jobs) prevents blocking filesystem walk
// - Mutex protects shared results slice and deduplication map
// - Atomic counter tracks files processed across workers
func ScanForOnions(root string) ([]model.Onion, error) {

	// Final results slice (shared between workers, protected by mutex)
	results := []model.Onion{}

	// Mutex protecting concurrent access to results + seen map
	resultsMux := sync.Mutex{}

	// Global deduplication map: key format = "onion_value|path"
	// Allows same onion in different files but deduplicates within same file
	seen := make(map[string]bool)

	// Buffered channel used as a job queue (100 jobs buffer)
	// Buffer size prevents filesystem walker from blocking on worker availability
	jobs := make(chan FileJob, 100)

	// WaitGroup used to wait for all workers to finish processing
	wg := sync.WaitGroup{}

	// Build exclusion list (system directories not relevant for forensic analysis)
	excluded := buildExcludedPaths(root)

	// Atomic counter for progress reporting (thread-safe increment)
	var filesProcessed uint64
	start := time.Now()

	/*
		----------------------------------------------------
		 Progress reporting goroutine
		----------------------------------------------------
		Prints scan progress every minute without blocking workers
	*/
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Safely read current progress
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
				return // stop when scanning is complete
			}
		}
	}()

	/*
		----------------------------------------------------
		 Worker pool
		----------------------------------------------------
		NumWorkers goroutines process files concurrently
	*/
	for i := 0; i < NumWorkers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			// Each worker continuously reads from the job channel until it's closed
			for job := range jobs {

				// ---- Worker activity tracking (DEBUG) ----
				current := atomic.AddInt32(&activeWorkers, 1)
				updateMax(current)

				// Scan one file for onion addresses
				onions := scanFile(job.Path)

				// File processed
				atomic.AddUint64(&filesProcessed, 1)

				// Merge results
				resultsMux.Lock()
				for _, onion := range onions {
					key := onion.Value + "|" + onion.Path
					if !seen[key] {
						seen[key] = true
						results = append(results, onion)
					}
				}
				resultsMux.Unlock()

				// ---- Worker done (DEBUG) ----
				atomic.AddInt32(&activeWorkers, -1)
			}
		}()
	}

	/*
		----------------------------------------------------
		 Filesystem traversal
		----------------------------------------------------
		Main goroutine walks filesystem and dispatches files to workers
	*/
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}

		// Skip excluded directories (Windows system folders)
		if isExcludedPath(path, excluded) {
			if d.IsDir() {
				return filepath.SkipDir // don't recurse into excluded dirs
			}
			return nil
		}

		// Detect onion addresses in filenames themselves
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

		// Do not send directories to workers (only files)
		if d.IsDir() {
			return nil
		}

		// Skip very large files (>500MB) to avoid excessive processing time
		info, err := d.Info()
		if err != nil || info.Size() > 500*1024*1024 {
			return nil
		}

		// Send file to worker pool via job channel
		jobs <- FileJob{Path: path, Info: info}
		return nil
	})

	// Close job channel to signal workers that no more jobs are coming
	close(jobs)

	// Wait for all workers to finish processing remaining jobs
	wg.Wait()

	// Stop progress reporting goroutine
	close(done)

	// Print final summary
	fmt.Printf(
		"[+] Scan finished: %d files processed | %d onions found | total time: %s\n",
		filesProcessed,
		len(results),
		time.Since(start).Truncate(time.Minute),
	)

	fmt.Printf(
		"[DEBUG] Max concurrent workers used: %d / %d\n",
		maxActiveWorkers,
		NumWorkers,
	)

	return results, err
}
