package tor

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type Onion struct {
	Value string
	Path  string
}

type OnionStatus string

const (
	OnionUp      OnionStatus = "UP"
	OnionDown    OnionStatus = "DOWN"
	OnionUnknown OnionStatus = "UNKNOWN"
)

type Result struct {
	Onion  Onion
	Status OnionStatus
	Error  string
}

// Default Tor Browser SOCKS proxy
const torSocksAddr = "127.0.0.1:9150"

func statusText(status OnionStatus) string {
	return string(status)
}

func line(w int) string {
	return strings.Repeat("-", w)
}

func computeColumnWidths(results []Result) (linkW, pathW, statusW int) {
	linkW = len("Link")
	pathW = len("Path")
	statusW = len("Status")

	for _, r := range results {
		if len(r.Onion.Value) > linkW {
			linkW = len(r.Onion.Value)
		}
		if len(r.Onion.Path) > pathW {
			pathW = len(r.Onion.Path)
		}
		if len(statusText(r.Status)) > statusW {
			statusW = len(statusText(r.Status))
		}
	}
	return
}

// CheckTorAvailable verifies that Tor SOCKS proxy is reachable
func CheckTorAvailable() error {
	conn, err := net.DialTimeout("tcp", torSocksAddr, 3*time.Second)
	if err != nil {
		return errors.New("Tor SOCKS proxy not reachable (is Tor Browser running?)")
	}
	_ = conn.Close()
	return nil
}

// ParseOnionFile reads onion_full.txt and returns onions
func ParseOnionFile(path string) ([]Onion, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var onions []Onion
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.Contains(line, "|") {
			continue
		}

		parts := strings.SplitN(line, "|", 2)
		onions = append(onions, Onion{
			Value: strings.TrimSpace(parts[0]),
			Path:  strings.TrimSpace(parts[1]),
		})
	}

	return onions, scanner.Err()
}

// CheckOnionTCP checks onion availability via TCP using Tor
func CheckOnionTCP(onion Onion, port int) Result {
	netDialer := &net.Dialer{
		Timeout: 15 * time.Second,
	}

	dialer, err := proxy.SOCKS5("tcp", torSocksAddr, nil, netDialer)
	if err != nil {
		return Result{Onion: onion, Status: OnionUnknown, Error: err.Error()}
	}

	address := fmt.Sprintf("%s:%d", onion.Value, port)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return Result{Onion: onion, Status: OnionDown}
		}
		return Result{Onion: onion, Status: OnionUnknown, Error: err.Error()}
	}

	_ = conn.Close()
	return Result{Onion: onion, Status: OnionUp}
}

// CheckOnions checks all onions from a file
func CheckOnions(onionFile string, port int) ([]Result, error) {
	if err := CheckTorAvailable(); err != nil {
		return nil, err
	}

	onions, err := ParseOnionFile(onionFile)
	if err != nil {
		return nil, err
	}

	results := make([]Result, 0, len(onions))
	for _, onion := range onions {
		results = append(results, CheckOnionTCP(onion, port))
	}

	return results, nil
}

func WriteResultsTable(path string, results []Result) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)

	linkW, pathW, statusW := computeColumnWidths(results)

	fmt.Fprintf(w, "+-%s-+-%s-+-%s-+\n", line(linkW), line(pathW), line(statusW))
	fmt.Fprintf(w, "| %-*s | %-*s | %-*s |\n", linkW, "Link", pathW, "Path", statusW, "Status")
	fmt.Fprintf(w, "+-%s-+-%s-+-%s-+\n", line(linkW), line(pathW), line(statusW))

	for _, r := range results {
		fmt.Fprintf(
			w,
			"| %-*s | %-*s | %-*s |\n",
			linkW, r.Onion.Value,
			pathW, r.Onion.Path,
			statusW, statusText(r.Status),
		)
	}

	fmt.Fprintf(w, "+-%s-+-%s-+-%s-+\n", line(linkW), line(pathW), line(statusW))

	return w.Flush()
}
