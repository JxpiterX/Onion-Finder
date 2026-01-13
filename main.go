package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"time"

	"onion-finder/internal"
	"onion-finder/internal/scanner"
	"onion-finder/internal/tor"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <image.E01 | directory>\n", os.Args[0])
		os.Exit(1)
	}

	inputPath := os.Args[1]

	// --- Resolve absolute path ---
	absPath, err := filepath.Abs(inputPath)
	if err != nil {
		exitError("unable to resolve absolute path", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		exitError("path does not exist", err)
	}

	var scanRoot string
	var mounted bool
	var deviceNumber string

	// --- Case 1: directory (test mode) ---
	if info.IsDir() {
		fmt.Println("[!] Directory provided, scanning filesystem directly (test mode)")
		scanRoot = absPath

	} else {
		// --- Case 2: E01 ---
		lower := strings.ToLower(absPath)
		if !strings.HasSuffix(lower, ".e01") {
			exitError("provided file is not an E01 or directory", nil)
		}

		fmt.Println("[+] E01 image accepted")
		fmt.Println("    Path:", absPath)

		mount, err := internal.MountE01(absPath)
		if err != nil {
			exitError("failed to mount E01", err)
		}

		fmt.Println("[+] Image mounted")
		fmt.Println("    Mount point :", mount.MountPoint)
		fmt.Println("    Device num  :", mount.DeviceNumber)

		scanRoot = mount.MountPoint
		deviceNumber = mount.DeviceNumber
		mounted = true
	}

	// --- Ensure dismount if needed ---
	if mounted {
		defer internal.Dismount(deviceNumber)
	}

	// --- Scan for .onion ---
	fmt.Println("[*] Scanning filesystem for .onion domains...")
	onions, err := scanner.ScanForOnions(scanRoot)
	if err != nil {
		exitError("failed to scan filesystem", err)
	}

	fmt.Printf("[+] Found %d onion(s)\n", len(onions))

	// --- Write report ---
	outputFile := "onion.txt"
	err = internal.WriteOnionReport(outputFile, onions)
	if err != nil {
		exitError("failed to write onion report", err)
	}

	fmt.Println("[+] Report written:", outputFile)
	fmt.Println("[+] Done.")

	// --- Wait before Tor check ---
	fmt.Println("[*] Waiting 1 minute before Tor onion availability check...")
	time.Sleep(30 * time.Second)

	// --- Tor availability ---
	fmt.Println("[*] Checking Tor availability...")
	if err := tor.CheckTorAvailable(); err != nil {
		log.Fatalf("[!] Tor not available: %v", err)
	}

	fmt.Println("[+] Tor detected, checking onion services...")

	// --- Onion availability check via Tor ---
	results, err := tor.CheckOnions(outputFile, 443)
	if err != nil {
		log.Fatalf("[!] Onion check failed: %v", err)
	}

	// --- Write results table to file ---
	resultsFile := "results.txt"
	if err := tor.WriteResultsTable(resultsFile, results); err != nil {
		log.Fatalf("[!] Failed to write results: %v", err)
	}

	fmt.Println("[+] Onion availability results written to:", resultsFile)
}

// ---------------- UTILS ----------------
func exitError(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s: %v\n", msg, err)
	} else {
		fmt.Fprintf(os.Stderr, "[-] %s\n", msg)
	}
	os.Exit(1)
}
