package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"onion-finder/internal"
	"onion-finder/internal/scanner"
	"onion-finder/internal/tor"
)

func main() {
	// --- Flags ---
	keepMounted := flag.Bool("keep-mounted", false, "Keep E01 image mounted after scan")
	dismount := flag.Bool("dismount", false, "Dismount last mounted E01 image")
	flag.Parse()

	if *dismount {
		fmt.Println("[*] Dismount requested")

		device, err := internal.GetLastMountedDevice()
		if err != nil {
			fmt.Println("[!] Failed to find mounted device:", err)
			return
		}

		fmt.Println("[*] Dismounting device:", device)

		if err := internal.Dismount(device); err != nil {
			fmt.Println("[!] Failed to dismount device:", err)
			return
		}

		internal.LogDismount(device)
		fmt.Println("[+] Image dismounted successfully")
		return
	}

	// --- Args ---
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [--keep-mounted] <image.E01 | directory>\n", os.Args[0])
		return
	}

	inputPath := flag.Arg(0)

	// --- Resolve absolute path ---
	absPath, err := filepath.Abs(inputPath)
	if err != nil {
		exitError("unable to resolve absolute path", err)
		return
	}

	info, err := os.Stat(absPath)
	if err != nil {
		exitError("path does not exist", err)
		return
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
			return
		}

		fmt.Println("[+] E01 image accepted")
		fmt.Println("    Path:", absPath)

		mount, err := internal.MountE01(absPath)
		if err != nil {
			exitError("failed to mount E01", err)
			return
		}

		fmt.Println("[+] Image mounted")
		fmt.Println("    Mount point :", mount.MountPoint)
		fmt.Println("    Device num  :", mount.DeviceNumber)

		scanRoot = mount.MountPoint
		deviceNumber = mount.DeviceNumber
		mounted = true

		internal.LogMount(absPath, mount.DeviceNumber, mount.MountPoint, *keepMounted)
	}

	// --- Ensure dismount unless --keep-mounted ---
	if mounted && !*keepMounted {
		defer func() {
			fmt.Println("[*] Dismounting image...")
			if err := internal.Dismount(deviceNumber); err != nil {
				fmt.Println("[!] Failed to dismount:", err)
			} else {
				internal.LogDismount(deviceNumber)
				fmt.Println("[+] Image dismounted")
			}
		}()
	} else if mounted && *keepMounted {
		fmt.Println("[!] Image will remain mounted (--keep-mounted enabled)")
	}

	// --- Scan for .onion ---
	fmt.Println("[*] Scanning filesystem for .onion domains...")
	onions, err := scanner.ScanForOnions(scanRoot)
	if err != nil {
		exitError("failed to scan filesystem", err)
		return
	}

	fmt.Printf("[+] Found %d onion(s)\n", len(onions))

	// --- Write report ---
	outputFile := "onion.txt"
	if err := internal.WriteOnionReport(outputFile, onions); err != nil {
		exitError("failed to write onion report", err)
		return
	}

	fmt.Println("[+] Report written:", outputFile)
	fmt.Println("[+] Done.")

	// --- Wait before Tor check ---
	fmt.Println("[*] Waiting 30 seconds before Tor onion availability check...")
	time.Sleep(30 * time.Second)

	// --- Tor availability ---
	fmt.Println("[*] Checking Tor availability...")
	if err := tor.CheckTorAvailable(); err != nil {
		fmt.Println("[!] Tor not available:", err)
		return
	}

	fmt.Println("[+] Tor detected, checking onion services...")

	// --- Onion availability check via Tor ---
	results, err := tor.CheckOnions(outputFile, 443)
	if err != nil {
		fmt.Println("[!] Onion check failed:", err)
		return
	}

	// --- Write results table ---
	resultsFile := "results.txt"
	if err := tor.WriteResultsTable(resultsFile, results); err != nil {
		fmt.Println("[!] Failed to write results:", err)
		return
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
}
