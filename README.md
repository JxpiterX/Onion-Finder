# Onion Finder

Onion Finder is a **digital forensics tool for Windows** designed to scan disk images or mounted filesystems  
in order to detect **Tor v3 `.onion` addresses**.

The tool relies on two key dependencies:
- **Arsenal Image Mounter (AIM)**
- **Tor Browser**

AIM is used to mount E01 forensic disk images in **read-only mode**, preserving forensic integrity.  
Tor Browser is leveraged to check the availability of discovered `.onion` services **anonymously**, without exposing the investigator’s identity.

This tool is intended for DFIR analysts investigating:
- Dark web usage
- Malware artifacts
- OSINT or cybercrime cases


## Features

- Mount E01 forensic images (read-only)
- Recursively scan filesystems
- Detect Tor v3 `.onion` addresses
- Extract full paths of occurrences
- Tor availability check
- Upcoming : Retrieve HTTP headers to analyze service content
- Generate forensic reports


## Architecture

The project follows a clean internal architecture:
```bash
onion-finder/
├── .gitignore            # Git ignore rules
├── go.mod                # Go module definition
├── go.sum                # Go dependencies checksums
├── LICENSE               # Apache 2.0 license
├── main.go               # Entry point
├── onion.txt             # input file (onion list generated)
├── README.md             # Project documentation
├── results.txt           # Analysis results (generated output)
│
└── internal/              # Internal application packages
    ├── aim.go             # Disk image mounting with Arsenal Mounter Imager
    ├── report.go          # Onion report generation (onion.txt)
    │
    ├── model/
    │   └── model.go       # Core data structures (Onion, Result, Status)
    │
    ├── scanner/
    │   └── scan.go        # Filesystem scan & onion extraction
    │
    └── tor/
        └── tor.go         # Tor availability & onion reachability checks
```


> All generated artifacts (`results.txt`, `onion.txt`) are excluded from version control via `.gitignore`.


## Installation

### Requirements

The following components are required to run Onion Finder:

- **Go >= 1.21**
- **Arsenal Image Mounter (AIM)**
- **Tor Browser**
- **Windows Administrator privileges** (required for disk image mounting)


### I. Install Go

Go is required to build and run the tool.

1. Download Go for windows : https://go.dev/dl/go1.25.5.windows-amd64.msi
2. Install it using the default settings.
3. Verify the installation:
```bash
go version
```
Make sure the reported version is 1.21 or higher.··


### II. Install Arsenal Image Mounter (AIM)

Arsenal Image Mounter is used to mount E01 forensic disk images in read-only mode.

1. Download Arsenal Image Mounter from the official Arsenal Recon website : https://arsenalrecon.com/downloads
2. Install the application.
3. Ensure the aim_cli.exe binary is accessible from the system PATH, or located in a known directory.

Administrator privileges are required for disk mounting operations.··


### III. Install Tor Browser 

Tor Browser is required to anonymously check the availability of detected `.onion` services.

1. Download Tor Browser from the official Tor Project website : https://www.torproject.org/download
2. Install Tor Browser using the default configuration.
3. Launch Tor Browser at least once to complete the initial setup and ensure the Tor service can start correctly.

The tool relies on the local Tor service provided by Tor Browser to perform availability checks.··


### IV. Build the Tool

Clone the repository and build the binary:
```bash
git clone https://github.com/yourusername/onion-finder.git
cd onion-finder
go build
```
Run the executable as Administrator to allow disk image mounting.

