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

