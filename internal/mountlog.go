package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const logDir = "logs"

func getMountLogFile() (string, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", err
	}

	filename := "mount_" + time.Now().Format("20060102") + ".log"
	return filepath.Join(logDir, filename), nil
}

func LogMount(image, device, mountPoint string, keepMounted bool) error {
	logFile, err := getMountLogFile()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now().Format("2006-01-02 15:04:05")

	fmt.Fprintf(f, "[%s]\n", now)
	fmt.Fprintf(f, "Image: %s\n", image)
	fmt.Fprintf(f, "Device: %s\n", device)
	fmt.Fprintf(f, "Mount point: %s\n", mountPoint)

	if keepMounted {
		fmt.Fprintln(f, "[!] Image will remain mounted (--keep-mounted enabled)")
	}

	return nil
}

func LogDismount(device string) error {
	logFile, err := getMountLogFile()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(f, "Image was dismounted : %s\n\n", now)
	return nil
}

func GetLastMountedDevice() (string, error) {
	logFile, err := getMountLogFile()
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")

	var lastDevice string
	var dismounted bool

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Device:") {
			lastDevice = strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			dismounted = false
		}

		if strings.HasPrefix(line, "Image was dismounted") {
			dismounted = true
		}
	}

	if lastDevice == "" {
		return "", fmt.Errorf("no mounted device found in log")
	}

	if dismounted {
		return "", fmt.Errorf("last device already dismounted")
	}

	return lastDevice, nil
}
