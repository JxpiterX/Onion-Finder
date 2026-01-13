package internal

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const aimCliPath = `C:\Program Files\Arsenal-Image-Mounter-v3.12.331\Arsenal-Image-Mounter-v3.12.331\aim_cli.exe`

type MountResult struct {
	MountPoint   string
	DeviceNumber string
}

// MountE01 mounts an E01 image using Arsenal Image Mounter CLI
func MountE01(imagePath string) (*MountResult, error) {
	cmd := exec.Command(
		aimCliPath,
		"--mount",
		"--filename="+imagePath,
		"--provider=LibEwf",
		"--readonly",
		"--background",
	)

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	time.Sleep(2 * time.Second)

	return getMountedDiskInfo()
}

// Dismount unmounts a previously mounted image using its device number
func Dismount(deviceNumber string) error {
	cmd := exec.Command(
		aimCliPath,
		"--dismount="+deviceNumber,
	)
	return cmd.Run()
}

func getMountedDiskInfo() (*MountResult, error) {
	cmd := exec.Command(aimCliPath, "--list")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")

	var mountPoint string
	var deviceNumber string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Device number") {
			fields := strings.Fields(line)
			deviceNumber = fields[len(fields)-1]
		}

		if strings.Contains(line, "Mounted at") {
			fields := strings.Fields(line)
			mountPoint = fields[len(fields)-1]
		}
	}

	if mountPoint == "" || deviceNumber == "" {
		return nil, fmt.Errorf("failed to retrieve mount point or device number from AIM")
	}

	return &MountResult{
		MountPoint:   mountPoint,
		DeviceNumber: deviceNumber,
	}, nil
}
