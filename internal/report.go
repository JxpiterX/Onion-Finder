package internal

import (
	"bufio"
	"fmt"
	"os"

	"onion-finder/internal/model"
)

func WriteOnionReport(filename string, onions []model.Onion) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, o := range onions {
		line := fmt.Sprintf("%s | %s\n", o.Value, o.Path)
		if _, err := writer.WriteString(line); err != nil {
			return err
		}
	}

	return nil
}
