package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

// loadConfig reads a configuration file in "key = value" format and sets the
// corresponding flags via flag.Set. Lines starting with '#' and blank lines are
// ignored. loadConfig must be called before flag.Parse so that command-line
// flags can still override the file values.
func loadConfig(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected key=value, got %q", filename, lineNum, line)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if err := flag.Set(k, v); err != nil {
			return fmt.Errorf("%s:%d: setting %s: %v", filename, lineNum, k, err)
		}
	}
	return scanner.Err()
}
