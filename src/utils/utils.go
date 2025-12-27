package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func GetCgroupPathsForPid(pid int) []string {
	var paths []string
	file, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return paths
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) == 3 {
			paths = append(paths, parts[2])
		}
	}
	return paths
}
