package collector

import (
	"os/exec"
	"strings"
	"fmt"
)

func CollectLinux(rule map[string]string) string {
	qtype := strings.ToLower(rule["type"])
	if qtype == "bash" || qtype == "sh" || qtype == "shell" {
		cmd := exec.Command("bash", "-c", rule["cmd"])
		cmd.Env = append(cmd.Env, "LC_ALL=C.UTF-8")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	return "ERROR: unsupported query.type (expected bash/sh)"
}