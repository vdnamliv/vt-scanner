package collector

import (
	"os/exec"
	"strings"
	"fmt"
)

func CollectWindows(rule map[string]string) string {
	qtype := strings.ToLower(rule["type"])
	if qtype == "powershell" {
		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
			fmt.Sprintf("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='SilentlyContinue'; %s", rule["cmd"]))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	if qtype == "cmd" {
		cmd := exec.Command("cmd", "/C", rule["cmd"])
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	return "ERROR: unsupported query.type (expected powershell/cmd)"
}