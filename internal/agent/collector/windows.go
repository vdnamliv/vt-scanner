package collector

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// CollectWindows dispatch theo query.type
func CollectWindows(rule map[string]string) string {
	qtype := strings.ToLower(rule["type"])
	switch qtype {
	case "powershell":
		return runPowerShell(rule["cmd"])
	case "cmd":
		return runCmd(rule["cmd"])
	case "service":
		return collectService(rule)
	case "registry":
		return collectRegistry(rule)
	case "process":
		return collectProcess(rule)
	default:
		return "ERROR: unsupported query.type (expected powershell/cmd/service/registry/process)"
	}
}

// ----- Powershell & CMD (giữ như cũ) -----

func runPowerShell(ps string) string {
	if strings.TrimSpace(ps) == "" {
		return "ERROR: empty powershell cmd"
	}
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		fmt.Sprintf("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='SilentlyContinue'; %s", ps))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func runCmd(line string) string {
	if strings.TrimSpace(line) == "" {
		return "ERROR: empty cmd"
	}
	cmd := exec.Command("cmd", "/C", line)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// ----- Service collector -----
//
// YAML ví dụ:
// query:
//   type: service
//   name: "AVP*"     # wildcard ok: *, ?
// expect: { equals: "Running" }
func collectService(rule map[string]string) string {
	name := strings.TrimSpace(rule["name"])
	if name == "" {
		return "ERROR: service.name missing"
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	defer m.Disconnect()

	// Hỗ trợ wildcard: duyệt tất cả service
	if strings.ContainsAny(name, "*?") {
		names, err := m.ListServices()
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		found := false
		running := false
		for _, n := range names {
			ok, _ := filepath.Match(strings.ToLower(name), strings.ToLower(n))
			if !ok {
				continue
			}
			found = true
			s, e := m.OpenService(n)
			if e != nil {
				continue
			}
			st, e := s.Query()
			s.Close()
			if e == nil && st.State == svc.Running {
				running = true
			}
		}
		if !found {
			return "NotFound"
		}
		if running {
			return "Running"
		}
		return "Stopped"
	}

	// Tên cụ thể
	s, err := m.OpenService(name)
	if err != nil {
		return "NotFound"
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	if st.State == svc.Running {
		return "Running"
	}
	return "Stopped"
}

// ----- Registry collector -----
//
// YAML ví dụ (DWORD):
// query:
//   type: registry
//   root: HKLM
//   path: "SYSTEM\\CurrentControlSet\\Control"
//   value: "PEFirmwareType"
//   kind: "dword"
// expect: { equals: "2" }
func collectRegistry(rule map[string]string) string {
	rootStr := strings.ToUpper(strings.TrimSpace(rule["root"]))
	path := strings.TrimSpace(rule["path"])
	val := strings.TrimSpace(rule["value"])
	kind := strings.ToLower(strings.TrimSpace(rule["kind"])) // string|expand|dword|qword|multi|binary

	if rootStr == "" || path == "" || val == "" {
		return "ERROR: registry.root/path/value missing"
	}

	var root registry.Key
	switch rootStr {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		root = registry.CURRENT_USER
	case "HKCR", "HKEY_CLASSES_ROOT":
		root = registry.CLASSES_ROOT
	case "HKU", "HKEY_USERS":
		root = registry.USERS
	case "HKCC", "HKEY_CURRENT_CONFIG":
		root = registry.CURRENT_CONFIG
	default:
		return "ERROR: unsupported root"
	}

	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "NotFound"
	}
	defer k.Close()

	switch kind {
	case "dword", "qword", "int", "integer", "number":
		v, _, err := k.GetIntegerValue(val)
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return fmt.Sprintf("%d", v)

	case "multi":
		v, _, err := k.GetStringsValue(val)
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return strings.Join(v, ";")

	case "binary":
		v, _, err := k.GetBinaryValue(val)
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return fmt.Sprintf("%X", v)

	case "expand":
		// Một số version registry package không có GetExpandStringValue.
		// Đọc như chuỗi thường rồi tự expand %VAR% qua Windows API.
		v, _, err := k.GetStringValue(val)
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return os.ExpandEnv(v)

	default: // string (REG_SZ hoặc REG_EXPAND_SZ đọc thẳng, không expand)
		v, _, err := k.GetStringValue(val)
		if err != nil {
			// fallback nhẹ: thử multi/number nếu người viết YAML nhầm kind
			if vs, _, e2 := k.GetStringsValue(val); e2 == nil {
				return strings.Join(vs, ";")
			}
			if vi, _, e3 := k.GetIntegerValue(val); e3 == nil {
				return fmt.Sprintf("%d", vi)
			}
			return fmt.Sprintf("ERROR: %v", err)
		}
		return v
	}
}


// ----- Process collector -----
//
// YAML ví dụ:
// query:
//   type: process
//   name: "ajiant.exe"  # hoặc wildcard: "*.exe"
// expect: { equals: "Running" }
func collectProcess(rule map[string]string) string {
	name := strings.ToLower(strings.TrimSpace(rule["name"]))
	if name == "" {
		return "ERROR: process.name missing"
	}
	// Đơn giản & không phụ thuộc lib: dùng tasklist
	out, err := exec.Command("cmd", "/C", "tasklist /FO CSV /NH").Output()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	lines := bytes.Split(out, []byte{'\n'})
	for _, ln := range lines {
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		// Dòng CSV dạng: "Image Name","PID","Session Name","Session#","Mem Usage"
		// Ta kiểm tra substring tên tiến trình (đơn giản hoá)
		s := strings.ToLower(string(ln))
		// Gỡ dấu ngoặc kép đầu trường
		if strings.ContainsAny(name, "*?") {
			// wildcard
			parts := strings.SplitN(s, ",", 2)
			procQuoted := strings.Trim(parts[0], `"`)
			match, _ := filepath.Match(name, procQuoted)
			if match {
				return "Running"
			}
		} else {
			if strings.Contains(s, "\""+name+"\"") {
				return "Running"
			}
		}
	}
	return "NotRunning"
}
