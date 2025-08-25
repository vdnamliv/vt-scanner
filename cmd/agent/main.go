// cmd/agent/main.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
	"vt-scanner/internal/agent"
)

/* ===================== Types ===================== */

type AppConfig struct {
	ServerURL   string `json:"server"`      // ví dụ: http://localhost:8000
	EnrollKey   string `json:"enroll_key"`  // ví dụ: ORG_KEY_DEMO
	IntervalSec int    `json:"interval"`    // giây
	Once        bool   `json:"once"`        // nếu true thì chạy 1 vòng
}

type Credentials struct {
	AgentID      string `json:"agent_id"`
	AgentSecret  string `json:"agent_secret"`
	PollInterval int    `json:"poll_interval"`
}

/* ===================== Utils ===================== */

func mustHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return h
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func loadJSON[T any](p string, out *T) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func saveJSON(p string, v any, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, perm)
}

func validateURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("server URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid server URL: %s", raw)
	}
	return nil
}

/* ===================== Config paths ===================== */

func configPath() string {
	// Ưu tiên: ./config.json (cạnh .exe) để dễ phát hành/đổi IP/key
	p := filepath.Join(exeDir(), "config.json")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	// Windows: ProgramData/LOCALAPPDATA fallback
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			p2 := filepath.Join(pd, "VT Agent", "config.json")
			if _, err := os.Stat(p2); err == nil {
				return p2
			}
		}
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			p3 := filepath.Join(la, "VT Agent", "config.json")
			if _, err := os.Stat(p3); err == nil {
				return p3
			}
		}
	}
	// nếu chưa tồn tại, trả về cạnh exe (để có thể tạo mới)
	return filepath.Join(exeDir(), "config.json")
}

func credsPath() (string, error) {
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			if up := os.Getenv("USERPROFILE"); up != "" {
				base = filepath.Join(up, "AppData", "Local")
			}
		}
		if base == "" {
			return "", fmt.Errorf("LOCALAPPDATA/USERPROFILE not found")
		}
		return filepath.Join(base, "VT Agent", "creds.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("cannot resolve home dir")
	}
	return filepath.Join(home, ".vt_agent", "creds.json"), nil
}

/* ===================== ENV merge ===================== */

func fromEnv(cfg *AppConfig) {
	if v := os.Getenv("AGENT_SERVER"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("AGENT_ENROLL_KEY"); v != "" {
		cfg.EnrollKey = v
	}
	if v := os.Getenv("AGENT_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.IntervalSec = n
		}
	}
	if v := os.Getenv("AGENT_ONCE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Once = b
		}
	}
}

/* ===================== Creds cache ===================== */

func loadCredentials() (string, string, int, error) {
	p, err := credsPath()
	if err != nil {
		return "", "", 0, err
	}
	if _, err := os.Stat(p); err == nil {
		var c Credentials
		if err := loadJSON(p, &c); err != nil {
			return "", "", 0, err
		}
		return c.AgentID, c.AgentSecret, c.PollInterval, nil
	}
	return "", "", 0, fmt.Errorf("no cached credentials")
}

func saveCredentials(aid, sec string, poll int) error {
	p, err := credsPath()
	if err != nil {
		return err
	}
	return saveJSON(p, Credentials{AgentID: aid, AgentSecret: sec, PollInterval: poll}, 0o600)
}

/* ===================== main ===================== */

func main() {
	hostname := mustHostname()
	log.Printf("Agent starting on host: %s (%s)", hostname, runtime.GOOS)

	// ----- FLAGS (override cao nhất)
	flagServer := flag.String("server", "", "Server URL, e.g. http://localhost:8000")
	flagKey := flag.String("enroll-key", "", "Enrollment key")
	flagInterval := flag.Int("interval", 0, "Poll interval (seconds)")
	flagOnce := flag.Bool("once", false, "Run one cycle then exit")
	flag.Parse()

	// ----- Load config.json (bắt buộc cung cấp server & enroll_key theo yêu cầu)
	cfg := AppConfig{}
	_ = loadJSON(configPath(), &cfg) // nếu chưa có file, cfg rỗng

	// ----- ENV fallback
	fromEnv(&cfg)

	// ----- FLAGS override
	if *flagServer != "" {
		cfg.ServerURL = *flagServer
	}
	if *flagKey != "" {
		cfg.EnrollKey = *flagKey
	}
	if *flagInterval > 0 {
		cfg.IntervalSec = *flagInterval
	}
	if *flagOnce {
		cfg.Once = true
	}

	// ----- Mặc định: interval 600s nếu không set
	if cfg.IntervalSec <= 0 {
		cfg.IntervalSec = 600
	}

	// ----- Double-click Windows: nếu không truyền flag -> mặc định once=true
	if runtime.GOOS == "windows" && len(os.Args) == 1 {
		cfg.Once = true
	}

	// ----- Kiểm tra cấu hình bắt buộc (server + enroll_key lấy từ config.json/ENV/FLAGS)
	if err := validateURL(cfg.ServerURL); err != nil {
		log.Fatalf("config error: %v (hãy chỉnh 'server' trong config.json)", err)
	}
	if cfg.EnrollKey == "" {
		log.Fatalf("config error: enroll_key is empty (hãy đặt trong config.json)")
	}

	// ----- Enroll / load creds
	aid, sec, poll, err := loadCredentials()
	if err != nil || aid == "" || sec == "" {
		aid, sec, poll = agent.Enroll(cfg.ServerURL, cfg.EnrollKey)
		if err := saveCredentials(aid, sec, poll); err != nil {
			log.Printf("Failed to save credentials: %v", err)
		}
		log.Printf("Enrolled: agent_id=%s, poll=%ds", aid, poll)
	} else {
		log.Printf("Loaded cached credentials: agent_id=%s", aid)
	}

	// poll từ server hợp lệ thì dùng; cho phép override bằng cfg.IntervalSec
	if poll <= 0 {
		poll = cfg.IntervalSec
	}
	if cfg.IntervalSec > 0 {
		poll = cfg.IntervalSec
	}

	// ----- Run once / loop
	if cfg.Once {
		if err := agent.RunOnce(cfg.ServerURL, aid, sec, hostname); err != nil {
			log.Fatalf("Run failed: %v", err)
		}
		return
	}
	for {
		if err := agent.RunOnce(cfg.ServerURL, aid, sec, hostname); err != nil {
			log.Printf("Run error: %v", err)
		}
		time.Sleep(time.Duration(poll) * time.Second)
	}
}
