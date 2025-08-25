// cmd/agent/main.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"vt-scanner/internal/agent"
)

// --- Lưu ý: phần creds path để chạy tốt trên Windows ---
type Credentials struct {
	AgentID      string `json:"agent_id"`
	AgentSecret  string `json:"agent_secret"`
	PollInterval int    `json:"poll_interval"`
}

func agentCredsPath() (string, error) {
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			base = os.Getenv("USERPROFILE")
			if base == "" {
				return "", fmt.Errorf("LOCALAPPDATA/USERPROFILE not found")
		 }
			base = filepath.Join(base, "AppData", "Local")
		}
		return filepath.Join(base, "vt_agent", "creds.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".vt_agent", "creds.json"), nil
}

func loadCredentials() (string, string, int, error) {
	cacheFile, err := agentCredsPath()
	if err != nil {
		return "", "", 0, err
	}
	if _, err := os.Stat(cacheFile); err == nil {
		data, err := os.ReadFile(cacheFile)
		if err != nil {
			return "", "", 0, err
		}
		var creds Credentials
		if err := json.Unmarshal(data, &creds); err != nil {
			return "", "", 0, err
		}
		return creds.AgentID, creds.AgentSecret, creds.PollInterval, nil
	}
	return "", "", 0, fmt.Errorf("no cached credentials")
}

func saveCredentials(aid, sec string, poll int) error {
	cacheFile, err := agentCredsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cacheFile), 0755); err != nil {
		return err
	}
	data, err := json.Marshal(Credentials{AgentID: aid, AgentSecret: sec, PollInterval: poll})
	if err != nil {
		return err
	}
	return os.WriteFile(cacheFile, data, 0600)
}

func main() {
	hostname, _ := os.Hostname() // Khai báo hostname ở đây
	log.Printf("Agent starting on host: %s", hostname)

	// Mặc định trỏ về máy server của bạn
	defaultServer := "http://192.168.1.1:8000"
	defaultKey := "ORG_KEY_DEMO"

	serverURL := flag.String("server", defaultServer, "Server URL")
	enrollKey := flag.String("enroll-key", defaultKey, "Enrollment key")
	interval := flag.Int("interval", 600, "Poll interval in seconds")
	once := flag.Bool("once", false, "Run one cycle then exit")
	flag.Parse()

	// Nếu người dùng double-click không truyền tham số → tự động chạy 1 vòng
	if len(os.Args) == 1 {
		*once = true
	}

	aid, sec, poll, err := loadCredentials()
	if err != nil || aid == "" {
		aid, sec, poll = agent.Enroll(*serverURL, *enrollKey)
		if err := saveCredentials(aid, sec, poll); err != nil {
			log.Printf("Failed to save credentials: %v", err)
		}
		log.Printf("Enrolled: agent_id=%s, poll=%ds", aid, poll)
	} else {
		log.Printf("Loaded cached credentials: agent_id=%s", aid)
	}

	if *interval != 0 {
		poll = *interval
	}

	if *once {
		if err := agent.RunOnce(*serverURL, aid, sec, hostname); err != nil {
			log.Fatalf("Run failed: %v", err)
		}
		return
	}

	for {
		if err := agent.RunOnce(*serverURL, aid, sec, hostname); err != nil {
			log.Printf("Run error: %v", err)
		}
		time.Sleep(time.Duration(poll) * time.Second)
	}
}
