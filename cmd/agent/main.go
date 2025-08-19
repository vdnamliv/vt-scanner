package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
	"vt-scanner/internal/agent"
)

type Credentials struct {
	AgentID      string `json:"agent_id"`
	AgentSecret  string `json:"agent_secret"`
	PollInterval int    `json:"poll_interval"`
}

func loadCredentials() (string, string, int, error) {
	cacheDir := os.Getenv("HOME") + "/.vt_agent"
	cacheFile := cacheDir + "/creds.json"
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
	cacheDir := os.Getenv("HOME") + "/.vt_agent"
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}
	cacheFile := cacheDir + "/creds.json"
	data, err := json.Marshal(Credentials{AgentID: aid, AgentSecret: sec, PollInterval: poll})
	if err != nil {
		return err
	}
	return os.WriteFile(cacheFile, data, 0644)
}

func main() {
	hostname, _ := os.Hostname() // Khai báo hostname ở đây
	log.Printf("Agent starting on host: %s", hostname)
	serverURL := flag.String("server", "http://127.0.0.1:8000", "Server URL")
	enrollKey := flag.String("enroll-key", "ORG_KEY_DEMO", "Enrollment key")
	interval := flag.Int("interval", 600, "Poll interval in seconds")
	once := flag.Bool("once", false, "Run one cycle then exit")
	flag.Parse()

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