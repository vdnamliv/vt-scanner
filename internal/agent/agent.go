package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"
	"vt-scanner/internal/agent/collector"
	"vt-scanner/internal/agent/evaluator"
)

type Rule struct {
	ID        string                 `yaml:"id"`
	Title     string                 `yaml:"title"`
	Severity  string                 `yaml:"severity"`
	Rationale string                 `yaml:"rationale"`
	Query     map[string]string      `yaml:"query"`
	Expect    map[string]interface{} `yaml:"expect"`
	Fix       string                 `yaml:"fix"`
}

type EnrollResponse struct {
	AgentID      string `json:"agent_id"`
	AgentSecret  string `json:"agent_secret"`
	PollInterval int    `json:"poll_interval_sec"`
}

type PolicyResponse struct {
	Version   int    `json:"version"`
	Policies  []Rule `json:"policies"`
}

type Result struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	Expected   string `json:"expected"`
	Actual     string `json:"actual"`
	Rationale  string `json:"rationale"`
	EngineUsed string `json:"engine_used"`
	Fix        string `json:"fix"`
}

type Payload struct {
	AgentID  string   `json:"agent_id"`
	RunID    string   `json:"run_id"`
	OS       string   `json:"os"`
	Hostname string   `json:"hostname"`
	Results  []Result `json:"results"`
}

func Enroll(serverURL, enrollKey string) (string, string, int) {
	hostname, _ := os.Hostname()
	osName := detectOS()
	body, _ := json.Marshal(map[string]string{
		"enrollment_key": enrollKey,
		"hostname":       hostname,
		"os":             osName,
		"arch":           "amd64",
		"version":        "agent-0.2.0",
	})
	resp, err := http.Post(serverURL+"/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatal("Enroll failed:", err)
	}
	defer resp.Body.Close()
	var data EnrollResponse
	json.NewDecoder(resp.Body).Decode(&data)
	return data.AgentID, data.AgentSecret, data.PollInterval
}

func detectOS() string {
	switch os := runtime.GOOS; os {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	default:
		return "unknown"
	}
}

func RunOnce(serverURL, agentID, agentSecret, hostname string) error {
	osName := detectOS()
	url := fmt.Sprintf("%s/policies?os=%s", serverURL, osName)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s:%s", agentID, agentSecret))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var policies PolicyResponse
	json.NewDecoder(resp.Body).Decode(&policies)

	log.Printf("Received %d policies", len(policies.Policies))

	results := []Result{}
	for _, rule := range policies.Policies {
        var actual string
        switch osName {
        case "windows":
            actual = collector.CollectWindows(rule.Query)
        case "linux":
            actual = collector.CollectLinux(rule.Query)
        case "macos":
            actual = collector.CollectMacOS(rule.Query)
        default:
            actual = "unsupported"
        }
        ok := evaluator.Evaluate(actual, rule.Expect)
        results = append(results, Result{
            ID:         rule.ID,
            Title:      rule.Title,
            Severity:   rule.Severity,
            Status:     map[bool]string{true: "PASS", false: "FAIL"}[ok],
            Expected:   fmt.Sprintf("%v", rule.Expect["equals"]),
            Actual:     actual,
            Rationale:  rule.Rationale,
            EngineUsed: rule.Query["type"],
            Fix:        rule.Fix,
        })
    }

	payload := Payload{
		AgentID:  agentID,
		RunID:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		OS:       osName,
		Hostname: hostname,
		Results:  results,
	}
	body, _ := json.Marshal(payload)
	req, _ = http.NewRequest("POST", serverURL+"/results", bytes.NewReader(body))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s:%s", agentID, agentSecret))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	log.Printf("Sent %d results", len(results))
	return nil
}