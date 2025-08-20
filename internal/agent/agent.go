package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"
	"vt-scanner/internal/agent/collector"
	"vt-scanner/internal/agent/evaluator"
)

type Rule struct {
	ID        string                 `yaml:"id"        json:"id"`
	Title     string                 `yaml:"title"     json:"title"`
	Severity  string                 `yaml:"severity"  json:"severity"`
	Rationale string                 `yaml:"rationale" json:"rationale"`
	Query     map[string]string      `yaml:"query"     json:"query"`
	Expect    map[string]interface{} `yaml:"expect"    json:"expect"`
	Fix       string                 `yaml:"fix"       json:"fix"`
	FailText  string                 `yaml:"fail_text" json:"fail_text"`
	PassText  string                 `yaml:"pass_text" json:"pass_text"`
}

type EnrollResponse struct { //phản hồi khi đăng ký
	AgentID      string `json:"agent_id"`
	AgentSecret  string `json:"agent_secret"`
	PollInterval int    `json:"poll_interval_sec"`
}

type PolicyResponse struct { // phản hồi khi lấy chính sách
	Version  int    `json:"version"` // /policies?os=...
	Policies []Rule `json:"policies"`
}

type Result struct { // kết quả kiểm tra của 1 rule
	ID         string `json:"id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	Expected   string `json:"expected"`
	Actual     string `json:"actual"` // để tương thích, nhưng sẽ để trống
	Rationale  string `json:"rationale"`
	EngineUsed string `json:"engine_used"`
	Fix        string `json:"fix"`
	Reason     string `json:"reason"`
}

type Payload struct {
	AgentID  string   `json:"agent_id"`
	RunID    string   `json:"run_id"`
	OS       string   `json:"os"`
	Hostname string   `json:"hostname"`
	Results  []Result `json:"results"`
}

func formatExpect(m map[string]interface{}) string {
	if v, ok := m["equals"]; ok {
		return fmt.Sprintf("equals %v", v)
	}
	if v, ok := m["in"]; ok {
		return fmt.Sprintf("in %v", v)
	}
	if v, ok := m["contains"]; ok {
		return fmt.Sprintf("contains %v", v)
	}
	if v, ok := m["regex"]; ok {
		return fmt.Sprintf("regex %v", v)
	}
	return fmt.Sprintf("%v", m)
}

func Enroll(serverURL, enrollKey string) (string, string, int) {
	hostname, _ := os.Hostname() // lấy hostname
	osName := detectOS()         // lấy OS
	body, _ := json.Marshal(map[string]string{ //tạo json body
		"enrollment_key": enrollKey,
		"hostname":       hostname,
		"os":             osName,
		"arch":           runtime.GOARCH,
		"version":        "agent-0.2.0",
	})
	resp, err := http.Post(serverURL+"/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatal("Enroll failed:", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("Enroll failed: %s - %s", resp.Status, string(b))
	}
	var data EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Fatal("Enroll decode failed:", err)
	}
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
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET /policies failed: %s - %s", resp.Status, string(b))
	}

	var policies PolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return fmt.Errorf("decode policies failed: %w", err)
	}

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
		ok, machineReason := evaluator.Evaluate(actual, rule.Expect)

		reason := machineReason
		if ok && rule.PassText != "" {
			reason = rule.PassText
		}
		if !ok && rule.FailText != "" {
			reason = rule.FailText
		}

		results = append(results, Result{
			ID:         rule.ID,
			Title:      rule.Title, // UI sẽ lấy "Policy" từ Title
			Severity:   rule.Severity,
			Status:     map[bool]string{true: "PASS", false: "FAIL"}[ok],
			Expected:   formatExpect(rule.Expect),
			Actual:     "", // KHÔNG gửi actual nữa
			Rationale:  rule.Rationale,
			EngineUsed: rule.Query["type"],
			Fix:        rule.Fix,
			Reason:     reason, // NEW
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
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req) // thực sự gửi
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST /results failed: %s - %s", resp.Status, string(b))
	}

	log.Printf("Sent %d results", len(results))
	return nil
}
