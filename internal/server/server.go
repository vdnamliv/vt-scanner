package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

type Agent struct {
	Secret   string
	OS       string
	Hostname string
}

type Run1 struct {
	ID         int
	AgentID    string
	Hostname   string
	OS         string
	RunID      string
	ReceivedAt int
}

type Result struct {
	ID       int
	RunFK    int
	PolicyID string
	Title    string
	Severity string
	Status   string
	Expected string
	Actual   string
}

var (
	agents        = map[string]Agent{}
	policies      = map[string][]map[string]interface{}{}
	policyVersion = 1
	db            *sql.DB
	rulesDir      = filepath.Join("..", "rules")
)

func initDB() {
	os.MkdirAll(filepath.Join("server_state"), 0755)
	var err error
	db, err = sql.Open("sqlite3", filepath.Join("server_state", "audit.db"))
	if err != nil {
		log.Fatal("DB error:", err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id TEXT, hostname TEXT, os TEXT, run_id TEXT, received_at INTEGER
		);
		CREATE TABLE IF NOT EXISTS results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_fk INTEGER, policy_id TEXT, title TEXT, severity TEXT, status TEXT, expected TEXT, actual TEXT,
			FOREIGN KEY(run_fk) REFERENCES runs(id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		log.Fatal("DB init error:", err)
	}
}

func loadRulesByOS() {
	for _, osName := range []string{"windows", "linux", "macos"} {
		path := filepath.Join(rulesDir, osName+".yml")
		data, err := os.ReadFile(path)
		if err != nil {
			policies[osName] = []map[string]interface{}{}
			continue
		}
		var rules []map[string]interface{}
		yaml.Unmarshal(data, &rules)
		policies[osName] = rules
	}
}

func Run(addr, cert, key string) error {
	initDB()
	loadRulesByOS()

	r := mux.NewRouter()
	r.HandleFunc("/health", health).Methods("GET")
	r.HandleFunc("/enroll", enroll).Methods("POST")
	r.HandleFunc("/policies", policiesHandler).Methods("GET")
	r.HandleFunc("/results", results).Methods("POST")
	r.HandleFunc("/reload_policies", reloadPolicies).Methods("POST")
	r.HandleFunc("/", index).Methods("GET")

	log.Printf("Server starting on %s", addr)
	if cert != "" && key != "" {
		return http.ListenAndServeTLS(addr, cert, key, r)
	}
	return http.ListenAndServe(addr, r)
}

func health(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "version": policyVersion})
}

func enroll(w http.ResponseWriter, r *http.Request) {
	var data struct {
		EnrollmentKey string `json:"enrollment_key"`
		Hostname      string `json:"hostname"`
		OS            string `json:"os"`
		Arch          string `json:"arch"`
		Version       string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if data.EnrollmentKey != "ORG_KEY_DEMO" {
		http.Error(w, "bad enrollment key", http.StatusForbidden)
		return
	}
	agentID := fmt.Sprintf("ag_%d", time.Now().UnixMilli())
	agentSecret := fmt.Sprintf("s_%x", make([]byte, 9))
	agents[agentID] = Agent{Secret: agentSecret, OS: data.OS, Hostname: data.Hostname}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id":        agentID,
		"agent_secret":    agentSecret,
		"poll_interval_sec": 600,
	})
}

func authAgent(r *http.Request) (string, Agent, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", Agent{}, fmt.Errorf("missing bearer")
	}
	token := strings.SplitN(auth[7:], ":", 2)
	if len(token) != 2 {
		return "", Agent{}, fmt.Errorf("bad token")
	}
	aid, sec := token[0], token[1]
	ag, ok := agents[aid]
	if !ok || ag.Secret != sec {
		return "", Agent{}, fmt.Errorf("invalid agent")
	}
	return aid, ag, nil
}

func policiesHandler(w http.ResponseWriter, r *http.Request) {
	_, _, err := authAgent(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	osName := r.URL.Query().Get("os")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"version":  policyVersion,
		"policies": policies[osName],
	})
}

func results(w http.ResponseWriter, r *http.Request) {
	aid, _, err := authAgent(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var payload struct {
		AgentID  string
		RunID    string
		OS       string
		Hostname string
		Results  []struct {
			PolicyID string `json:"policy_id"`
			Title    string `json:"title"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
			Expected string `json:"expected"`
			Actual   string `json:"actual"`
		}
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	received := int(time.Now().Unix())
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO runs(agent_id, hostname, os, run_id, received_at) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		http.Error(w, "DB prepare error", http.StatusInternalServerError)
		return
	}
	res, err := stmt.Exec(aid, payload.Hostname, payload.OS, payload.RunID, received)
	if err != nil {
		tx.Rollback()
		http.Error(w, "DB exec error", http.StatusInternalServerError)
		return
	}
	runFK, _ := res.LastInsertId()
	for _, res := range payload.Results {
		_, err := tx.Exec("INSERT INTO results(run_fk, policy_id, title, severity, status, expected, actual) VALUES (?, ?, ?, ?, ?, ?, ?)",
			runFK, res.PolicyID, res.Title, res.Severity, res.Status, res.Expected, res.Actual)
		if err != nil {
			tx.Rollback()
			http.Error(w, "DB insert error", http.StatusInternalServerError)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		http.Error(w, "DB commit error", http.StatusInternalServerError)
		return
	}

	// Write JSONL
	f, err := os.OpenFile(filepath.Join("server_state", "results.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		json.NewEncoder(f).Encode(map[string]interface{}{
			"agent_id":    aid,
			"run_id":      payload.RunID,
			"os":          payload.OS,
			"hostname":    payload.Hostname,
			"results":     payload.Results,
			"received_at": received,
		})
		f.WriteString("\n")
		f.Close()
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     true,
		"stored": len(payload.Results),
	})
}

func reloadPolicies(w http.ResponseWriter, r *http.Request) {
	_, _, err := authAgent(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	loadRulesByOS()
	policyVersion++
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"version": policyVersion,
	})
}

func index(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT runs.run_id, runs.hostname, runs.agent_id, results.policy_id, results.status, results.actual
		FROM results JOIN runs ON results.run_fk = runs.id
		ORDER BY runs.id DESC LIMIT 100
	`)
	if err != nil {
		http.Error(w, "DB query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var trs []string
	for rows.Next() {
		var runID, hostname, agentID, policyID, status, actual string
		if err := rows.Scan(&runID, &hostname, &agentID, &policyID, &status, &actual); err != nil {
			continue
		}
		statusCls := map[string]string{"PASS": "PASS", "FAIL": "FAIL"}[status]
		trs = append(trs, fmt.Sprintf(
			"<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>",
			statusCls, runID, hostname, agentID, policyID, status, html.EscapeString(actual)))
	}

	html := fmt.Sprintf(`
		<html><head><meta charset='utf-8'><style>
			body{font-family:Arial} table{border-collapse:collapse}
			th,td{border:1px solid #ccc;padding:6px} th{background:#f4f4f4}
			.PASS{background:#d4edda} .FAIL{background:#f8d7da}
			pre{margin:0;white-space:pre-wrap}
			form{margin-bottom:12px}
		</style></head><body>
		<h2>Latest Results</h2>
		<form method="post" action="/reload_policies"><button type="submit">Reload policies</button></form>
		<table>
			<tr><th>Run</th><th>Host</th><th>Agent</th><th>Policy</th><th>Status</th><th>Actual</th></tr>
			%s
		</table>
		</body></html>`, strings.Join(trs, ""))
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}