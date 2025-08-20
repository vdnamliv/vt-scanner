package server

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
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
	agents        = map[string]Agent{}                     // cache thông tin agent đã enroll
	policies      = map[string][]map[string]interface{}{}  // policy theo OS, đọc từ YAML
	policyVersion = 1
	db            *sql.DB
)

var rulesDir string

func init() {
	if v := os.Getenv("RULES_DIR"); v != "" {
		rulesDir = v
		return
	}
	exe, err := os.Executable()
	if err == nil {
		rulesDir = filepath.Join(filepath.Dir(exe), "rules")
	} else {
		rulesDir = "rules"
	}
}

func initDB() {
	os.MkdirAll(filepath.Join("server_state"), 0755)

	var err error
	db, err = sql.Open("sqlite3", filepath.Join("server_state", "audit.db"))
	if err != nil {
		log.Fatal("DB error:", err)
	}

	// Bật FK cho SQLite
	if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		log.Fatal("DB pragma error:", err)
	}

	// Schema mới: results KHÔNG còn 'actual', CÓ thêm 'reason'
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id    TEXT,
			hostname    TEXT,
			os          TEXT,
			run_id      TEXT,
			received_at INTEGER
		);

		CREATE TABLE IF NOT EXISTS results (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			run_fk    INTEGER NOT NULL,
			policy_id TEXT,
			title     TEXT,
			severity  TEXT,
			status    TEXT,
			expected  TEXT,
			reason    TEXT,
			FOREIGN KEY(run_fk) REFERENCES runs(id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		log.Fatal("DB init error:", err)
	}

	// --- Migrations cho DB cũ (nếu đã tạo trước đó) ---

	// 1) Thêm cột 'reason' nếu chưa có (IGNORE lỗi nếu đã tồn tại)
	_, _ = db.Exec(`ALTER TABLE results ADD COLUMN reason TEXT;`)

	// 2) (Tuỳ chọn) Thử drop cột 'actual' nếu SQLite hỗ trợ (>=3.35). IGNORE lỗi nếu không hỗ trợ/không tồn tại.
	_, _ = db.Exec(`ALTER TABLE results DROP COLUMN actual;`)
}

func loadRulesByOS() {
	for _, osName := range []string{"windows", "linux", "macos"} {
		path := filepath.Join(rulesDir, osName+".yml")
		log.Printf("Loading rules: %s", path)
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("No rules for %s: %v", osName, err)
			policies[osName] = []map[string]interface{}{}
			continue
		}
		var rules []map[string]interface{}
		if err := yaml.Unmarshal(data, &rules); err != nil {
			log.Printf("YAML parse error for %s: %v", osName, err)
			policies[osName] = []map[string]interface{}{}
			continue
		}
		log.Printf("Loaded %d %s rules", len(rules), osName)
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "version": policyVersion})
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

	// sinh secret ngẫu nhiên (thay vì toàn '0')
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "cannot generate secret", http.StatusInternalServerError)
		return
	}
	agentSecret := "s_" + hex.EncodeToString(b)

	agents[agentID] = Agent{Secret: agentSecret, OS: data.OS, Hostname: data.Hostname}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id":         agentID,
		"agent_secret":     agentSecret,
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
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
		AgentID  string `json:"agent_id"`
		RunID    string `json:"run_id"`
		OS       string `json:"os"`
		Hostname string `json:"hostname"`
		Results  []struct {
			PolicyID string `json:"policy_id"`
			ID       string `json:"id"`
			Title    string `json:"title"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
			Expected string `json:"expected"`
			Reason   string `json:"reason"`
		} `json:"results"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	received := int(time.Now().Unix())

	tx, err := db.Begin()
	if err != nil {
		log.Printf("DB begin error: %v", err)
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}

	// chèn run
	resRun, err := tx.Exec(
		"INSERT INTO runs(agent_id, hostname, os, run_id, received_at) VALUES (?, ?, ?, ?, ?)",
		aid, payload.Hostname, payload.OS, payload.RunID, received,
	)
	if err != nil {
		log.Printf("DB exec runs error: %v", err)
		tx.Rollback()
		http.Error(w, "DB exec error", http.StatusInternalServerError)
		return
	}
	runFK, _ := resRun.LastInsertId()

	// chèn results
	for _, rr := range payload.Results {
		pid := rr.PolicyID
		if pid == "" {
			pid = rr.ID
		}
		if _, err := tx.Exec(
			"INSERT INTO results(run_fk, policy_id, title, severity, status, expected, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
			runFK, pid, rr.Title, rr.Severity, rr.Status, rr.Expected, rr.Reason,
		); err != nil {
			log.Printf("DB insert results error: %v", err)
			tx.Rollback()
			http.Error(w, "DB insert error", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("DB commit error: %v", err)
		tx.Rollback()
		http.Error(w, "DB commit error", http.StatusInternalServerError)
		return
	}

	// Write JSONL
	f, err := os.OpenFile(filepath.Join("server_state", "results.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_ = json.NewEncoder(f).Encode(map[string]interface{}{
			"agent_id":    aid,
			"run_id":      payload.RunID,
			"os":          payload.OS,
			"hostname":    payload.Hostname,
			"results":     payload.Results,
			"received_at": received,
		})
		_, _ = f.WriteString("\n")
		_ = f.Close()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     true,
		"stored": len(payload.Results),
	})
}

func reloadPolicies(w http.ResponseWriter, r *http.Request) {
	// Cho phép: nếu đặt ADMIN_KEY thì yêu cầu key khớp; nếu không có ADMIN_KEY thì chỉ cho localhost
	if adminKey := os.Getenv("ADMIN_KEY"); adminKey != "" {
		key := r.URL.Query().Get("k")
		if key == "" {
			key = r.Header.Get("X-Admin-Key")
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(adminKey)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	} else {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "forbidden (localhost only)", http.StatusForbidden)
			return
		}
	}

	loadRulesByOS()
	policyVersion++
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"version": policyVersion,
	})
}

func index(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT runs.run_id, runs.hostname, runs.agent_id, results.title, results.status, results.reason
		FROM results JOIN runs ON results.run_fk = runs.id
		ORDER BY runs.id DESC LIMIT 100
	`)
	if err != nil {
		http.Error(w, "DB query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	esc := html.EscapeString // alias để gọi ngắn gọn

	var trs []string
	for rows.Next() {
		var runID, hostname, agentID, policyTitle, status, reason string
		if err := rows.Scan(&runID, &hostname, &agentID, &policyTitle, &status, &reason); err != nil {
			continue
		}
		statusCls := map[string]string{"PASS": "PASS", "FAIL": "FAIL"}[status]
		trs = append(trs, fmt.Sprintf(
			"<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>",
			statusCls, esc(runID), esc(hostname), esc(agentID), esc(policyTitle), esc(status), esc(reason),
		))
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "DB rows error", http.StatusInternalServerError)
		return
	}

	page := fmt.Sprintf(`
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
			<tr><th>Run</th><th>Host</th><th>Agent</th><th>Policy</th><th>Status</th><th>Reason</th></tr>
			%s
		</table>
		</body></html>`, strings.Join(trs, ""))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}
