//internal/server/server.go
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
	Secret     string
	OS         string
	Hostname   string
	Fingerprint string
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
	policies      = map[string][]map[string]interface{}{} // policy theo OS, đọc từ YAML
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

	dbPath := filepath.Join("server_state", "audit.db")
	dsn := fmt.Sprintf("file:%s?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL", dbPath)

	var err error
	db, err = sql.Open("sqlite3", dsn)
	if err != nil {
		log.Fatal("DB open error:", err)
	}

	// Bảng agents (giữ nguyên nếu bạn đang dùng)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS agents (
			agent_id     TEXT PRIMARY KEY,
			agent_secret TEXT NOT NULL,
			hostname     TEXT,
			os           TEXT,
			fingerprint  TEXT UNIQUE,
			enrolled_at  INTEGER,
			last_seen    INTEGER
		);
	`)
	if err != nil {
		log.Fatal("DB init agents error:", err)
	}

	// Bảng runs
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id    TEXT,
			hostname    TEXT,
			os          TEXT,
			run_id      TEXT,
			received_at INTEGER
		);
	`)
	if err != nil {
		log.Fatal("DB init runs error:", err)
	}

	// Bảng results: thêm cột fix TEXT
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS results (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			run_fk    INTEGER NOT NULL,
			policy_id TEXT,
			title     TEXT,
			severity  TEXT,
			status    TEXT,
			expected  TEXT,
			reason    TEXT,
			fix       TEXT,
			FOREIGN KEY(run_fk) REFERENCES runs(id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		log.Fatal("DB init results error:", err)
	}
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
		Fingerprint   string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if data.EnrollmentKey != "ORG_KEY_DEMO" {
		http.Error(w, "bad enrollment key", http.StatusForbidden)
		return
	}

	// Xử lý enroll: dùng fingerprint để tái sử dụng agent_id, đồng thời cấp secret mới (vô hiệu agent cũ)
	now := int(time.Now().Unix())
	var agentID string
	var exists bool

	if data.Fingerprint != "" {
		row := db.QueryRow(`SELECT agent_id FROM agents WHERE fingerprint = ?`, data.Fingerprint)
		_ = row.Scan(&agentID)
		if agentID != "" {
			exists = true
		}
	}
	if !exists {
		agentID = fmt.Sprintf("ag_%d", time.Now().UnixMilli())
	}

	// sinh secret ngẫu nhiên
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "cannot generate secret", http.StatusInternalServerError)
		return
	}
	agentSecret := "s_" + hex.EncodeToString(b)

	if exists {
		_, err := db.Exec(`UPDATE agents SET agent_secret=?, hostname=?, os=?, last_seen=? WHERE agent_id=?`,
			agentSecret, data.Hostname, data.OS, now, agentID)
		if err != nil {
			http.Error(w, "DB update agent error", http.StatusInternalServerError)
			return
		}
	} else {
		_, err := db.Exec(`INSERT INTO agents(agent_id, agent_secret, hostname, os, fingerprint, enrolled_at, last_seen)
		                  VALUES(?,?,?,?,?,?,?)`,
			agentID, agentSecret, data.Hostname, data.OS, data.Fingerprint, now, now)
		if err != nil {
			http.Error(w, "DB insert agent error", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id":          agentID,
		"agent_secret":      agentSecret,
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

	var dbSec, hostname, osName, fp string
	row := db.QueryRow(`SELECT agent_secret, hostname, os, fingerprint FROM agents WHERE agent_id=?`, aid)
	if err := row.Scan(&dbSec, &hostname, &osName, &fp); err != nil {
		return "", Agent{}, fmt.Errorf("invalid agent")
	}
	if subtle.ConstantTimeCompare([]byte(dbSec), []byte(sec)) != 1 {
		return "", Agent{}, fmt.Errorf("invalid agent")
	}
	// cập nhật last_seen
	_, _ = db.Exec(`UPDATE agents SET last_seen=? WHERE agent_id=?`, int(time.Now().Unix()), aid)
	return aid, Agent{Secret: dbSec, Hostname: hostname, OS: osName, Fingerprint: fp}, nil
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
		AgentID     string `json:"agent_id"`
		RunID       string `json:"run_id"`
		OS          string `json:"os"`
		Hostname    string `json:"hostname"`
		Fingerprint string `json:"fingerprint"`
		Results     []struct {
			PolicyID string `json:"policy_id"`
			ID       string `json:"id"`
			Title    string `json:"title"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
			Expected string `json:"expected"`
			Reason   string `json:"reason"`
			Fix      string `json:"fix"` // <-- nhận fix từ agent (YAML)
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

	// DỌN kết quả cũ của agent này để chỉ giữ bản mới nhất
	if _, err := tx.Exec(`DELETE FROM results WHERE run_fk IN (SELECT id FROM runs WHERE agent_id = ?)`, aid); err != nil {
		log.Printf("DB delete old results error: %v", err)
		tx.Rollback()
		http.Error(w, "DB delete error", http.StatusInternalServerError)
		return
	}
	if _, err := tx.Exec(`DELETE FROM runs WHERE agent_id = ?`, aid); err != nil {
		log.Printf("DB delete old runs error: %v", err)
		tx.Rollback()
		http.Error(w, "DB delete error", http.StatusInternalServerError)
		return
	}

	// Chèn RUN mới
	resRun, err := tx.Exec(
		"INSERT INTO runs(agent_id, hostname, os, run_id, received_at) VALUES (?, ?, ?, ?, ?)",
		aid, payload.Hostname, payload.OS, payload.RunID, received,
	)
	if err != nil {
		log.Printf("DB insert run error: %v", err)
		tx.Rollback()
		http.Error(w, "DB exec error", http.StatusInternalServerError)
		return
	}
	runFK, _ := resRun.LastInsertId()

	// Chèn RESULTS mới (gán fix theo PASS/FAIL)
	for _, rr := range payload.Results {
		pid := rr.PolicyID
		if pid == "" {
			pid = rr.ID
		}
		fixToStore := "None"
		if strings.ToUpper(rr.Status) == "FAIL" && strings.TrimSpace(rr.Fix) != "" {
			fixToStore = rr.Fix
		}

		if _, err := tx.Exec(
			"INSERT INTO results(run_fk, policy_id, title, severity, status, expected, reason, fix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			runFK, pid, rr.Title, rr.Severity, rr.Status, rr.Expected, rr.Reason, fixToStore,
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

	// (Tùy chọn) ghi JSONL
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
		WITH latest AS (
			SELECT agent_id, MAX(id) AS id
			FROM runs
			GROUP BY agent_id
		)
		SELECT runs.run_id, runs.hostname, runs.agent_id, results.title, results.status, results.reason, results.fix, runs.received_at
		FROM latest
		JOIN runs    ON runs.id = latest.id
		JOIN results ON results.run_fk = runs.id
		ORDER BY runs.id DESC
	`)
	if err != nil {
		http.Error(w, "DB query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	esc := html.EscapeString
	var trs []string
	for rows.Next() {
		var runID, hostname, agentID, policyTitle, status, reason, fix string
		var receivedAt int64
		if err := rows.Scan(&runID, &hostname, &agentID, &policyTitle, &status, &reason, &fix, &receivedAt); err != nil {
			continue
		}
		statusCls := map[string]string{"PASS": "PASS", "FAIL": "FAIL"}[status]
		runTime := time.Unix(receivedAt, 0).Format("2006-01-02 15:04:05")
		trs = append(trs, fmt.Sprintf(
			"<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td><td><pre>%s</pre></td></tr>",
			statusCls, esc(runTime), esc(hostname), esc(agentID), esc(policyTitle), esc(status), esc(reason), esc(fix),
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
			<tr><th>Time</th><th>Host</th><th>Agent</th><th>Policy</th><th>Status</th><th>Reason</th><th>Fix</th></tr>
			%s
		</table>
		</body></html>`, strings.Join(trs, ""))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}
