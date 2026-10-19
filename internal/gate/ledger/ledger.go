// Package ledger is the gate's egress record: one row per request that the gate
// handled, kept as daily JSONL files and handed to OG Core's egress provider.
// Rows never contain values, placeholders or query strings.
package ledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Row is one request. Field names follow OG Core's EgressRecordParcel where one exists.
type Row struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"ts"`
	DurationMs int64     `json:"duration_ms"`
	Caller     string    `json:"caller"`
	UID        uint32    `json:"uid"`
	AccountID  string    `json:"account_id,omitempty"`
	RegionID   string    `json:"region_id,omitempty"`
	Adapter    string    `json:"adapter,omitempty"`
	// Destination is the display host ("api.outgate.ai"), "on-device model" (og-local)
	// or "on-device/<alias>" (another on-device model instance).
	Destination string `json:"destination"`
	// Class is the destination class: outgate, on-device, provider, mirror, backup, uploads or web ("" when refused before routing).
	Class  string `json:"class,omitempty"`
	Method string `json:"method"`
	// PathClass is the path with ids replaced by ":id".
	PathClass  string `json:"path_class"`
	EgressKind string `json:"egress_kind,omitempty"`
	// Kind is OG Core's class: llm, tool, upload, answer, event, other; a backup row's is upload,
	// download, list, delete or head, an uploads row's download or upload (and their path_class is empty:
	// never an object key); a web row's is other, its path_class empty too (never a path of the web).
	Kind             string         `json:"kind"`
	LaneID           string         `json:"lane_id,omitempty"`
	StepIndex        *int           `json:"step_index,omitempty"`
	ThreadID         string         `json:"thread_id,omitempty"`
	ApprovalID       string         `json:"approval_id,omitempty"`
	Status           int            `json:"status"`
	BytesOut         int64          `json:"bytes_out"`
	BytesOutRaw      int64          `json:"bytes_out_raw"`
	BytesIn          int64          `json:"bytes_in"`
	Content          bool           `json:"content"`
	MaskedCount      int            `json:"masked_count"`
	MaskedCategories map[string]int `json:"masked_categories,omitempty"`
	RestoredCount    int            `json:"restored_count,omitempty"`
	// Mask is whether the content was masked: "on", "off" (a masked class in
	// passthrough) or "not_required" (its class isn't masked, or no content).
	Mask        string `json:"mask,omitempty"`
	Blocked     bool   `json:"blocked"`
	BlockReason string `json:"block_reason,omitempty"`
	OnDevice    bool   `json:"on_device"`
	Mode        string `json:"mode"`
	Error       string `json:"error,omitempty"`
	// AppID and Participant name an app tenancy's app and participant (lifecycle rows, appq.go).
	AppID       string `json:"app_id,omitempty"`
	Participant string `json:"participant,omitempty"`
	// Direction is "in" for a request that came in through the tunnel front.
	Direction string `json:"direction,omitempty"`
	// Event is a lifecycle note (tunnel.connected, ...).
	Event string `json:"event,omitempty"`
	// Subject is who sent a tunnel request: service_token:<name>, user:<keyed hash> or other.
	Subject string `json:"subject,omitempty"`
	// ClientKey is the id of the tunnel client key a request carried, never the key.
	ClientKey string `json:"client_key,omitempty"`
	// Container and RunID name the on-device program and its run a containers request came from (og-os M40).
	Container string `json:"container,omitempty"`
	RunID     string `json:"run_id,omitempty"`
}

// Sink receives every row once it is complete.
type Sink interface {
	Record(*Row)
}

// Fanout passes each row to every sink.
type Fanout []Sink

func (f Fanout) Record(r *Row) {
	for _, s := range f {
		s.Record(r)
	}
}

// Files appends rows to <dir>/egress-YYYY-MM-DD.jsonl (UTC) and deletes files
// older than the retention.
type Files struct {
	dir       string
	retention time.Duration
	now       func() time.Time

	mu      sync.Mutex
	day     string
	f       *os.File
	w       *bufio.Writer
	lastGC  time.Time
	onError func(error)
}

func NewFiles(dir string, retention time.Duration, onError func(error)) (*Files, error) {
	// Group-shared with OG Core's reader and Settings (uid system), like the other OG daemons.
	if err := os.MkdirAll(dir, 0o770); err != nil { //nolint:gosec // see above
		return nil, err
	}
	if onError == nil {
		onError = func(error) {}
	}
	return &Files{dir: dir, retention: retention, now: time.Now, onError: onError}, nil
}

func (l *Files) Record(r *Row) {
	b, err := json.Marshal(r)
	if err != nil {
		l.onError(err)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.rotate(); err != nil {
		l.onError(err)
		return
	}
	if _, err := l.w.Write(append(b, '\n')); err != nil {
		l.onError(err)
		return
	}
	if err := l.w.Flush(); err != nil {
		l.onError(err)
	}
}

func (l *Files) rotate() error {
	now := l.now().UTC()
	day := now.Format("2006-01-02")
	if day != l.day || l.f == nil {
		if l.f != nil {
			_ = l.w.Flush()
			_ = l.f.Close()
		}
		f, err := os.OpenFile(filepath.Join(l.dir, "egress-"+day+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o660) //nolint:gosec // group-shared, see NewFiles
		if err != nil {
			l.f = nil
			return err
		}
		l.f, l.w, l.day = f, bufio.NewWriter(f), day
	}
	if now.Sub(l.lastGC) > time.Hour {
		l.lastGC = now
		l.gc(now)
	}
	return nil
}

func (l *Files) gc(now time.Time) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	cutoff := now.Add(-l.retention).Format("2006-01-02")
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "egress-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		if day := strings.TrimSuffix(strings.TrimPrefix(name, "egress-"), ".jsonl"); day < cutoff {
			_ = os.Remove(filepath.Join(l.dir, name))
		}
	}
}

func (l *Files) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	_ = l.w.Flush()
	err := l.f.Close()
	l.f = nil
	return err
}

// Ring keeps the last rows in memory for the gate's debug query and health.
type Ring struct {
	mu   sync.Mutex
	rows []Row
	next int
	full bool
	tot  Totals
	day  string
	now  func() time.Time
}

// Totals counts today's rows (local time, like OG Core's counters).
type Totals struct {
	Day      string `json:"day"`
	Requests int    `json:"requests"`
	Content  int    `json:"content"`
	Clean    int    `json:"clean"`
	Masked   int    `json:"masked"`
	Blocked  int    `json:"blocked"`
	OnDevice int    `json:"on_device"`
	Values   int    `json:"masked_values"`
	BytesOut int64  `json:"bytes_out"`
	BytesIn  int64  `json:"bytes_in"`
}

func NewRing(n int) *Ring {
	return &Ring{rows: make([]Row, n), now: time.Now}
}

func (r *Ring) Record(row *Row) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[r.next] = *row
	r.next = (r.next + 1) % len(r.rows)
	if r.next == 0 {
		r.full = true
	}
	if Lifecycle(row) {
		return
	}
	day := r.now().Format("2006-01-02")
	if day != r.day {
		r.day, r.tot = day, Totals{Day: day}
	}
	r.tot.Requests++
	r.tot.BytesOut += row.BytesOut
	r.tot.BytesIn += row.BytesIn
	if row.Content {
		r.tot.Content++
	}
	switch Outcome(row) {
	case "BLOCKED":
		r.tot.Blocked++
	case "ON_DEVICE":
		r.tot.OnDevice++
	case "MASKED":
		r.tot.Masked++
	default:
		r.tot.Clean++
	}
	r.tot.Values += row.MaskedCount
}

// Last returns up to n rows, newest first.
func (r *Ring) Last(n int) []Row {
	r.mu.Lock()
	defer r.mu.Unlock()
	size := r.next
	if r.full {
		size = len(r.rows)
	}
	if n <= 0 || n > size {
		n = size
	}
	out := make([]Row, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, r.rows[(r.next-i+len(r.rows))%len(r.rows)])
	}
	return out
}

func (r *Ring) Totals() Totals {
	r.mu.Lock()
	defer r.mu.Unlock()
	if day := r.now().Format("2006-01-02"); day != r.day {
		return Totals{Day: day}
	}
	return r.tot
}

// Outcome is OG Core's rule (CONTRACT.md 4.5): blocked, else on-device, else masked > 0, else clean.
func Outcome(r *Row) string {
	switch {
	case r.Blocked:
		return "BLOCKED"
	case r.OnDevice:
		return "ON_DEVICE"
	case r.MaskedCount > 0:
		return "MASKED"
	default:
		return "CLEAN"
	}
}

// Categories renders masked counts as OG Core's "PII:2,CREDENTIAL:1".
func Categories(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", k, m[k]))
	}
	return strings.Join(parts, ",")
}
