// Package corelink connects the gate to OG Core (og-os M01) through og-gate-link,
// the gate's binder helper: Go has no binder, so the gate runs the helper as a
// child and exchanges JSON lines with it. Through it the gate reports its health
// and state, hands its ledger rows to OG Core's egress provider, receives the
// user's masking policy and raises and follows 08 approvals.
package corelink

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
)

// Rule is one category of OG Core's masking policy (wire values).
type Rule struct {
	Category int  `json:"c"`
	Action   int  `json:"a"`
	UserSet  bool `json:"user"`
}

// Approval is OG Core's view of an approval (ApprovalParcel, the parts the gate uses).
type Approval struct {
	ID           string  `json:"id"`
	Kind         int     `json:"kind"`
	State        int     `json:"state"`
	LaneID       string  `json:"lane_id"`
	DecisionID   string  `json:"decision_id"`
	RaisedBy     string  `json:"raised_by"`
	Answer       *Answer `json:"answer"`
	CancelReason string  `json:"cancel_reason"`
}

type Answer struct {
	ActionID   string   `json:"action_id"`
	Role       int      `json:"role"`
	Source     int      `json:"source"`
	AnsweredBy string   `json:"answered_by"`
	Choices    []Choice `json:"choices"`
}

type Choice struct {
	Item      string `json:"item"`
	Treatment int    `json:"treatment"`
	On        bool   `json:"on"`
}

// Approval states and action roles (OG Core's ApprovalState, ActionRole).
const (
	StatePending   = 1
	StateAnswered  = 2
	StateCancelled = 3

	RoleApprove     = 1
	RoleAlternative = 2
	RoleSkip        = 3
	RoleTalk        = 4
	RoleTakeOver    = 5
)

// Request is an 08 gate approval to raise (ApprovalParcel's content model).
type Request struct {
	LaneID      string       `json:"lane_id,omitempty"`
	AccountID   string       `json:"account_id,omitempty"`
	RegionID    string       `json:"region_id,omitempty"`
	ThreadID    string       `json:"thread_id,omitempty"`
	Kicker      string       `json:"kicker"`
	Title       string       `json:"title"`
	Subtitle    string       `json:"subtitle,omitempty"`
	Footnote    string       `json:"footnote,omitempty"`
	GateIndex   int          `json:"gate_index"`
	GateCount   int          `json:"gate_count"`
	Disclosures []Disclosure `json:"disclosures"`
	Actions     []Action     `json:"actions"`
}

type Disclosure struct {
	ID      string `json:"id"`
	Field   string `json:"field"`
	Label   string `json:"label"`
	Preview string `json:"preview"`
	Allowed []int  `json:"allowed"`
	Default int    `json:"default"`
	Needed  bool   `json:"needed"`
}

type Action struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Role  int    `json:"role"`
	Style int    `json:"style"`
}

// Treatments and styles (OG Core's Treatment, ActionStyle).
const (
	TreatReal    = 1
	TreatMasked  = 4
	TreatBlocked = 5

	StylePrimary   = 1
	StyleSecondary = 2
	StyleTertiary  = 3
)

// Gate states (OG Core's GateState).
const (
	GateOK      = 1
	GateMasking = 2
	GateBlocked = 3
)

// Handlers receive what OG Core pushes. Called from the link's reader goroutine.
type Handlers struct {
	Policy   func([]Rule)
	Resolved func(Approval)
	StopAll  func(laneIDs []string)
	Lanes    func(map[string]string)
	Attached func(api int)
	Detached func()
}

// Link runs og-gate-link and keeps it running.
type Link struct {
	Path string
	Args []string
	Log  *slog.Logger
	H    Handlers
	// Debug (debuggable builds): log any descriptor that would have leaked into the helper.
	Debug bool

	mu      sync.Mutex
	stdin   io.WriteCloser
	waiters map[string]chan json.RawMessage
	health  *healthMsg
	pending []egressRow
	labels  map[string]string
	seq     atomic.Uint64
	up      atomic.Bool
	flushC  chan struct{}
}

type healthMsg struct {
	connected bool
	detail    string
}

// maxPending bounds ledger rows kept while OG Core is away.
const maxPending = 1000

// ErrUnavailable: OG Core isn't attached (or the helper is down).
var ErrUnavailable = errors.New("core_unavailable")

// ErrLinkUnavailable: the helper itself isn't running, for the requests that don't need OG Core
// (the keystore ops).
var ErrLinkUnavailable = errors.New("link_unavailable")

// Start runs the helper until ctx ends, restarting it when it exits.
func (l *Link) Start(ctx context.Context) {
	l.mu.Lock()
	l.waiters = map[string]chan json.RawMessage{}
	l.labels = map[string]string{}
	l.flushC = make(chan struct{}, 1)
	l.mu.Unlock()
	go l.flushLoop(ctx)
	go func() {
		backoff := time.Second
		for ctx.Err() == nil {
			start := time.Now()
			err := l.run(ctx)
			l.setDown()
			if ctx.Err() != nil {
				return
			}
			if time.Since(start) > time.Minute {
				backoff = time.Second
			}
			l.Log.Warn("og-gate-link exited; restarting", "err", err, "in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
		}
	}()
}

func (l *Link) run(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, l.Path, l.Args...) //nolint:gosec // the helper's path comes from the gate's command line
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	// Only stdin, stdout and stderr reach the helper (no ExtraFiles): descriptors the gate inherited
	// without close-on-exec (init's sockets) would otherwise follow it into its binder domain, where
	// SELinux refuses them (og-os M12).
	if leaked := closeOnExecAll(); l.Debug && len(leaked) > 0 {
		l.Log.Info("og-gate-link: marked close-on-exec", "fds", leaked)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	l.mu.Lock()
	l.stdin = stdin
	h := l.health
	l.mu.Unlock()
	if h != nil {
		l.write(map[string]any{"t": "health", "connected": h.connected, "detail": h.detail})
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		l.dispatch(sc.Bytes())
	}
	return cmd.Wait()
}

func (l *Link) setDown() {
	l.mu.Lock()
	l.stdin = nil
	for id, ch := range l.waiters {
		close(ch)
		delete(l.waiters, id)
	}
	l.mu.Unlock()
	if l.up.Swap(false) && l.H.Detached != nil {
		l.H.Detached()
	}
}

func (l *Link) dispatch(line []byte) {
	var m struct {
		T        string            `json:"t"`
		ID       string            `json:"id"`
		API      int               `json:"api"`
		Rules    []Rule            `json:"rules"`
		Approval json.RawMessage   `json:"approval"`
		LaneIDs  []string          `json:"lane_ids"`
		Lanes    []json.RawMessage `json:"lanes"`
		Error    string            `json:"error"`
		Op       string            `json:"op"`
	}
	if json.Unmarshal(line, &m) != nil {
		return
	}
	switch m.T {
	case "attached":
		l.up.Store(true)
		l.Log.Info("OG Core attached", "api", m.API)
		if l.H.Attached != nil {
			l.H.Attached(m.API)
		}
		l.kickFlush()
	case "detached":
		l.up.Store(false)
		l.Log.Warn("OG Core detached")
		if l.H.Detached != nil {
			l.H.Detached()
		}
	case "policy":
		if l.H.Policy != nil {
			l.H.Policy(m.Rules)
		}
	case "resolved":
		var a Approval
		if json.Unmarshal(m.Approval, &a) == nil && l.H.Resolved != nil {
			l.H.Resolved(a)
		}
	case "stop_all":
		if l.H.StopAll != nil {
			l.H.StopAll(m.LaneIDs)
		}
	case "lanes":
		labels := map[string]string{}
		for _, raw := range m.Lanes {
			var ln struct {
				ID    string `json:"id"`
				Title string `json:"title"`
			}
			if json.Unmarshal(raw, &ln) == nil && ln.ID != "" {
				labels[ln.ID] = laneLabel(ln.Title)
			}
		}
		l.mu.Lock()
		l.labels = labels
		l.mu.Unlock()
		if l.H.Lanes != nil {
			l.H.Lanes(labels)
		}
	case "raised", "approval", "sealed", "opened", "error":
		if m.T == "error" && m.ID == "" {
			l.Log.Warn("og-gate-link", "op", m.Op, "err", m.Error)
			return
		}
		l.mu.Lock()
		ch := l.waiters[m.ID]
		delete(l.waiters, m.ID)
		l.mu.Unlock()
		if ch != nil {
			ch <- append(json.RawMessage(nil), line...)
		}
	}
}

// laneLabel is the live list's lower-case lane label ("Travel · Berlin trip" → "travel").
func laneLabel(title string) string {
	t := strings.ToLower(strings.TrimSpace(title))
	if i := strings.IndexAny(t, " ·:-"); i > 0 {
		t = t[:i]
	}
	if len(t) > 16 {
		t = t[:16]
	}
	return t
}

func (l *Link) write(v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stdin == nil {
		return false
	}
	_, err = l.stdin.Write(append(b, '\n'))
	return err == nil
}

// Up reports whether OG Core is attached.
func (l *Link) Up() bool { return l.up.Load() }

// ReportHealth is the gate dot: connected=false shows red with the detail
// (decision: the gate dot and Settings say why chat can't send).
func (l *Link) ReportHealth(connected bool, detail string) {
	l.mu.Lock()
	changed := l.health == nil || l.health.connected != connected || l.health.detail != detail
	l.health = &healthMsg{connected: connected, detail: detail}
	l.mu.Unlock()
	if changed {
		l.write(map[string]any{"t": "health", "connected": connected, "detail": detail})
	}
}

// ReportState flashes MASKING or BLOCKED on the gate dot.
func (l *Link) ReportState(state int, detail string) {
	l.write(map[string]any{"t": "state", "state": state, "detail": detail})
}

func (l *Link) call(ctx context.Context, msg map[string]any) (json.RawMessage, error) {
	return l.request(ctx, msg, true)
}

// request sends msg and waits for the reply with its id. needCore: OG Core must be attached;
// otherwise the helper running is enough (the keystore ops).
func (l *Link) request(ctx context.Context, msg map[string]any, needCore bool) (json.RawMessage, error) {
	id := fmt.Sprintf("q%d", l.seq.Add(1))
	msg["id"] = id
	ch := make(chan json.RawMessage, 1)
	unavailable := ErrUnavailable
	if !needCore {
		unavailable = ErrLinkUnavailable
	}
	l.mu.Lock()
	if l.waiters == nil || (needCore && !l.up.Load()) || (!needCore && l.stdin == nil) {
		l.mu.Unlock()
		return nil, unavailable
	}
	l.waiters[id] = ch
	l.mu.Unlock()
	if !l.write(msg) {
		l.mu.Lock()
		delete(l.waiters, id)
		l.mu.Unlock()
		return nil, unavailable
	}
	select {
	case r, ok := <-ch:
		if !ok {
			return nil, unavailable
		}
		return r, nil
	case <-ctx.Done():
		l.mu.Lock()
		delete(l.waiters, id)
		l.mu.Unlock()
		return nil, ctx.Err()
	}
}

// Raise raises an 08 approval and returns its id.
func (l *Link) Raise(ctx context.Context, r *Request) (string, error) {
	resp, err := l.call(ctx, map[string]any{"t": "raise", "approval": r})
	if err != nil {
		return "", err
	}
	var m struct {
		T          string `json:"t"`
		ApprovalID string `json:"approval_id"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(resp, &m); err != nil || m.T != "raised" || m.ApprovalID == "" {
		return "", fmt.Errorf("raise: %s", m.Error)
	}
	return m.ApprovalID, nil
}

// Seal and Open run on og-gate-link's keystore2 key (the masking map's key-encryption key, og-os M12).
// They need the helper, not OG Core.
func (l *Link) Seal(ctx context.Context, plain, aad []byte) ([]byte, error) {
	return l.keyOp(ctx, "seal", "sealed", plain, aad)
}

func (l *Link) Open(ctx context.Context, sealed, aad []byte) ([]byte, error) {
	return l.keyOp(ctx, "open", "opened", sealed, aad)
}

func (l *Link) keyOp(ctx context.Context, op, want string, data, aad []byte) ([]byte, error) {
	resp, err := l.request(ctx, map[string]any{"t": op, "data": hex.EncodeToString(data), "aad": hex.EncodeToString(aad)}, false)
	if err != nil {
		return nil, err
	}
	var m struct {
		T     string `json:"t"`
		Data  string `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp, &m); err != nil || m.T != want {
		return nil, fmt.Errorf("%s: %s", op, m.Error)
	}
	return hex.DecodeString(m.Data)
}

// Cancel withdraws an approval the gate raised.
func (l *Link) Cancel(id, reason string) {
	l.write(map[string]any{"t": "cancel", "approval_id": id, "reason": reason})
}

// Get reads an approval from OG Core.
func (l *Link) Get(ctx context.Context, id string) (*Approval, error) {
	resp, err := l.call(ctx, map[string]any{"t": "get_approval", "approval_id": id})
	if err != nil {
		return nil, err
	}
	var m struct {
		T        string    `json:"t"`
		Approval *Approval `json:"approval"`
		Error    string    `json:"error"`
	}
	if err := json.Unmarshal(resp, &m); err != nil || m.T != "approval" {
		return nil, fmt.Errorf("get approval: %s", m.Error)
	}
	return m.Approval, nil
}

type egressRow struct {
	TsMs             int64  `json:"ts_ms"`
	LaneID           string `json:"lane_id,omitempty"`
	LaneLabel        string `json:"lane_label,omitempty"`
	RegionID         string `json:"region_id,omitempty"`
	Destination      string `json:"destination"`
	Kind             string `json:"kind"`
	AppPackage       string `json:"app_package,omitempty"`
	BytesOut         int64  `json:"bytes_out"`
	BytesIn          int64  `json:"bytes_in"`
	MaskedCount      int    `json:"masked_count"`
	MaskedCategories string `json:"masked_categories,omitempty"`
	Blocked          bool   `json:"blocked"`
	BlockReason      string `json:"block_reason,omitempty"`
	OnDevice         bool   `json:"on_device"`
	ApprovalID       string `json:"approval_id,omitempty"`
}

// callerPackages names the app a caller class stands for in OG Core's ledger.
var callerPackages = map[string]string{"chat": "ai.outgate.chat"}

// Record implements ledger.Sink. OG Core gets the rows that say what left the
// phone (content, refusals, on-device requests); long-polls, token refreshes and
// presence stay in the gate's own ledger only, so today's counters count messages
// rather than polls.
func (l *Link) Record(r *ledger.Row) {
	if !r.Content && !r.Blocked && !r.OnDevice {
		return
	}
	l.mu.Lock()
	label := l.labels[r.LaneID]
	l.mu.Unlock()
	row := egressRow{
		TsMs: r.Time.UnixMilli(), LaneID: r.LaneID, LaneLabel: label, RegionID: r.RegionID,
		Destination: r.Destination, Kind: r.Kind, AppPackage: callerPackages[r.Caller],
		BytesOut: r.BytesOut, BytesIn: r.BytesIn, MaskedCount: r.MaskedCount,
		MaskedCategories: ledger.Categories(r.MaskedCategories), Blocked: r.Blocked,
		BlockReason: r.BlockReason, OnDevice: r.OnDevice, ApprovalID: r.ApprovalID,
	}
	l.mu.Lock()
	l.pending = append(l.pending, row)
	if len(l.pending) > maxPending {
		l.pending = l.pending[len(l.pending)-maxPending:]
	}
	l.mu.Unlock()
	l.kickFlush()
	switch {
	case r.Blocked && r.Content:
		l.ReportState(GateBlocked, r.BlockReason)
	case r.MaskedCount > 0:
		l.ReportState(GateMasking, "")
	}
}

func (l *Link) kickFlush() {
	select {
	case l.flushC <- struct{}{}:
	default:
	}
}

// flushLoop sends pending rows in batches, at most every 250 ms.
func (l *Link) flushLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.flushC:
		}
		time.Sleep(250 * time.Millisecond)
		if !l.up.Load() {
			continue
		}
		l.mu.Lock()
		rows := l.pending
		l.pending = nil
		l.mu.Unlock()
		for len(rows) > 0 {
			n := min(len(rows), 64)
			if !l.write(map[string]any{"t": "egress", "rows": rows[:n]}) {
				l.mu.Lock()
				l.pending = append(rows, l.pending...)
				l.mu.Unlock()
				break
			}
			rows = rows[n:]
		}
	}
}
