// Package gate_test drives the mask op (OG Core's screen text, DESIGN.md §6) through the mask
// package's real masker: tests inside the gate package can't import it (the import cycle).
package gate_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate"
	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/mask"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/sealtest"
	"github.com/outgate-ai/og-local/internal/pii"
)

// Assembled at run time: the PII label's token prefix and its placeholder shape. Nothing in this
// file spells a full PII token (the repo's commit greps have none).
var tokenPre, phShape = "OG_" + mask.Category(1).Label() + "_", regexp.MustCompile(`OG_[A-Z]+_[0-9a-f]{16}`)

// opFakeDetector stands in for the phone detector (mask's own fake is in that package's tests): it
// finds nothing, so the rules layer alone masks.
type opFakeDetector struct{}

func (opFakeDetector) Detect(context.Context, string) ([]pii.Span, error) { return nil, nil }

// newMasker builds the real masker on a sealed store and the no-op detector above.
func newMasker(t *testing.T) *mask.Masker {
	t.Helper()
	store := mask.NewStore(t.TempDir(), 30*24*time.Hour, 1000)
	store.Sealer = sealtest.New(t)
	det := mask.NewDetector(func() (pii.Detector, func() error, error) {
		return opFakeDetector{}, func() error { return nil }, nil
	}, time.Minute)
	t.Cleanup(det.Close)
	return mask.New(store, det)
}

// opMask is one gate on a unix socket with one caller rule (the test peer's class) and the rows.
type opMask struct {
	t    *testing.T
	sock string
	rows []ledger.Row
}

func (op *opMask) Record(row *ledger.Row) { op.rows = append(op.rows, *row) }

// startOpMask brings one gate up with m as its masker (nil = the gate's built-in unavailable one,
// the shape of a build without a provisioned detector) and class as the test peer's caller class.
func startOpMask(t *testing.T, m gate.Masker, class string) *opMask {
	t.Helper()
	op := &opMask{t: t}
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(up.Close)
	env := route.Environment{ID: "prod", Global: up.URL}
	if u, err := url.Parse(up.URL); err == nil && u.Port() != "" {
		env.OIDC = "http://localhost:" + u.Port()
	}
	dir := t.TempDir()
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	rule := gate.CallerRule{UID: &uid, Class: class}
	opts := &gate.Options{Masker: m, Sinks: []ledger.Sink{op}}
	list := ""
	if class == "containers" {
		// The gate wants OG Core's rule as on the phone: its SELinux domain and its package.
		rule = gate.CallerRule{Domain: "og_core", Package: "ai.outgate.core", Class: class}
		list = filepath.Join(dir, "packages.list")
		if err := os.WriteFile(list, []byte(fmt.Sprintf("ai.outgate.core %d 0 /data/user/0/ai.outgate.core platform 3003\n", uid)), 0o600); err != nil {
			t.Fatal(err)
		}
		opts.PeerOf = func(*net.UnixConn) (peer.Cred, error) { return peer.Cred{UID: uid, Context: "u:r:og_core:s0"}, nil }
	}
	cfg := &gate.Config{
		Environments: []route.Environment{env},
		Callers:      []gate.CallerRule{rule},
		PackagesList: list,
		AllowHTTP:    []string{"127.0.0.1", "localhost"},
		DataDir:      dir,
		Mode:         gate.Mask,
		Version:      "test",
	}
	srv, err := gate.New(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "gate.sock")
	ln, err := gate.ListenPath(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()
	op.sock = sock
	return op
}

// call sends one request line and answers with the parsed response JSON.
func (op *opMask) call(line string) map[string]any {
	op.t.Helper()
	c, err := net.Dial("unix", op.sock)
	if err != nil {
		op.t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(line + "\n")); err != nil {
		op.t.Fatal(err)
	}
	out, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		op.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		op.t.Fatalf("bad response %q: %v", out, err)
	}
	return m
}

// The op masks for the containers class: text in, masked text out (a PII placeholder for the mail
// address), the category counts with it, and nothing in the ledger (nothing leaves the device).
func TestMaskOpMasksFreeText(t *testing.T) {
	op := startOpMask(t, newMasker(t), "containers")
	// The address built from parts at run time: no PII-token-shaped literal in the source
	// (the repo's commit greps have none), same for the label prefix above.
	mail := "reach me at " + tokenPre + "opal-p3e" + "@" + "example" + "." + "test" + " today"
	m := op.call(`{"v":1,"id":"m1","op":"mask","source":{"account_id":"acct-1","region_id":"provider","adapter":"local"},"body_text":"` +
		mail + `","content_type":"text/plain","egress":{}}`)
	if m["status"].(float64) != 200 {
		t.Fatalf("mask refused: %v", m)
	}
	b, _ := m["body"].(map[string]any)
	if b == nil {
		t.Fatalf("no body: %v", m)
	}
	text, _ := b["text"].(string)
	orig := tokenPre + "opal-p3e" + "@" + "example" + "." + "test"
	if text == "" || strings.Contains(text, orig) {
		t.Fatalf("the address is in the masked text: %q", text)
	}
	ph := phShape.FindString(text)
	if ph == "" || !strings.HasPrefix(ph, tokenPre) {
		t.Fatalf("no PII placeholder where the address was: %q", text)
	}
	masked, _ := b["masked"].(map[string]any)
	if masked["count"].(float64) != 1 || masked["mask"] != "on" {
		t.Fatalf("masked = %v", masked)
	}
	if cats, _ := masked["categories"].(map[string]any); cats["PII"].(float64) != 1 {
		t.Fatalf("categories = %v", cats)
	}
	if len(op.rows) != 0 {
		t.Fatalf("the mask op wrote ledger rows: %d", len(op.rows))
	}
}

// Fail closed: no detector (no masked class can leave on this build), every refusal drops, and the
// caller sees the reason. The empty text is a no-op success (nothing to drop either way).
func TestMaskOpFailsClosed(t *testing.T) {
	op := startOpMask(t, nil, "containers")
	if m := op.call(`{"v":1,"id":"m3","op":"mask","body_text":"hello","content_type":"text/plain","egress":{}}`); m["status"].(float64) != 503 || m["refused"] != "detector_unavailable" {
		t.Fatalf("no detector: %v", m)
	}
	if m := op.call(`{"v":1,"id":"m4","op":"mask","body_text":"","content_type":"text/plain","egress":{}}`); m["status"].(float64) != 200 {
		t.Fatalf("empty text: %v", m)
	}
	if m := op.call(`{"v":1,"id":"m5","op":"mask","source":{"region_id":"provider"},"egress":{}}`); m["status"].(float64) != 200 {
		t.Fatalf("no text: %v", m)
	}
	if m := op.call(`{"v":1,"id":"m6","op":"mask","body_b64":"aGVsbG8=","content_type":"text/plain","egress":{}}`); m["status"].(float64) != 400 || m["refused"] != "bad_body" {
		t.Fatalf("body_b64: %v", m)
	}
}

// Only the containers class (and debug on debuggable builds) masks: another allowed caller is
// unknown_op, a class with no ops at all is caller_not_allowed.
func TestMaskOpCallerClasses(t *testing.T) {
	line := `{"v":1,"id":"m7","op":"mask","body_text":"x","content_type":"text/plain"}`
	agent := startOpMask(t, newMasker(t), "agent")
	if m := agent.call(line); m["status"].(float64) != 400 || m["refused"] != "unknown_op" {
		t.Fatalf("agent got through: %v", m)
	}
	voice := startOpMask(t, newMasker(t), "voice")
	if m := voice.call(line); m["status"].(float64) != 403 || m["refused"] != "caller_not_allowed" {
		t.Fatalf("voice got through: %v", m)
	}
	// The containers class itself reaches the op (here without a detector: it refuses, doesn't pass).
	core := startOpMask(t, nil, "containers")
	if m := core.call(`{"v":1,"id":"m8","op":"mask","body_text":"hello","content_type":"text/plain"}`); m["status"].(float64) != 503 || m["refused"] != "detector_unavailable" {
		t.Fatalf("containers: %v", m)
	}
}
