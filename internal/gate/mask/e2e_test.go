package mask

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/outgate-ai/og-local/internal/gate"
	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/pii"
)

type rows struct {
	mu  sync.Mutex
	all []ledger.Row
}

func (r *rows) Record(row *ledger.Row) {
	r.mu.Lock()
	r.all = append(r.all, *row)
	r.mu.Unlock()
}

// The gate in mask mode: the region sees placeholders, the caller sees values.
func TestGateMasksOutgoingAndRestoresIncoming(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, string(b))
		mu.Unlock()
		var in struct {
			Payload struct {
				Text string `json:"text"`
			} `json:"payload"`
		}
		_ = json.Unmarshal(b, &in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{
			map[string]any{"kind": "text_delta", "payload": map[string]any{"text": "You said: " + in.Payload.Text}},
		}})
	}))
	defer up.Close()

	m, _, _ := newTestMasker(t, map[string]pii.Class{testName: pii.ClassPerson})
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	dir := t.TempDir()
	rec := &rows{}
	cfg := &gate.Config{
		Environments: []route.Environment{{ID: "prod", Global: up.URL, OIDC: "https://oidc.example.test"}},
		Classes:      providerClasses(up.URL),
		Callers:      []gate.CallerRule{{UID: &uid, Class: "chat"}},
		AllowHTTP:    []string{"127.0.0.1", "localhost"},
		DataDir:      dir, Mode: gate.Mask, Version: "test",
	}
	srv, err := gate.New(cfg, &gate.Options{Masker: m, Sinks: []ledger.Sink{rec}})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "g.sock")
	ln, err := gate.ListenPath(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	type response struct {
		Status   int             `json:"status"`
		Body     json.RawMessage `json:"body"`
		Masked   map[string]any  `json:"masked"`
		Class    string          `json:"class"`
		Restored []map[string]string
	}
	call := func(region, path, text string) response {
		t.Helper()
		req, _ := json.Marshal(map[string]any{
			"source": map[string]any{"region_id": region, "adapter": "chat"}, "method": "POST", "path": path,
			"body": map[string]any{"kind": "input.text", "payload": map[string]any{"text": text}}, "egress": map[string]any{},
		})
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write(append(req, '\n'))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var resp response
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	text := "Ask " + testName + " at " + testEmail
	resp := call("provider:llm", "/v1/messages", text)
	mu.Lock()
	sent := seen[0]
	mu.Unlock()
	if strings.Contains(sent, testName) || strings.Contains(sent, testEmail) || len(Placeholders(sent)) != 2 {
		t.Fatalf("upstream saw %s", sent)
	}
	if resp.Status != 200 || !strings.Contains(string(resp.Body), "You said: "+text) {
		t.Errorf("caller got %d %s", resp.Status, resp.Body)
	}
	if resp.Masked["count"].(float64) != 2 || len(resp.Restored) != 2 || resp.Restored[0]["path"] != "events[0].payload.text" {
		t.Errorf("masked %v restored %v", resp.Masked, resp.Restored)
	}
	rec.mu.Lock()
	row := rec.all[len(rec.all)-1]
	rec.mu.Unlock()
	if row.MaskedCount != 2 || row.MaskedCategories["PII"] != 2 || row.RestoredCount != 2 || row.Blocked || ledger.Outcome(&row) != "MASKED" {
		t.Errorf("row = %+v", row)
	}
	b, _ := json.Marshal(row)
	if strings.Contains(string(b), testName) || strings.Contains(string(b), "OG_PII_") {
		t.Errorf("ledger row holds a value or a placeholder: %s", b)
	}
	if row.Class != "provider" || row.Mask != gate.MaskOn || resp.Class != "provider" || resp.Masked["mask"] != gate.MaskOn {
		t.Errorf("class/mask: row %s/%s, response %s/%v", row.Class, row.Mask, resp.Class, resp.Masked["mask"])
	}

	// The same text to Outgate leaves as it is: the region's guardrail masks it.
	out := call("global", "/api/v1/agents/threads/thr-fake-m08/events", text)
	mu.Lock()
	sent = seen[1]
	mu.Unlock()
	if !strings.Contains(sent, testName) || !strings.Contains(sent, testEmail) || len(Placeholders(sent)) != 0 {
		t.Errorf("Outgate saw %s", sent)
	}
	if out.Status != 200 || out.Class != "outgate" || out.Masked["count"].(float64) != 0 || out.Masked["mask"] != gate.MaskNotRequired {
		t.Errorf("Outgate response %+v", out)
	}
	rec.mu.Lock()
	row = rec.all[len(rec.all)-1]
	rec.mu.Unlock()
	if row.Class != "outgate" || row.Mask != gate.MaskNotRequired || row.MaskedCount != 0 || !row.Content || ledger.Outcome(&row) != "CLEAN" {
		t.Errorf("Outgate row = %+v", row)
	}

	// A placeholder this gate minted earlier comes back filled in from Outgate too
	// (threads from before Outgate traffic went unmasked); nothing else changes.
	ph := Placeholders(seen[0])[0]
	back := call("global", "/api/v1/agents/threads/thr-fake-m08/events", "earlier: "+ph)
	if !strings.Contains(string(back.Body), "You said: earlier: ") || strings.Contains(string(back.Body), ph) || len(back.Restored) != 1 {
		t.Errorf("legacy placeholder not restored: %s %v", back.Body, back.Restored)
	}
}
