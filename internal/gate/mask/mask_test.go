package mask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate"
	"github.com/outgate-ai/og-local/internal/pii"
)

// Obviously synthetic test values; none of them belongs to anyone.
const (
	testName  = "Testy McTestface"
	testEmail = "test.user@example.invalid"
	testPhone = "+1 555 0100 0199"
	testIBAN  = "DE89 3704 0044 0532 0130 00"
	testCard  = "4111 1111 1111 1111"
)

// unknownPH has a placeholder's shape but was never minted here.
var unknownPH = "OG_" + "PII_" + strings.Repeat("0", 18)

var phShape = regexp.MustCompile(`^OG_(PII|CREDENTIAL|SENSITIVE)_[0-9a-f]{16}$`)

// fakeDetector flags configured substrings, like the model would.
type fakeDetector struct {
	hits  map[string]pii.Class
	calls atomic.Int32
	texts []string
}

func (f *fakeDetector) Detect(_ context.Context, text string) ([]pii.Span, error) {
	f.calls.Add(1)
	f.texts = append(f.texts, text)
	var out []pii.Span
	for v, c := range f.hits {
		for i := 0; ; {
			j := strings.Index(text[i:], v)
			if j < 0 {
				break
			}
			out = append(out, pii.Span{Start: i + j, End: i + j + len(v), Class: c, Score: 0.9})
			i += j + len(v)
		}
	}
	return out, nil
}

func newTestMasker(t *testing.T, hits map[string]pii.Class) (*Masker, *fakeDetector, string) {
	t.Helper()
	dir := t.TempDir()
	fd := &fakeDetector{hits: hits}
	det := NewDetector(func() (pii.Detector, func() error, error) { return fd, func() error { return nil }, nil }, time.Minute)
	t.Cleanup(det.Close)
	return New(NewStore(dir, 30*24*time.Hour, 1000), det), fd, dir
}

func call(body string) *gate.Call {
	return &gate.Call{ContentType: "application/json", Raw: []byte(body), Content: true}
}

func TestMaskAndRestoreRoundTrip(t *testing.T) {
	m, fd, _ := newTestMasker(t, map[string]pii.Class{testName: pii.ClassPerson})
	in := `{"kind":"input.text","client_id":"c-1","payload":{"text":"Book a table for ` + testName +
		`, mail ` + testEmail + `, card ` + testCard + `"}}`
	out, masked, err := m.Mask(context.Background(), call(in), []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, v := range []string{testName, testEmail, testCard} {
		if strings.Contains(s, v) {
			t.Errorf("%q left the phone: %s", v, s)
		}
	}
	if !strings.Contains(s, `"kind":"input.text"`) || !strings.Contains(s, `"client_id":"c-1"`) {
		t.Errorf("structural fields changed: %s", s)
	}
	phs := Placeholders(s)
	if len(phs) != 3 {
		t.Fatalf("placeholders = %v in %s", phs, s)
	}
	for _, ph := range phs {
		if !phShape.MatchString(ph) {
			t.Errorf("placeholder %q has the wrong shape", ph)
		}
	}
	if masked.Count != 3 || masked.Categories["PII"] != 2 || masked.Categories["SENSITIVE"] != 1 {
		t.Errorf("masked = %+v", masked)
	}
	if fd.calls.Load() != 1 {
		t.Errorf("detector calls = %d, want 1 (one batch)", fd.calls.Load())
	}

	again, _, _ := m.Mask(context.Background(), call(in), []byte(in))
	if string(again) != s {
		t.Error("placeholders are not stable across requests")
	}

	reply := `{"events":[{"seq":7,"kind":"text_delta","payload":{"text":"Done: booked for ` + phs[0] + ` and ` + phs[1] + `"}},` +
		`{"seq":8,"kind":"tool_use","payload":{"input":{"to":"` + phs[2] + `","x":"` + unknownPH + `"}}}]}`
	rc := &gate.Call{RespContentType: "application/json"}
	back, restored := m.Restore(context.Background(), rc, []byte(reply))
	b := string(back)
	if !strings.Contains(b, testName) || !strings.Contains(b, testEmail) || !strings.Contains(b, testCard) {
		t.Errorf("not restored: %s", b)
	}
	if !strings.Contains(b, unknownPH) {
		t.Error("an unknown placeholder was touched")
	}
	if len(restored) != 3 || restored[0].Path != "events[0].payload.text" || restored[2].Path != "events[1].payload.input.to" {
		t.Errorf("restored = %+v", restored)
	}
	var v any
	if json.Unmarshal(back, &v) != nil {
		t.Error("restored body is not JSON")
	}
}

func TestPolicyActions(t *testing.T) {
	m, _, _ := newTestMasker(t, map[string]pii.Class{testName: pii.ClassPerson})
	in := `{"text":"` + testName + ` ` + testEmail + ` see https://shop.example.test/p?id=3&utm_source=news&fbclid=abc#top"}`

	m.SetPolicy(DefaultPolicy().Merge(map[Category]Action{Name: Allow, Email: Block}))
	out, masked, err := m.Mask(context.Background(), call(in), []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, testName) {
		t.Errorf("allowed name was masked: %s", s)
	}
	if strings.Contains(s, testEmail) || !strings.Contains(s, Blocked) {
		t.Errorf("blocked email: %s", s)
	}
	if !strings.Contains(s, "https://shop.example.test/p?id=3#top") {
		t.Errorf("trackers not stripped cleanly: %s", s)
	}
	if masked.Count != 0 || masked.Blocked != 3 {
		t.Errorf("masked = %+v", masked)
	}

	m.SetPolicy(DefaultPolicy().Merge(map[Category]Action{Email: Ask}))
	_, _, err = m.Mask(context.Background(), call(in), []byte(in))
	var na *NeedsApproval
	if !errors.As(err, &na) || !errors.Is(err, gate.ErrNeedsApproval) || len(na.Categories) != 1 || na.Categories[0] != Email {
		t.Errorf("ask: %v", err)
	}
}

func TestBinaryFollowsImagesPolicy(t *testing.T) {
	m, _, _ := newTestMasker(t, nil)
	c := &gate.Call{Binary: true, Raw: []byte("\x89PNG synthetic"), Content: true}
	if _, _, err := m.Mask(context.Background(), c, c.Raw); !errors.Is(err, gate.ErrNeedsApproval) {
		t.Errorf("image without approval: %v", err)
	}
	c.Approved = true
	if out, _, err := m.Mask(context.Background(), c, c.Raw); err != nil || !bytes.Equal(out, c.Raw) {
		t.Errorf("approved image: %q %v", out, err)
	}
	m.SetPolicy(DefaultPolicy().Merge(map[Category]Action{Images: Block}))
	if out, masked, err := m.Mask(context.Background(), c, c.Raw); err != nil || out != nil || masked.Blocked != 1 {
		t.Errorf("blocked image: %q %+v %v", out, masked, err)
	}
}

func TestFailClosed(t *testing.T) {
	dir := t.TempDir()
	det := NewDetector(func() (pii.Detector, func() error, error) { return nil, nil, errors.New("no model") }, time.Minute)
	m := New(NewStore(dir, time.Hour, 10), det)
	in := `{"text":"hello there"}`
	if _, _, err := m.Mask(context.Background(), call(in), []byte(in)); !errors.Is(err, gate.ErrDetectorUnavailable) {
		t.Errorf("no detector: %v", err)
	}
	if ok, why := m.Ready(); ok || why != ErrDetectorUnavailable.Error() {
		t.Errorf("Ready = %v %q", ok, why)
	}
	if st := det.Stats(); st.Loaded || st.Error == "" {
		t.Errorf("stats = %+v", st)
	}

	locked := New(NewStore(filepath.Join(dir, "missing"), time.Hour, 10), det)
	if _, _, err := locked.Mask(context.Background(), call(in), []byte(in)); !errors.Is(err, gate.ErrStorageLocked) {
		t.Errorf("locked storage: %v", err)
	}
}

func TestStorePersistsAndExpires(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, 30*24*time.Hour, 1000)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	phs, err := s.Assign([]Item{{Name, testName}, {Address, testName}, {Credential, "synthetic-secret-value"}})
	if err != nil {
		t.Fatal(err)
	}
	if phs[0] != phs[1] {
		t.Error("same label and value got two placeholders")
	}
	if !strings.HasPrefix(phs[2], "OG_CREDENTIAL_") {
		t.Errorf("credential placeholder %q", phs[2])
	}
	if fi, err := os.Stat(filepath.Join(dir, "key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", fi, err)
	}

	s2 := NewStore(dir, 30*24*time.Hour, 1000)
	s2.now = func() time.Time { return now.Add(10 * 24 * time.Hour) }
	if v, c, ok := s2.Lookup(phs[0]); !ok || v != testName || c != Name {
		t.Errorf("after reopen: %q %v %v", v, c, ok)
	}
	again, _ := s2.Assign([]Item{{Name, testName}})
	if again[0] != phs[0] {
		t.Error("placeholder changed after reopen (device key not kept)")
	}

	// 35 days after the first use: the credential (last used then) is gone, the name
	// (used again on day 10) is kept for 30 days after that.
	s3 := NewStore(dir, 30*24*time.Hour, 1000)
	s3.now = func() time.Time { return now.Add(35 * 24 * time.Hour) }
	if _, _, ok := s3.Lookup(phs[2]); ok {
		t.Error("expired placeholder still restores")
	}
	if _, _, ok := s3.Lookup(phs[0]); !ok {
		t.Error("placeholder used 25 days ago no longer restores")
	}
}

func TestStoreDifferentKeysDifferentPlaceholders(t *testing.T) {
	a, _ := NewStore(t.TempDir(), time.Hour, 10).Assign([]Item{{Name, testName}})
	b, _ := NewStore(t.TempDir(), time.Hour, 10).Assign([]Item{{Name, testName}})
	if a[0] == b[0] {
		t.Error("two devices minted the same placeholder")
	}
}

func TestBatchOffsets(t *testing.T) {
	m, fd, _ := newTestMasker(t, map[string]pii.Class{testName: pii.ClassPerson})
	var nodes []string
	for i := 0; i < 120; i++ {
		label := "Row label number " + strings.Repeat("x", i%7)
		if i == 77 {
			label = "Reservation for " + testName
		}
		nodes = append(nodes, `{"role":"text","label":"`+label+`"}`)
	}
	in := `{"snapshot":{"nodes":[` + strings.Join(nodes, ",") + `]}}`
	out, masked, err := m.Mask(context.Background(), call(in), []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), testName) || masked.Count != 1 {
		t.Errorf("snapshot not masked: count %d", masked.Count)
	}
	if n := fd.calls.Load(); n < 1 || n > 2 {
		t.Errorf("detector calls = %d, want the 120 labels batched", n)
	}
}
