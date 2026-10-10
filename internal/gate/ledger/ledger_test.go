package ledger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFilesRotateAndRetain(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "egress-2020-01-01.jsonl")
	if err := os.WriteFile(old, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dir, "unrelated.txt")
	_ = os.WriteFile(keep, nil, 0o600)

	f, err := NewFiles(dir, 30*24*time.Hour, func(err error) { t.Error(err) })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 23, 59, 0, 0, time.UTC)
	f.now = func() time.Time { return now }
	f.Record(&Row{ID: "a", Method: "POST"})
	now = now.Add(2 * time.Minute)
	f.Record(&Row{ID: "b", Method: "GET"})
	_ = f.Close()

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old ledger file not deleted")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("unrelated file deleted")
	}
	for day, id := range map[string]string{"2026-10-10": "a", "2026-10-11": "b"} {
		fh, err := os.Open(filepath.Join(dir, "egress-"+day+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		if !sc.Scan() {
			t.Fatalf("%s: empty", day)
		}
		var r Row
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil || r.ID != id {
			t.Errorf("%s: row %+v err %v, want id %s", day, r, err, id)
		}
		_ = fh.Close()
	}
}

func TestRingTotalsAndOrder(t *testing.T) {
	r := NewRing(3)
	r.Record(&Row{ID: "1", Content: true})
	r.Record(&Row{ID: "2", Content: true, MaskedCount: 2})
	r.Record(&Row{ID: "3", Blocked: true})
	r.Record(&Row{ID: "4", OnDevice: true})
	last := r.Last(10)
	if len(last) != 3 || last[0].ID != "4" || last[2].ID != "2" {
		t.Fatalf("Last = %+v", last)
	}
	tot := r.Totals()
	if tot.Requests != 4 || tot.Clean != 1 || tot.Masked != 1 || tot.Blocked != 1 || tot.OnDevice != 1 || tot.Values != 2 || tot.Content != 2 {
		t.Errorf("totals = %+v", tot)
	}
}

func TestCategories(t *testing.T) {
	if got := Categories(map[string]int{"PII": 2, "CREDENTIAL": 1}); got != "CREDENTIAL:1,PII:2" {
		t.Errorf("got %q", got)
	}
}
