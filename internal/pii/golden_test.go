package pii

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type goldenFixture struct {
	Text     string      `json:"text"`
	Labels   []string    `json:"labels"`
	Offsets  [][2]int    `json:"offsets"`
	Logits   [][]float32 `json:"logits"`
	Expected []struct {
		Start int    `json:"start"`
		End   int    `json:"end"`
		Class string `json:"class"`
	} `json:"expected"`
}

func TestDecodeGoldenFixtures(t *testing.T) {
	dir := filepath.Join("onnx", "testdata")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixtures dir: %v", err)
	}
	seen := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		seen++
		t.Run(e.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var fx goldenFixture
			if err := json.Unmarshal(data, &fx); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			d := NewDecoder(fx.Labels, TransitionBiases{})
			got := d.Decode(fx.Logits, fx.Offsets)

			if len(got) != len(fx.Expected) {
				t.Fatalf("got %d spans, want %d: %+v", len(got), len(fx.Expected), got)
			}
			for i, want := range fx.Expected {
				if got[i].Start != want.Start || got[i].End != want.End || string(got[i].Class) != want.Class {
					t.Errorf("span %d: got [%d:%d]%s, want [%d:%d]%s",
						i, got[i].Start, got[i].End, got[i].Class, want.Start, want.End, want.Class)
				}
			}
		})
	}
	if seen == 0 {
		t.Fatal("no golden fixtures found")
	}
}
