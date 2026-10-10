//go:build onnx && manual

package onnx

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/outgate-ai/og-local/internal/pii"
)

// TestDetectMatchesGoldenFixtures runs the real model over the fixture texts and
// checks the spans and the logits against the captured ones, so a runtime or model
// change that shifts detections shows up before it ships.
func TestDetectMatchesGoldenFixtures(t *testing.T) {
	md := os.Getenv("OGL_MODEL_DIR")
	lib := os.Getenv("OGL_ONNXRUNTIME_LIB")
	if md == "" || lib == "" {
		t.Skip("set OGL_MODEL_DIR and OGL_ONNXRUNTIME_LIB")
	}
	det, err := New(md, lib)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer det.Close()

	paths, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	if len(paths) == 0 {
		t.Fatal("no fixtures")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fx fixture
			if err := json.Unmarshal(data, &fx); err != nil {
				t.Fatal(err)
			}
			ids, _ := det.tok.encode(fx.Text)
			logits, err := det.run(ids)
			if err != nil {
				t.Fatal(err)
			}
			var maxDiff float64
			for i := range logits {
				for j := range logits[i] {
					maxDiff = math.Max(maxDiff, math.Abs(float64(logits[i][j]-fx.Logits[i][j])))
				}
			}
			t.Logf("max |logit diff| = %.4f", maxDiff)

			spans, err := det.Detect(t.Context(), fx.Text)
			if err != nil {
				t.Fatal(err)
			}
			var want []pii.Span
			for _, w := range fx.Expected {
				want = append(want, pii.Span{Start: w.Start, End: w.End, Class: pii.Class(w.Class)})
			}
			want = pii.TrimSpans(fx.Text, want)
			if len(spans) != len(want) {
				t.Fatalf("spans = %+v, want %+v", spans, want)
			}
			for i, s := range spans {
				w := want[i]
				if s.Start != w.Start || s.End != w.End || s.Class != w.Class {
					t.Errorf("span %d = %d-%d %s, want %d-%d %s", i, s.Start, s.End, s.Class, w.Start, w.End, w.Class)
				}
			}
		})
	}
}
