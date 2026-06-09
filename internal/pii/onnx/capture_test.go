//go:build onnx && manual

package onnx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fixture struct {
	Text     string      `json:"text"`
	Labels   []string    `json:"labels"`
	Offsets  [][2]int    `json:"offsets"`
	Logits   [][]float32 `json:"logits"`
	Expected []span      `json:"expected"`
}

type span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Class string `json:"class"`
}

func TestCaptureGoldenFixtures(t *testing.T) {
	md := os.Getenv("OGL_MODEL_DIR")
	lib := os.Getenv("OGL_ONNXRUNTIME_LIB")
	if md == "" || lib == "" {
		t.Skip("set OGL_MODEL_DIR and OGL_ONNXRUNTIME_LIB to capture")
	}

	det, err := New(md, lib)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer det.Close()

	labels, err := readLabels(filepath.Join(md, "config.json"))
	if err != nil {
		t.Fatalf("readLabels: %v", err)
	}

	cases := map[string]string{
		"email_phone": "My email is alice@example.com and my number is 415-555-0100.",
		"person":      "Contact John Smith about the contract.",
		"none":        "just a normal sentence with no private data",
		"account":     "Wire it to account 000123456789 by Friday.",
	}

	out := os.Getenv("OGL_FIXTURE_DIR")
	if out == "" {
		out = "testdata"
	}
	for name, text := range cases {
		ids, offsets := det.tok.encode(text)
		logits, err := det.run(ids)
		if err != nil {
			t.Fatalf("%s: run: %v", name, err)
		}
		spans := det.decoder.Decode(logits, offsets)

		fx := fixture{Text: text, Labels: labels, Offsets: offsets, Logits: logits}
		for _, s := range spans {
			fx.Expected = append(fx.Expected, span{Start: s.Start, End: s.End, Class: string(s.Class)})
		}
		data, err := json.MarshalIndent(fx, "", "  ")
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		path := filepath.Join(out, name+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		t.Logf("wrote %s (%d spans)", path, len(spans))
	}
}
