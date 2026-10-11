package main

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate"
	"github.com/outgate-ai/og-local/internal/gate/mask"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/pii"
)

// The gate dot: no external providers, no detector needed, green; a provider whose
// content can't be masked keeps the dot green with the reason; red only if
// gate.conf masks Outgate itself and the detector can't run.
func TestGateHealth(t *testing.T) {
	var loads, probes atomic.Int32
	det := mask.NewDetector(func() (pii.Detector, func() error, error) {
		loads.Add(1)
		return nil, nil, errors.New("no model")
	}, time.Minute)
	det.Present = func() error {
		probes.Add(1)
		return errors.New("model not provisioned")
	}
	m := mask.New(mask.NewStore(t.TempDir(), time.Hour, 10), det)
	health := func(classes []gate.ClassRule) (bool, string) {
		t.Helper()
		cfg := &gate.Config{DataDir: t.TempDir(), Mode: gate.Mask, Classes: classes}
		srv, err := gate.New(cfg, &gate.Options{Masker: m})
		if err != nil {
			t.Fatal(err)
		}
		return gateHealth(srv, cfg, m)
	}

	if ok, detail := health(nil); !ok || detail != gate.DetectorNotNeeded {
		t.Errorf("no providers: %v %q", ok, detail)
	}
	if loads.Load() != 0 || probes.Load() != 0 {
		t.Errorf("the detector was touched without a provider: loads %d, probes %d", loads.Load(), probes.Load())
	}
	provider := []gate.ClassRule{{Class: "provider", Mask: true, Destinations: []route.Provider{{ID: "a", Base: "https://llm.example.test"}}}}
	if ok, detail := health(provider); !ok || !strings.Contains(detail, "external providers can't leave") {
		t.Errorf("provider without a detector: %v %q", ok, detail)
	}
	if ok, detail := health([]gate.ClassRule{{Class: "outgate", Mask: true}}); ok || !strings.Contains(detail, "model not provisioned") {
		t.Errorf("Outgate masked without a detector: %v %q", ok, detail)
	}
	if loads.Load() != 0 {
		t.Errorf("health loaded the detector %d times", loads.Load())
	}
}
