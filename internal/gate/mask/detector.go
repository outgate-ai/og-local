package mask

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/redact"
	"github.com/outgate-ai/og-local/internal/storage/memory"
)

// ErrDetectorUnavailable: the model isn't provisioned or failed to load.
var ErrDetectorUnavailable = errors.New("detector_unavailable")

// Loader opens the detector; Close releases it.
type Loader func() (pii.Detector, func() error, error)

// Detector loads the model on first use and unloads it after an idle period, so
// its ~1 GB is resident only while agent traffic flows (lead decision, step 1).
type Detector struct {
	load Loader
	idle time.Duration
	now  func() time.Time
	// Present, when set, says cheaply (without loading) whether the model is there.
	Present func() error

	mu       sync.Mutex
	pipe     *redact.Pipeline
	closeFn  func() error
	lastUse  time.Time
	stats    DetectorStats
	timer    *time.Timer
	failedAt time.Time
}

// DetectorStats goes into the gate's health (first-message latency is visible).
type DetectorStats struct {
	Loaded     bool      `json:"loaded"`
	Loads      int       `json:"loads"`
	LastLoadMs int64     `json:"last_load_ms,omitempty"`
	LastLoadAt time.Time `json:"last_load_at,omitzero"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
	Error      string    `json:"error,omitempty"`
	Unloads    int       `json:"unloads"`
}

func NewDetector(load Loader, idle time.Duration) *Detector {
	return &Detector{load: load, idle: idle, now: time.Now}
}

// retryAfterFailure keeps a missing model from being re-probed on every request.
const retryAfterFailure = 30 * time.Second

func (d *Detector) pipeline() (*redact.Pipeline, error) {
	if d.pipe != nil {
		return d.pipe, nil
	}
	if !d.failedAt.IsZero() && d.now().Sub(d.failedAt) < retryAfterFailure {
		return nil, ErrDetectorUnavailable
	}
	start := d.now()
	det, closeFn, err := d.load()
	if err != nil {
		d.failedAt = d.now()
		d.stats.Error = err.Error()
		return nil, ErrDetectorUnavailable
	}
	cache, err := memory.New[[]pii.Span](8192)
	if err != nil {
		_ = closeFn()
		return nil, err
	}
	p, err := redact.New(det, cache)
	if err != nil {
		_ = closeFn()
		return nil, err
	}
	d.pipe, d.closeFn, d.failedAt = p, closeFn, time.Time{}
	d.stats.Loaded, d.stats.Error = true, ""
	d.stats.Loads++
	d.stats.LastLoadMs = d.now().Sub(start).Milliseconds()
	d.stats.LastLoadAt = start.UTC()
	return p, nil
}

// Spans runs the detector over texts (each one a batch of fields).
func (d *Detector) Spans(ctx context.Context, texts []string) ([][]pii.Span, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, err := d.pipeline()
	if err != nil {
		return nil, err
	}
	out := make([][]pii.Span, len(texts))
	for i, t := range texts {
		spans, err := p.Spans(ctx, t)
		if err != nil {
			return nil, err
		}
		out[i] = spans
	}
	d.lastUse = d.now()
	d.stats.LastUsedAt = d.lastUse.UTC()
	d.armIdle()
	return out, nil
}

func (d *Detector) armIdle() {
	if d.idle <= 0 {
		return
	}
	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.idle, d.unloadIfIdle)
}

func (d *Detector) unloadIfIdle() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pipe == nil || d.now().Sub(d.lastUse) < d.idle {
		return
	}
	d.unload()
}

func (d *Detector) unload() {
	if d.closeFn != nil {
		_ = d.closeFn()
	}
	d.pipe, d.closeFn = nil, nil
	d.stats.Loaded = false
	d.stats.Unloads++
}

// Usable reports, without loading anything, whether a request could use the model
// now: it is loaded, or not loaded and not known to be missing.
func (d *Detector) Usable() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pipe != nil {
		return nil
	}
	if !d.failedAt.IsZero() && d.now().Sub(d.failedAt) < retryAfterFailure {
		return ErrDetectorUnavailable
	}
	if d.Present != nil {
		if err := d.Present(); err != nil {
			d.stats.Error = err.Error()
			return ErrDetectorUnavailable
		}
		d.stats.Error = ""
	}
	return nil
}

// Reason is the last load or presence error, for the gate dot's detail.
func (d *Detector) Reason() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats.Error
}

func (d *Detector) Stats() DetectorStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

func (d *Detector) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
	if d.pipe != nil {
		d.unload()
	}
}
