package detector

import (
	"errors"

	"github.com/outgate-ai/og-local/internal/pii"
)

var (
	ErrUnavailable  = errors.New("detector: this build cannot redact; reinstall with -tags onnx")
	ErrModelMissing = errors.New("detector: model not found; run 'ogl model pull' first")
)

type Config struct {
	ModelName string
	LibPath   string
	// Threads caps the detector's intra-op threads; 0 keeps the runtime default.
	Threads int
	// ModelFile, OptimizedPath and ProfilePrefix are onnx.WithModelFile,
	// WithOptimizedModelPath and WithProfiling; empty keeps the defaults.
	ModelFile     string
	OptimizedPath string
	ProfilePrefix string
}

// New returns the PII detector and its close function; the pure-Go build
// returns ErrUnavailable.
func New(cfg Config) (pii.Detector, func() error, error) { //nolint:gocritic // a value Config keeps call sites literal
	return newDetector(cfg)
}
