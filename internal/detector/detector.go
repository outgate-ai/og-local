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
}

// New returns the PII detector and its close function; the pure-Go build
// returns ErrUnavailable.
func New(cfg Config) (pii.Detector, func() error, error) {
	return newDetector(cfg)
}
