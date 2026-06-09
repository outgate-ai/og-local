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

// New constructs the PII detector for the current build. In the default
// pure-Go build it returns ErrUnavailable; in the onnx build it resolves the
// cached model and shared library and returns a real detector together with a
// close function.
func New(cfg Config) (pii.Detector, func() error, error) {
	return newDetector(cfg)
}
