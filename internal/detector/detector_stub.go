//go:build !onnx

package detector

import "github.com/outgate-ai/og-local/internal/pii"

func newDetector(_ Config) (pii.Detector, func() error, error) {
	return nil, nil, ErrUnavailable
}
