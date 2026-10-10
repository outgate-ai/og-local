//go:build !onnx

package detector

import "github.com/outgate-ai/og-local/internal/pii"

func newDetector(_ Config) (pii.Detector, func() error, error) { //nolint:gocritic // matches the onnx build
	return nil, nil, ErrUnavailable
}
