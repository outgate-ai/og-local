package launch

import (
	"github.com/outgate-ai/og-local/internal/detector"
	"github.com/outgate-ai/og-local/internal/pii"
)

func defaultNewDetector() (pii.Detector, func() error, error) {
	return detector.New(detector.Config{})
}
