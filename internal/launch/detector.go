package launch

import (
	"os"

	"github.com/outgate-ai/og-local/internal/detector"
	"github.com/outgate-ai/og-local/internal/pii"
)

func detectorConfigFromEnv(getenv func(string) string) detector.Config {
	return detector.Config{LibPath: getenv("OGL_ONNXRUNTIME_LIB")}
}

func defaultNewDetector() (pii.Detector, func() error, error) {
	return detector.New(detectorConfigFromEnv(os.Getenv))
}
