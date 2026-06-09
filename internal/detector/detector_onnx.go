//go:build onnx

package detector

import (
	"github.com/outgate-ai/og-local/internal/models"
	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/pii/onnx"
)

func newDetector(cfg Config) (pii.Detector, func() error, error) {
	model := models.Default()
	if cfg.ModelName != "" {
		m, ok := models.Lookup(cfg.ModelName)
		if !ok {
			return nil, nil, &models.UnknownModelError{Name: cfg.ModelName}
		}
		model = m
	}

	root := models.CacheRoot()
	dir := models.ModelDir(root, model)
	fsys := models.OSFS()
	if !models.IsCached(fsys, dir, model) {
		return nil, nil, ErrModelMissing
	}

	lib, err := models.SharedLibPath(fsys, root, cfg.LibPath)
	if err != nil {
		return nil, nil, err
	}

	det, err := onnx.New(dir, lib)
	if err != nil {
		return nil, nil, err
	}
	return det, func() error { det.Close(); return nil }, nil
}
