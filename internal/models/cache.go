package models

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const manifestName = ".ogl-manifest.json"

// CacheRoot resolves the cache base directory: OGL_CACHE_DIR, else
// XDG_CACHE_HOME/og-local, else ~/.cache/og-local.
func CacheRoot() string {
	if v := os.Getenv("OGL_CACHE_DIR"); v != "" {
		return v
	}
	if v := os.Getenv("XDG_CACHE_HOME"); v != "" {
		return filepath.Join(v, "og-local")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		//coverage:ignore reason=UserHomeDir only fails when HOME is unset; not portably testable.
		return filepath.Join(".", ".cache", "og-local")
	}
	return filepath.Join(home, ".cache", "og-local")
}

// ModelDir is the snapshot directory for a model, mirroring the
// huggingface_hub layout: <root>/models/models--<org>--<name>/snapshots/<rev>.
func ModelDir(root string, m Model) string {
	repo := "models--" + strings.ReplaceAll(m.Repo, "/", "--")
	return filepath.Join(root, "models", repo, "snapshots", m.Revision)
}

type manifest struct {
	Name     string   `json:"name"`
	Revision string   `json:"revision"`
	Files    []string `json:"files"`
}

// IsCached reports whether every file of m is present at its expected size and
// a matching manifest exists.
func IsCached(fsys FS, dir string, m Model) bool {
	mf, err := readManifest(fsys, dir)
	if err != nil || mf.Revision != m.Revision {
		return false
	}
	for _, f := range m.Files {
		fi, err := fsys.Stat(filepath.Join(dir, f.Path))
		if err != nil {
			return false
		}
		if f.Size > 0 && fi.Size() != f.Size {
			return false
		}
	}
	return true
}

// WriteManifest records the completed download.
func WriteManifest(fsys FS, dir string, m Model) error {
	paths := make([]string, len(m.Files))
	for i, f := range m.Files {
		paths[i] = f.Path
	}
	data, err := json.Marshal(manifest{Name: m.Name, Revision: m.Revision, Files: paths})
	if err != nil {
		//coverage:ignore reason=Marshal of string/[]string fields cannot fail.
		return err
	}
	w, err := fsys.Create(filepath.Join(dir, manifestName))
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

func readManifest(fsys FS, dir string) (manifest, error) {
	f, err := fsys.Open(filepath.Join(dir, manifestName))
	if err != nil {
		return manifest{}, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		return manifest{}, err
	}
	var mf manifest
	if err := json.Unmarshal(data, &mf); err != nil {
		return manifest{}, err
	}
	return mf, nil
}
