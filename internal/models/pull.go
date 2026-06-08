package models

import (
	"context"
	"net/http"
)

// Pull downloads the named model (or the default if name is "") into the cache,
// reporting progress via onProgress.
func Pull(ctx context.Context, name string, onProgress ProgressFunc) error {
	m, err := resolve(name)
	if err != nil {
		return err
	}
	root := CacheRoot()
	fsys := OSFS()
	d := NewDownloader(http.DefaultTransport, fsys)
	dir := ModelDir(root, m)
	if err := d.Fetch(ctx, m, dir, onProgress); err != nil {
		return err
	}
	return WriteManifest(fsys, dir, m)
}

// Cached describes a model's presence in the cache.
type Cached struct {
	Model
	Present bool
}

// List reports, for every catalog model, whether it is fully cached.
func List() []Cached {
	root := CacheRoot()
	fsys := OSFS()
	out := make([]Cached, 0, len(catalog))
	for _, m := range All() {
		out = append(out, Cached{Model: m, Present: IsCached(fsys, ModelDir(root, m), m)})
	}
	return out
}

func resolve(name string) (Model, error) {
	if name == "" {
		return Default(), nil
	}
	m, ok := Lookup(name)
	if !ok {
		return Model{}, &UnknownModelError{Name: name}
	}
	return m, nil
}

type UnknownModelError struct{ Name string }

func (e *UnknownModelError) Error() string { return "models: unknown model " + e.Name }
