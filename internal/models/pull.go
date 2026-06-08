package models

import (
	"context"
	"net/http"
)

type puller struct {
	fsys    FS
	rt      http.RoundTripper
	root    string
	baseURL string
}

func defaultPuller() puller {
	return puller{fsys: OSFS(), rt: http.DefaultTransport, root: CacheRoot(), baseURL: hfBaseURL}
}

func (p puller) pull(ctx context.Context, name string, onProgress ProgressFunc) error {
	m, err := resolve(name)
	if err != nil {
		return err
	}
	d := NewDownloaderWithBaseURL(p.rt, p.fsys, p.baseURL)
	dir := ModelDir(p.root, m)
	if err := d.Fetch(ctx, m, dir, onProgress); err != nil {
		return err
	}
	return WriteManifest(p.fsys, dir, m)
}

func (p puller) list() []Cached {
	out := make([]Cached, 0, len(catalog))
	for _, m := range All() {
		out = append(out, Cached{Model: m, Present: IsCached(p.fsys, ModelDir(p.root, m), m)})
	}
	return out
}

func Pull(ctx context.Context, name string, onProgress ProgressFunc) error {
	return defaultPuller().pull(ctx, name, onProgress)
}

type Cached struct {
	Model
	Present bool
}

func List() []Cached { return defaultPuller().list() }

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
