//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/models"
)

func TestModelPullEndToEnd(t *testing.T) {
	files := map[string]string{
		"config.json":     `{"hidden_size": 8}`,
		"tokenizer.json":  strings.Repeat("vocab", 200),
		"onnx/model.onnx": strings.Repeat("WEIGHTS", 500),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, body := range files {
			if strings.HasSuffix(r.URL.Path, "/"+name) {
				http.ServeContent(w, r, name, time.Time{}, strings.NewReader(body))
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := models.Model{
		Name:     "fixture/tiny",
		Repo:     "fixture/tiny",
		Revision: "rev0",
	}
	for name, body := range files {
		sum := sha256.Sum256([]byte(body))
		m.Files = append(m.Files, models.File{
			Path:   name,
			Size:   int64(len(body)),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}

	dir := t.TempDir()
	d := models.NewDownloaderWithBaseURL(http.DefaultTransport, models.OSFS(), srv.URL)
	if err := d.Fetch(context.Background(), m, dir, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if err := models.WriteManifest(models.OSFS(), dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	for name, body := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != body {
			t.Errorf("%s content mismatch", name)
		}
	}

	if !models.IsCached(models.OSFS(), dir, m) {
		t.Error("IsCached = false after full pull")
	}
}
