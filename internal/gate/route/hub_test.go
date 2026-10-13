package route

import (
	"errors"
	"net/url"
	"testing"
)

const testRev = "0123456789abcdef0123456789abcdef01234567"

func TestHub(t *testing.T) {
	base, _ := url.Parse(HubOrigin)
	d, err := Hub(base, "ggml-org/gemma-4-E2B-it-GGUF", testRev, "gemma-4-E2B-it-Q4_0.gguf")
	if err != nil || d.URL.String() != "https://huggingface.co/ggml-org/gemma-4-E2B-it-GGUF/resolve/"+testRev+"/gemma-4-E2B-it-Q4_0.gguf" ||
		d.Class != ClassMirror || d.Display != "huggingface.co" {
		t.Fatalf("Hub = %+v, %v", d, err)
	}
	for _, repo := range []string{"", "gemma", "a/b/c", "../x", "a/..", "-a/b", "a/.b", "a b/c", "a/b?x"} {
		if _, err := Hub(base, repo, testRev, "f.gguf"); !errors.Is(err, ErrBadRepo) {
			t.Errorf("repo %q: %v", repo, err)
		}
	}
	for _, rev := range []string{"", "main", "v1.0", testRev[:39], testRev + "0", "0123456789ABCDEF0123456789ABCDEF01234567"} {
		if _, err := Hub(base, "o/r", rev, "f.gguf"); !errors.Is(err, ErrBadRepo) {
			t.Errorf("revision %q: %v", rev, err)
		}
	}
	for _, p := range []string{"", "/f.gguf", "../f.gguf", "a//f.gguf", "f.gguf?download=1"} {
		if _, err := Hub(base, "o/r", testRev, p); !errors.Is(err, ErrBadPath) {
			t.Errorf("path %q: %v", p, err)
		}
	}
}

func TestHubRedirect(t *testing.T) {
	base, _ := url.Parse(HubOrigin)
	for raw, want := range map[string]bool{
		"https://huggingface.co/api/resolve-cache/x":   true,
		"https://cas-bridge.xethub.hf.co/xet-bridge/x": true,
		"https://cdn-lfs-eu-1.hf.co/repos/x":           true,
		"https://CDN-LFS.HuggingFace.co/x":             true,
		"https://hf.co/x":                              true,
		"http://cdn-lfs.hf.co/x":                       false,
		"https://evilhf.co/x":                          false,
		"https://hf.co.example.test/x":                 false,
		"https://user@cdn-lfs.hf.co/x":                 false,
		"https://models.example.test/x":                false,
	} {
		u, _ := url.Parse(raw)
		if got := HubRedirect(base, u); got != want {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
	}
	test, _ := url.Parse("https://127.0.0.1:4443")
	if u, _ := url.Parse("https://127.0.0.1:4443/m/x"); !HubRedirect(test, u) {
		t.Error("the base's own host is refused")
	}
}
