package route

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRouter(t *testing.T) *Router {
	t.Helper()
	dir := t.TempDir()
	return &Router{
		Envs: []Environment{
			{ID: "prod", Global: "https://api.example.test", OIDC: "https://console.example.test"},
			{ID: "dev", Global: "https://api.dev.example.test", OIDC: "https://console.dev.example.test", DebuggableOnly: true},
		},
		ModelSocket: "/model.sock",
		Regions:     NewRegions(filepath.Join(dir, "regions.json"), 30*24*time.Hour),
		Tenancies:   tenancies{},
	}
}

// tenancies stands in for the gate's sealed store (internal/gate/appq).
type tenancies map[string]Tenancy

func (m tenancies) Get(name string) (Tenancy, error) {
	t, ok := m[name]
	if !ok {
		return Tenancy{}, fmt.Errorf("%w: appq:%s", ErrUnknownRegion, name)
	}
	return t, nil
}

func TestResolveGlobalAndAbsolute(t *testing.T) {
	r := testRouter(t)
	d, err := r.Resolve("global", "", "/api/v1/agents/threads", url.Values{"limit": {"5"}})
	if err != nil || d.URL.String() != "https://api.example.test/api/v1/agents/threads?limit=5" || d.Env != "prod" {
		t.Fatalf("global: %+v %v", d, err)
	}
	d, err = r.Resolve("", "https://console.example.test/oauth2/token", "", nil)
	if err != nil || d.Display != "console.example.test" {
		t.Fatalf("oidc absolute: %+v %v", d, err)
	}
	for _, bad := range []string{"https://evil.test/x", "http://api.example.test/x", "ftp://api.example.test/", "https://user@api.example.test/"} {
		if _, err := r.Resolve("", bad, "", nil); err == nil {
			t.Errorf("%s: allowed", bad)
		}
	}
	if _, err := r.Resolve("", "https://api.dev.example.test/x", "", nil); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("dev env reachable on a user build: %v", err)
	}
	r.Debuggable = true
	if d, err := r.Resolve("", "https://api.dev.example.test/x", "", nil); err != nil || d.Env != "dev" {
		t.Errorf("dev env on debuggable: %+v %v", d, err)
	}
}

func TestRegionsLearnedFromGlobalOnly(t *testing.T) {
	r := testRouter(t)
	if _, err := r.Resolve("", "https://reg-1.regions.example.test/v1/agents/threads/thr-1/events", "", nil); err == nil {
		t.Fatal("unknown region host allowed")
	}
	rules := []LearnRule{
		{Path: "/api/v1/agents/threads/:id/events-token", Field: "url"},
		{Path: "/api/v1/agents/regions", Field: "regions[].endpoint", IDField: "regions[].id"},
	}
	n := r.Regions.LearnFrom(rules, "/api/v1/agents/threads/:id/events-token",
		[]byte(`{"url":"https://reg-1.regions.example.test/v1/agents/threads/thr-1/events","token":"<redacted>"}`), "prod")
	if n != 1 {
		t.Fatalf("learned %d", n)
	}
	d, err := r.Resolve("", "https://reg-1.regions.example.test/v1/agents/threads/thr-1/events?since=3", "", nil)
	if err != nil || d.Env != "prod" {
		t.Fatalf("learned host: %+v %v", d, err)
	}
	r.Regions.LearnFrom(rules, "/api/v1/agents/regions",
		[]byte(`{"regions":[{"id":"reg-2","endpoint":"https://reg-2.example.test"},{"id":"reg-3"}]}`), "prod")
	d, err = r.Resolve("reg-2", "", "/v1/agents/devices/x/stream", nil)
	if err != nil || d.URL.String() != "https://reg-2.example.test/v1/agents/devices/x/stream" {
		t.Fatalf("region by id: %+v %v", d, err)
	}
	if _, err := r.Resolve("reg-3", "", "/x", nil); !errors.Is(err, ErrUnknownRegion) {
		t.Errorf("region without endpoint: %v", err)
	}

	again := NewRegions(r.Regions.path, 30*24*time.Hour)
	if _, ok := again.Get("reg-2"); !ok {
		t.Error("regions not persisted")
	}
	again.now = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
	if _, ok := again.HostEnv("reg-1.regions.example.test"); ok {
		t.Error("expired region host still allowed")
	}
}

func TestOnDeviceAndTenancy(t *testing.T) {
	r := testRouter(t)
	d, err := r.Resolve("on-device", "", "/v1/chat/completions", nil)
	if err != nil || d.Kind != OnDevice || d.Socket != "/model.sock" || d.Path != "/v1/chat/completions" {
		t.Fatalf("on-device: %+v %v", d, err)
	}
	pkg := `{"app":{"appId":"app_1","endpoints":{"hook":"https://api.example.test/api/v1/hooks/apps/app_1","commands":"https://api.example.test/api/v1/hooks/apps/app_1/commands"}},
	 "client":{"auth":{"header":"X-Outgate-Hook-Token"}},"join":{"participant":"phone","token":"tok-synthetic"},"issuer":{"appName":"Travel"}}`
	tn, err := ParsePackage([]byte(pkg))
	if err != nil || tn.AppID != "app_1" || tn.AppName != "Travel" || tn.Participant != "phone" {
		t.Fatalf("package: %+v %v", tn, err)
	}
	tn.Gen = "g1"
	r.Tenancies = tenancies{"travel": tn}
	d, err = r.Resolve("appq:travel", "", "/commands/pop", nil)
	if err != nil || d.URL.String() != "https://api.example.test/api/v1/hooks/apps/app_1/commands/pop" || d.Headers["X-Outgate-Hook-Token"] != "tok-synthetic" ||
		d.Tenancy != "travel" || d.TenancyGen != "g1" {
		t.Fatalf("tenancy commands: %+v %v", d, err)
	}
	d, err = r.Resolve("appq:travel", "", "?hook=events", nil)
	if err != nil || d.URL.String() != "https://api.example.test/api/v1/hooks/apps/app_1?hook=events" {
		t.Fatalf("tenancy hook: %+v %v", d, err)
	}
	if _, err := r.Resolve("appq:nope", "", "/commands/pop", nil); !errors.Is(err, ErrUnknownRegion) {
		t.Errorf("unknown tenancy: %v", err)
	}
	for _, bad := range []string{`{}`, `{"app":{"endpoints":{"hook":"https://h.test/x"}},"join":{}}`, `{"app":{"endpoints":{"hook":"nohost"}},"join":{"token":"t"}}`} {
		if _, err := ParsePackage([]byte(bad)); !errors.Is(err, ErrBadPackage) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestPathClass(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // paths with synthetic ids, not credentials
		"/api/v1/agents/threads/thr-abc123/events?since=4":                                    "/api/v1/agents/threads/:id/events",
		"/api/v1/agents/threads/0b9f3c2e-1d2a-4b5c-8d9e-0f1a2b3c4d5e/decisions/dec_77/answer": "/api/v1/agents/threads/:id/decisions/:id/answer",
		"/api/v1/hooks/apps/app_3b2fea2bb7ff/commands/12345/report":                           "/api/v1/hooks/apps/:id/commands/:id/report",
		"/oauth2/token": "/oauth2/token",
	}
	for in, want := range cases {
		if got := PathClass(in); got != want {
			t.Errorf("PathClass(%q) = %q, want %q", in, got, want)
		}
	}
	// Device ids, and the learn and store rules' device routes.
	for in, want := range map[string]string{
		"/api/v1/agents/devices/dev_0123456789abcdef/channel-token":        "/api/v1/agents/devices/:id/channel-token",
		"/api/v1/agents/devices/dev_0123456789abcdef/app-tenancies":        "/api/v1/agents/devices/:id/app-tenancies",
		"/api/v1/agents/devices/dev_0123456789abcdef/app-tenancies/travel": "/api/v1/agents/devices/:id/app-tenancies/travel",
	} {
		if got := PathClass(in); got != want {
			t.Errorf("PathClass(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ThreadID("/api/v1/agents/threads/thr-9/events"); got != "thr-9" {
		t.Errorf("ThreadID = %q", got)
	}
}

func TestDestinationClasses(t *testing.T) {
	r := testRouter(t)
	r.Providers = []Provider{{ID: "llm", Base: "https://llm.provider.test/v1"}}
	r.Regions.Learn("reg-1", "https://reg-1.regions.example.test", "prod")
	cases := []struct {
		region, url, path, class string
	}{
		{"global", "", "/api/v1/agents/threads", ClassOutgate},
		{"oidc", "", "/oauth2/token", ClassOutgate},
		{"", "https://console.example.test/oauth2/token", "", ClassOutgate},
		{"reg-1", "", "/v1/agents/threads/thr-1/events", ClassOutgate},
		{"on-device", "", "/v1/chat/completions", ClassOnDevice},
		{"provider:llm", "", "/messages", ClassProvider},
		{"", "https://llm.provider.test/v1/messages", "", ClassProvider},
	}
	for _, c := range cases {
		d, err := r.Resolve(c.region, c.url, c.path, nil)
		if err != nil || d.Class != c.class {
			t.Errorf("%s %s%s: %+v %v, want class %s", c.region, c.url, c.path, d, err, c.class)
		}
	}
	if d, _ := r.Resolve("provider:llm", "", "/messages", nil); d.URL.String() != "https://llm.provider.test/v1/messages" || d.Env != "" {
		t.Errorf("provider path: %+v", d)
	}
	for _, bad := range []string{"http://llm.provider.test/v1/messages", "https://other.provider.test/x"} {
		if _, err := r.Resolve("", bad, "", nil); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := r.Resolve("provider:other", "", "/x", nil); !errors.Is(err, ErrUnknownRegion) {
		t.Errorf("unknown provider: %v", err)
	}
}

func TestMirror(t *testing.T) {
	r := testRouter(t)
	r.AllowHTTP = []string{"mirror.localhost"}
	bases := map[string]error{
		"":                                  ErrNoMirror,
		"https://models.example.test":       nil,
		"https://models.example.test/m/":    nil,
		"HTTPS://models.example.test/m":     nil,
		"http://mirror.localhost:8080/m":    nil,
		"http://models.example.test/m":      ErrMirrorNotHTTPS,
		"ftp://models.example.test/m":       ErrMirrorNotHTTPS,
		"models.example.test/m":             ErrMirrorURL,
		"https://user@models.example.test/": ErrMirrorURL,
		"https://models.example.test/m?k=v": ErrMirrorURL,
		"https://models.example.test/m?":    ErrMirrorURL,
		"https://models.example.test/m#x":   ErrMirrorURL,
		"https:models.example.test":         ErrMirrorURL,
		"https://":                          ErrMirrorURL,
	}
	for raw, want := range bases {
		if _, err := r.MirrorBase(raw); !errors.Is(err, want) {
			t.Errorf("MirrorBase(%q) = %v, want %v", raw, err, want)
		}
	}
	for base, want := range map[string]string{
		"https://models.example.test":     "https://models.example.test/embeddinggemma-2/740m/model.litertlm",
		"https://models.example.test/m":   "https://models.example.test/m/embeddinggemma-2/740m/model.litertlm",
		"https://models.example.test/m//": "https://models.example.test/m/embeddinggemma-2/740m/model.litertlm",
	} {
		b, err := r.MirrorBase(base)
		if err != nil {
			t.Fatal(err)
		}
		d, err := Mirror(b, "embeddinggemma-2/740m/model.litertlm")
		if err != nil || d.URL.String() != want || d.Class != ClassMirror || d.Display != "models.example.test" || d.Env != "" {
			t.Errorf("%s: %+v %v", base, d, err)
		}
	}
	b, _ := r.MirrorBase("https://models.example.test/m")
	if d, err := Mirror(b, "voice/e2b/Model_E2B-it@q4+v2.1.gguf"); err != nil || d.URL.Path != "/m/voice/e2b/Model_E2B-it@q4+v2.1.gguf" {
		t.Errorf("all allowed characters: %+v %v", d, err)
	}
	for _, bad := range []string{
		"", "/abs/model.bin", "../model.bin", "a/../b.bin", "a/./b.bin", "a//b.bin", "dir/", "..",
		"model.bin?x=1", "model.bin#f", `a\b.bin`, "a b.bin", "a%2e%2e/b.bin", "a:b.bin", "a/~b.bin",
		strings.Repeat("a", 1025),
	} {
		if _, err := Mirror(b, bad); !errors.Is(err, ErrBadPath) {
			t.Errorf("Mirror(%q): %v", bad, err)
		}
	}
}
