package route

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
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
		Tenancies:   NewTenancies(filepath.Join(dir, "appq")),
	}
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
	dir := r.Tenancies.dir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pkg := `{"app":{"endpoints":{"hook":"https://api.example.test/api/v1/hooks/apps/app_1","commands":"https://api.example.test/api/v1/hooks/apps/app_1/commands"}},
	 "client":{"auth":{"header":"X-Outgate-Hook-Token"}},"join":{"participant":"phone","token":"tok-synthetic"}}`
	if err := os.WriteFile(filepath.Join(dir, "travel.ogpkg"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err = r.Resolve("appq:travel", "", "/commands/pop", nil)
	if err != nil || d.URL.String() != "https://api.example.test/api/v1/hooks/apps/app_1/commands/pop" || d.Headers["X-Outgate-Hook-Token"] != "tok-synthetic" {
		t.Fatalf("tenancy commands: %+v %v", d, err)
	}
	d, err = r.Resolve("appq:travel", "", "?hook=events", nil)
	if err != nil || d.URL.String() != "https://api.example.test/api/v1/hooks/apps/app_1?hook=events" {
		t.Fatalf("tenancy hook: %+v %v", d, err)
	}
	if _, err := r.Resolve("appq:nope", "", "/commands/pop", nil); !errors.Is(err, ErrUnknownRegion) {
		t.Errorf("unknown tenancy: %v", err)
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
	if got := ThreadID("/api/v1/agents/threads/thr-9/events"); got != "thr-9" {
		t.Errorf("ThreadID = %q", got)
	}
}
