package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/appq"
	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/sealtest"
)

const storeRoute = "/api/v1/agents/devices/dev_0123456789abcdef/app-tenancies"

func appTenancyRule() StoreRule {
	return StoreRule{Path: "/api/v1/agents/devices/:id/app-tenancies", Method: "POST", Field: "package", NameField: "tenancy.name", Kind: "appq"}
}

func testToken(app string) string { return "tok_test_" + app }

// appPackage is an .ogpkg package of app on the test upstream.
func appPackage(base, app string) string {
	return fmt.Sprintf(`{"format":"ogpkg/1","app":{"appId":%[2]q,"name":"Travel","endpoints":{"hook":"%[1]s/api/v1/hooks/apps/%[2]s","commands":"%[1]s/api/v1/hooks/apps/%[2]s/commands","docs":"%[1]s/api/v1/hooks/apps/%[2]s/docs"}},"client":{"auth":{"header":"X-Outgate-Hook-Token","query":"api_key"},"docs":"how to join"},"join":{"participant":"dev-test-phone","token":%[3]q},"issuer":{"orgId":"o-1","appName":"Travel"},"createdAt":"2026-10-15T08:00:00Z"}`,
		base, app, testToken(app))
}

// appUpstream answers like global and Outgate's app endpoints: the app-tenancies route mints app_1
// as "travel"; app_gone's token is revoked; app_nodecl declares no hooks.
func appUpstream(h *harness) {
	base := h.up.srv.URL
	h.up.mu.Lock()
	defer h.up.mu.Unlock()
	h.up.custom = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == storeRoute && r.Method == "POST":
			w.WriteHeader(201)
			_, _ = fmt.Fprintf(w, `{"tenancy":{"name":"travel","app_id":"app_1","app_name":"Travel","thread_id":"thr-1","participant":"dev-test-phone","created_at":"2026-10-15T08:00:00Z"},"package":%s}`,
				appPackage(base, "app_1"))
		case r.URL.Path == storeRoute+"/noname" && r.Method == "POST":
			w.WriteHeader(201)
			_, _ = fmt.Fprintf(w, `{"tenancy":{},"package":%s}`, appPackage(base, "app_1"))
		case strings.Contains(r.URL.Path, "/app_gone"):
			w.WriteHeader(401)
			_, _ = fmt.Fprint(w, `{"error":{"code":"invalid_token","message":"invalid or revoked token"}}`)
		case strings.Contains(r.URL.Path, "/app_nodecl"):
			w.WriteHeader(403)
			_, _ = fmt.Fprint(w, `{"error":{"code":"webhook_not_declared","message":"the manifest no longer declares this webhook"}}`)
		case strings.Contains(r.URL.Path, "/app_403"):
			w.WriteHeader(403)
			_, _ = fmt.Fprint(w, `{"error":{"code":"invalid_token","message":"invalid or revoked token"}}`)
		default:
			return false
		}
		return true
	}
}

// startAppq starts a gate with a sealed tenancy store (a CE dir of its own, the stand-in keystore)
// or with st when given; class is the test process's caller class.
func startAppq(t *testing.T, class string, st *appq.Store, mutate func(*Config)) (*harness, *appq.Store) {
	t.Helper()
	if st == nil {
		ce := filepath.Join(t.TempDir(), "ce")
		if err := os.Mkdir(ce, 0o700); err != nil {
			t.Fatal(err)
		}
		st = appq.New(filepath.Join(ce, "appq"), sealtest.New(t))
	}
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	h := startOpts(t, Passthrough, func(c *Config) {
		c.Callers = []CallerRule{{UID: &uid, Class: class}}
		c.Store = []StoreRule{appTenancyRule()}
		if mutate != nil {
			mutate(c)
		}
	}, nil, nil, func(o *Options) { o.Appq = st })
	appUpstream(h)
	return h, st
}

func (h *harness) raw(line string) string {
	h.t.Helper()
	b, _ := json.Marshal(h.call(line))
	return string(b)
}

func (r *rec) events(kind string) []ledger.Row {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ledger.Row
	for _, row := range r.rows {
		if row.EgressKind == kind {
			out = append(out, row)
		}
	}
	return out
}

func (r *rec) contains(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, _ := json.Marshal(r.rows)
	return strings.Contains(string(b), s)
}

const popLine = `{"source":{"account_id":"acct-1","region_id":"appq:%s","adapter":"appq"},"method":"POST","path":"/commands/pop","body":{},"egress":{"kind":"poll"},"timeout_ms":10000}`

func TestAppqStoreRuleKeepsThePackage(t *testing.T) {
	chat, st := startAppq(t, "chat", nil, nil)
	line := `{"source":{"account_id":"acct-1","region_id":"global","adapter":"chat"},"method":"POST","path":"` + storeRoute + `","body":{"app_id":"app_1"},"egress":{}}`
	out := chat.raw(line)
	var resp struct {
		Status int `json:"status"`
		Body   struct {
			Tenancy map[string]any `json:"tenancy"`
			Package map[string]any `json:"package"`
		} `json:"body"`
	}
	_ = json.Unmarshal([]byte(out), &resp)
	if resp.Status != 201 || resp.Body.Package["stored"] != "travel" || len(resp.Body.Package) != 1 || resp.Body.Tenancy["thread_id"] != "thr-1" {
		t.Fatalf("response = %s", out)
	}
	if strings.Contains(out, testToken("app_1")) || strings.Contains(out, "join") {
		t.Fatalf("the package reached the caller: %s", out)
	}
	added := chat.rows.events(ledger.AppqAdded)
	if len(added) != 1 || added[0].AppID != "app_1" || added[0].Participant != "dev-test-phone" || added[0].Caller != "chat" ||
		added[0].RegionID != "appq:travel" || added[0].AccountID != "acct-1" || added[0].PathClass != "/api/v1/agents/devices/:id/app-tenancies" ||
		added[0].Status != 201 || added[0].Kind != "other" || added[0].Method != "" || added[0].Destination != "127.0.0.1" {
		t.Errorf("added rows = %+v", added)
	}
	if chat.rows.contains(testToken("app_1")) {
		t.Error("a ledger row holds the token")
	}
	if tot := chat.srv.ring.Totals(); tot.Requests != 1 {
		t.Errorf("lifecycle rows counted as requests: %+v", tot)
	}

	// The agent runtime (another caller, the same store) lists it and its requests carry the token.
	agent, _ := startAppq(t, "agent", st, nil)
	list := agent.raw(`{"op":"appq_list"}`)
	var got struct {
		Status int         `json:"status"`
		Body   []appq.Info `json:"body"`
	}
	_ = json.Unmarshal([]byte(list), &got)
	if got.Status != 200 || len(got.Body) != 1 {
		t.Fatalf("list = %s", list)
	}
	if i := got.Body[0]; i.Name != "travel" || i.Participant != "dev-test-phone" || i.AppID != "app_1" || i.AppName != "Travel" ||
		i.ThreadID != "thr-1" || i.AccountID != "acct-1" || i.State != appq.StateActive || i.AddedAt.IsZero() {
		t.Errorf("listed %+v", i)
	}
	if strings.Contains(list, testToken("app_1")) {
		t.Error("appq_list shows the token")
	}
	if resp := agent.call(fmt.Sprintf(popLine, "travel")); resp["status"].(float64) != 200 {
		t.Fatalf("pop = %v", resp)
	}
	if u := agent.up.last(); u.Path != "/api/v1/hooks/apps/app_1/commands/pop" || u.Header.Get("X-Outgate-Hook-Token") != testToken("app_1") {
		t.Errorf("upstream got %+v", u)
	}
	resp2 := agent.call(`{"source":{"region_id":"appq:travel","adapter":"appq"},"method":"POST","path":"/?hook=events","body":{"kind":"gate.open"},"egress":{"kind":"gate"}}`)
	if resp2["status"].(float64) != 200 || agent.up.last().Query != "hook=events" || agent.up.last().Header.Get("X-Outgate-Hook-Token") != testToken("app_1") {
		t.Errorf("hook fire: %v %+v", resp2, agent.up.last())
	}
	if h := agent.call(`{"op":"health"}`); h["body"].(map[string]any)["appq"].(map[string]any)["tenancies"] != 1.0 {
		t.Errorf("health = %v", h["body"].(map[string]any)["appq"])
	}

	// Another method on the route, or another route: nothing kept.
	chat.call(`{"source":{"region_id":"global"},"method":"GET","path":"` + storeRoute + `","egress":{}}`)
	if n := len(chat.rows.events(ledger.AppqAdded)); n != 1 {
		t.Errorf("a GET added a tenancy (%d)", n)
	}
}

func TestAppqStoreRuleFailsClosed(t *testing.T) {
	line := `{"source":{"region_id":"global","adapter":"chat"},"method":"POST","path":"` + storeRoute + `","body":{"app_id":"app_1"},"egress":{}}`

	// The keystore refuses: global answered, but the package doesn't pass.
	ce := filepath.Join(t.TempDir(), "ce")
	_ = os.Mkdir(ce, 0o700)
	k := sealtest.New(t)
	k.Down.Store(true)
	h, st := startAppq(t, "chat", appq.New(filepath.Join(ce, "appq"), k), nil)
	out := h.raw(line)
	if !strings.Contains(out, `"refused":"tenancy_not_stored"`) || !strings.Contains(out, `"detail":"keystore_unavailable`) || !strings.Contains(out, `"status":503`) || strings.Contains(out, testToken("app_1")) {
		t.Errorf("keystore down: %s", out)
	}
	if row := h.rows.last(t); row.Error != "keystore_unavailable" || row.Status != 201 {
		t.Errorf("row = %+v", row)
	}
	if list, _ := st.List(); len(list) != 0 || len(h.rows.events(ledger.AppqAdded)) != 0 {
		t.Errorf("stored anyway: %v", list)
	}

	// CE storage locked, or no og-gate-link: refused before global mints anything.
	for name, s := range map[string]*appq.Store{
		"storage_locked":   appq.New(filepath.Join(t.TempDir(), "no-ce", "appq"), sealtest.New(t)),
		"link_unavailable": appq.New(filepath.Join(ce, "appq"), nil),
	} {
		h, _ := startAppq(t, "chat", s, nil)
		out := h.raw(line)
		if !strings.Contains(out, `"refused":"`+name+`"`) || len(h.up.got) != 0 {
			t.Errorf("%s: %s (upstream calls %d)", name, out, len(h.up.got))
		}
	}

	// A package without a usable tenancy name.
	h2, _ := startAppq(t, "chat", nil, func(c *Config) {
		c.Store = append(c.Store, StoreRule{Path: "/api/v1/agents/devices/:id/app-tenancies/noname", Method: "POST", Field: "package", NameField: "tenancy.name", Kind: "appq"})
	})
	out = h2.raw(`{"source":{"region_id":"global"},"method":"POST","path":"` + storeRoute + `/noname","body":{},"egress":{}}`)
	if !strings.Contains(out, `"refused":"tenancy_not_stored"`) || strings.Contains(out, testToken("app_1")) {
		t.Errorf("no name: %s", out)
	}
}

func TestStoreRuleConfig(t *testing.T) {
	// The rule as the device's gate.conf writes it.
	conf := filepath.Join(t.TempDir(), "gate.conf")
	_ = os.WriteFile(conf, []byte(`{"store": [{"path": "/api/v1/agents/devices/:id/app-tenancies", "method": "POST", "field": "package", "name_field": "tenancy.name", "kind": "appq"}]}`), 0o600)
	c, err := LoadConfig(conf)
	if err != nil || len(c.Store) != 1 || c.Store[0] != appTenancyRule() {
		t.Fatalf("LoadConfig: %+v %v", c.Store, err)
	}
	good := appTenancyRule()
	for _, change := range []func(*StoreRule){
		func(r *StoreRule) { r.Kind = "region" },
		func(r *StoreRule) { r.Method = "FETCH" },
		func(r *StoreRule) { r.Path = "api/v1/x" },
		func(r *StoreRule) { r.Path = "/x?y=1" },
		func(r *StoreRule) { r.Field = "" },
		func(r *StoreRule) { r.NameField = "tenancy..name" },
		func(r *StoreRule) { r.NameField = "package" },
		func(r *StoreRule) { r.Field = "items[].package" },
	} {
		r := good
		change(&r)
		c := Config{Store: []StoreRule{r}}
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	for pattern, paths := range map[string][2]string{
		"/api/v1/agents/devices/:id/app-tenancies": {"/api/v1/agents/devices/dev_1/app-tenancies", "/api/v1/agents/devices//app-tenancies"},
		"/a/:x/b": {"/a/1/b/", "/a/1/b/c"},
	} {
		if !matchPath(pattern, paths[0]) || matchPath(pattern, paths[1]) {
			t.Errorf("matchPath(%q): %q should match, %q not", pattern, paths[0], paths[1])
		}
	}
}

func TestAppqOpsByCaller(t *testing.T) {
	pkg := func(h *harness) string { return appPackage(h.up.srv.URL, "app_1") }
	importLine := func(h *harness) string {
		return fmt.Sprintf(`{"op":"appq_import","name":"travel","source":{"account_id":"acct-1"},"package":%s}`, pkg(h))
	}
	for _, class := range []string{"chat", "models", "voice", "local-agent"} {
		h, _ := startAppq(t, class, nil, func(c *Config) { c.Debuggable = true })
		for _, line := range []string{`{"op":"appq_list"}`, `{"op":"appq_remove","name":"travel"}`, importLine(h)} {
			if resp := h.call(line); resp["refused"] != "caller_not_allowed" {
				t.Errorf("%s %s: %v", class, line[:22], resp)
			}
		}
	}
	// The agent lists and removes, but doesn't import.
	agent, _ := startAppq(t, "agent", nil, func(c *Config) { c.Debuggable = true })
	if resp := agent.call(importLine(agent)); resp["refused"] != "caller_not_allowed" {
		t.Errorf("agent import: %v", resp)
	}
	if resp := agent.call(`{"op":"appq_list"}`); resp["status"].(float64) != 200 {
		t.Errorf("agent list: %v", resp)
	}
	// Debug tools: nothing on a user build; import and list on a debuggable one, never remove.
	user, _ := startAppq(t, "debug", nil, nil)
	for _, line := range []string{`{"op":"appq_list"}`, importLine(user)} {
		if resp := user.call(line); resp["refused"] != "caller_not_allowed" {
			t.Errorf("debug on a user build: %v", resp)
		}
	}
	if resp := user.call(fmt.Sprintf(popLine, "travel")); resp["refused"] != "destination_not_allowed" {
		t.Errorf("debug reached a tenancy on a user build: %v", resp)
	}
	dbg, st := startAppq(t, "debug", nil, func(c *Config) { c.Debuggable = true })
	out := dbg.raw(importLine(dbg))
	if !strings.Contains(out, `"status":200`) || !strings.Contains(out, `"name":"travel"`) || strings.Contains(out, testToken("app_1")) {
		t.Fatalf("import: %s", out)
	}
	if added := dbg.rows.events(ledger.AppqAdded); len(added) != 1 || added[0].Caller != "debug" || added[0].AccountID != "acct-1" {
		t.Errorf("import rows = %+v", added)
	}
	if got, err := st.Get("travel"); err != nil || got.Token != testToken("app_1") {
		t.Errorf("imported: %+v %v", got, err)
	}
	// A package given as a string (adb tools) works too; a missing one doesn't.
	asString, _ := json.Marshal(pkg(dbg))
	if resp := dbg.call(fmt.Sprintf(`{"op":"appq_import","name":"other","package":%s}`, asString)); resp["status"].(float64) != 200 {
		t.Errorf("string package: %v", resp)
	}
	for _, line := range []string{`{"op":"appq_import","name":"x"}`, `{"op":"appq_import","name":"a/b","package":` + pkg(dbg) + `}`, `{"op":"appq_import","name":"x","package":{"app":{}}}`} {
		if resp := dbg.call(line); resp["refused"] != "bad_request" {
			t.Errorf("%s: %v", line, resp)
		}
	}
	if resp := dbg.call(`{"op":"appq_list"}`); resp["status"].(float64) != 200 || len(resp["body"].([]any)) != 2 {
		t.Errorf("debug list: %v", resp)
	}
	if resp := dbg.call(`{"op":"appq_remove","name":"travel"}`); resp["refused"] != "caller_not_allowed" {
		t.Errorf("debug remove: %v", resp)
	}
}

func TestAppqRemove(t *testing.T) {
	agent, st := startAppq(t, "agent", nil, nil)
	if _, err := st.Add("travel", []byte(appPackage(agent.up.srv.URL, "app_1")), appq.Info{AccountID: "acct-1"}, appq.OriginStore); err != nil {
		t.Fatal(err)
	}
	resp := agent.call(`{"op":"appq_remove","name":"travel"}`)
	if body, _ := resp["body"].(map[string]any); resp["status"].(float64) != 200 || body["removed"] != true || body["left"] != true {
		t.Fatalf("remove = %v", resp)
	}
	leave := agent.up.last()
	if leave.Method != "POST" || leave.Path != "/api/v1/hooks/apps/app_1" || leave.Query != "hook=control" ||
		leave.Body != `{"action":"leave"}` || leave.Header.Get("X-Outgate-Hook-Token") != testToken("app_1") {
		t.Errorf("leave = %+v", leave)
	}
	if removed := agent.rows.events(ledger.AppqRemoved); len(removed) != 1 || removed[0].Caller != "agent" || removed[0].AppID != "app_1" {
		t.Errorf("removed rows = %+v", removed)
	}
	if control := agent.rows.events("control"); len(control) != 1 || control[0].RegionID != "appq:travel" || control[0].Status != 200 {
		t.Errorf("leave row = %+v", control)
	}
	if resp := agent.call(fmt.Sprintf(popLine, "travel")); resp["refused"] != "unknown_region" {
		t.Errorf("removed tenancy still used: %v", resp)
	}
	if resp := agent.call(`{"op":"appq_remove","name":"travel"}`); resp["refused"] != "unknown_region" {
		t.Errorf("remove twice: %v", resp)
	}

	// Its token already revoked: the leave fails, the tenancy is removed by the user all the same.
	if _, err := st.Add("gone", []byte(appPackage(agent.up.srv.URL, "app_gone")), appq.Info{}, appq.OriginStore); err != nil {
		t.Fatal(err)
	}
	resp = agent.call(`{"op":"appq_remove","name":"gone"}`)
	if body, _ := resp["body"].(map[string]any); body["removed"] != true || body["left"] != false {
		t.Errorf("remove a revoked tenancy = %v", resp)
	}
	if n := len(agent.rows.events(ledger.AppqRevoked)); n != 0 {
		t.Errorf("a removal's leave recorded a revocation (%d)", n)
	}
	if list, _ := st.List(); len(list) != 0 {
		t.Errorf("left: %v", list)
	}
}

func TestAppqRevokedOnTheWeb(t *testing.T) {
	agent, st := startAppq(t, "agent", nil, nil)
	for name, app := range map[string]string{"gone": "app_gone", "nodecl": "app_nodecl", "forbidden": "app_403"} {
		if _, err := st.Add(name, []byte(appPackage(agent.up.srv.URL, app)), appq.Info{AccountID: "acct-1"}, appq.OriginStore); err != nil {
			t.Fatal(err)
		}
	}
	if resp := agent.call(fmt.Sprintf(popLine, "gone")); resp["status"].(float64) != 401 {
		t.Fatalf("pop = %v", resp)
	}
	revoked := agent.rows.events(ledger.AppqRevoked)
	if len(revoked) != 1 || revoked[0].RegionID != "appq:gone" || revoked[0].Status != 401 || revoked[0].AppID != "app_gone" ||
		revoked[0].PathClass != "/api/v1/hooks/apps/:id/commands/pop" || revoked[0].AccountID != "acct-1" {
		t.Errorf("revoked rows = %+v", revoked)
	}
	if resp := agent.call(fmt.Sprintf(popLine, "gone")); resp["refused"] != "unknown_region" {
		t.Errorf("revoked tenancy still used: %v", resp)
	}
	if n := len(agent.rows.events(ledger.AppqRevoked)); n != 1 {
		t.Errorf("%d revoked rows", n)
	}
	// A 403 that says the manifest declares no such hook isn't a revocation; one with invalid_token is.
	agent.call(`{"source":{"region_id":"appq:nodecl"},"method":"POST","path":"/?hook=events","body":{"kind":"gate.open"},"egress":{"kind":"gate"}}`)
	agent.call(fmt.Sprintf(popLine, "forbidden"))
	resp := agent.call(`{"op":"appq_list"}`)
	if list, _ := resp["body"].([]any); len(list) != 1 || list[0].(map[string]any)["name"] != "nodecl" {
		t.Errorf("list = %v", resp)
	}
}

func TestAppqTokenFromTheSealedStore(t *testing.T) {
	agent, st := startAppq(t, "agent", nil, nil)
	if _, err := st.Add("travel", []byte(appPackage(agent.up.srv.URL, "app_1")), appq.Info{}, appq.OriginImport); err != nil {
		t.Fatal(err)
	}
	if resp := agent.call(fmt.Sprintf(popLine, "travel")); resp["status"].(float64) != 200 {
		t.Fatalf("pop = %v", resp)
	}
	if u := agent.up.last(); u.Path != "/api/v1/hooks/apps/app_1/commands/pop" || u.Header.Get("X-Outgate-Hook-Token") != testToken("app_1") {
		t.Errorf("upstream got %+v", u)
	}
	if row := agent.rows.last(t); row.RegionID != "appq:travel" || row.Destination != "127.0.0.1" || row.Kind != "event" {
		t.Errorf("row = %+v", row)
	}
	// Only the agent runtime, and debug tools on debuggable builds, reach a tenancy.
	for class, debuggable := range map[string]bool{"chat": true, "debug": false} {
		h, _ := startAppq(t, class, st, func(c *Config) { c.Debuggable = debuggable })
		if resp := h.call(fmt.Sprintf(popLine, "travel")); resp["refused"] != "destination_not_allowed" || len(h.up.got) != 0 {
			t.Errorf("%s (debuggable %v): %v", class, debuggable, resp)
		}
	}
	dbg, _ := startAppq(t, "debug", st, func(c *Config) { c.Debuggable = true })
	if resp := dbg.call(fmt.Sprintf(popLine, "travel")); resp["status"].(float64) != 200 {
		t.Errorf("debug on a debuggable build: %v", resp)
	}
}

func TestAppqRefusedUntilReady(t *testing.T) {
	// CE storage not unlocked yet.
	locked, _ := startAppq(t, "agent", appq.New(filepath.Join(t.TempDir(), "no-ce", "appq"), sealtest.New(t)), nil)
	if resp := locked.call(fmt.Sprintf(popLine, "travel")); resp["refused"] != "storage_locked" || resp["status"].(float64) != 503 {
		t.Errorf("locked: %v", resp)
	}
	if resp := locked.call(`{"op":"appq_list"}`); resp["refused"] != "storage_locked" {
		t.Errorf("list while locked: %v", resp)
	}
	if h := locked.call(`{"op":"health"}`); h["body"].(map[string]any)["appq"].(map[string]any)["ready"] != false {
		t.Errorf("health while locked: %v", h["body"].(map[string]any)["appq"])
	}
	// No store at all (a gate without a CE dir).
	none := startWith(t, Passthrough, nil, nil, nil)
	if resp := none.call(fmt.Sprintf(popLine, "travel")); resp["refused"] != "storage_locked" {
		t.Errorf("no store: %v", resp)
	}
	// og-gate-link down: the tenancy is listed but can't be opened.
	ce := filepath.Join(t.TempDir(), "ce")
	_ = os.Mkdir(ce, 0o700)
	k := sealtest.New(t)
	if _, err := appq.New(filepath.Join(ce, "appq"), k).Add("travel", []byte(appPackage("https://api.example.test", "app_1")), appq.Info{}, appq.OriginStore); err != nil {
		t.Fatal(err)
	}
	down, _ := startAppq(t, "agent", appq.New(filepath.Join(ce, "appq"), nil), nil)
	if resp := down.call(fmt.Sprintf(popLine, "travel")); resp["refused"] != "link_unavailable" || len(down.up.got) != 0 {
		t.Errorf("link down: %v", resp)
	}
	if resp := down.call(`{"op":"appq_list"}`); resp["status"].(float64) != 200 {
		t.Errorf("list with the link down: %v", resp)
	}
	k.Down.Store(true)
	ks, _ := startAppq(t, "agent", appq.New(filepath.Join(ce, "appq"), k), nil)
	if resp := ks.call(fmt.Sprintf(popLine, "travel")); resp["refused"] != "keystore_unavailable" {
		t.Errorf("keystore down: %v", resp)
	}
}

func TestAppqMigratedOutOfDE(t *testing.T) {
	for _, debuggable := range []bool{true, false} {
		h, st := startAppq(t, "agent", nil, func(c *Config) { c.Debuggable = debuggable })
		de := filepath.Join(h.dir, "appq")
		_ = os.MkdirAll(de, 0o770)
		_ = os.WriteFile(filepath.Join(de, "travel.ogpkg"), []byte(appPackage(h.up.srv.URL, "app_1")), 0o600)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		h.srv.MigrateAppq(ctx)
		cancel()
		if _, err := os.Stat(filepath.Join(de, "travel.ogpkg")); !os.IsNotExist(err) {
			t.Errorf("debuggable=%v: the DE package is still there", debuggable)
		}
		list, _ := st.List()
		migrated := h.rows.events(ledger.AppqMigrated)
		if !debuggable {
			if len(list) != 0 || len(migrated) != 0 {
				t.Errorf("a user build sealed a DE package: %v %v", list, migrated)
			}
			continue
		}
		if len(list) != 1 || len(migrated) != 1 || migrated[0].Caller != "gate" || migrated[0].AppID != "app_1" {
			t.Errorf("migrated: %v %+v", list, migrated)
		}
		if resp := h.call(fmt.Sprintf(popLine, "travel")); resp["status"].(float64) != 200 || h.up.last().Header.Get("X-Outgate-Hook-Token") != testToken("app_1") {
			t.Errorf("migrated tenancy: %v", resp)
		}
	}
}
