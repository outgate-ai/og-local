package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/appq"
	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// App tenancies (og-os M12c, Q6): what the gate does with its sealed store (internal/gate/appq).
// A store rule keeps a tenancy's package out of global's response to OGChat and seals it; the
// appq_* ops list, remove and (debuggable builds) import tenancies; a 401 to a tenancy's request
// deletes it (revoked on the web); the bring-up's plain DE packages are moved out; each change is a
// lifecycle row in the ledger.

// leaveTimeout bounds the control/leave a removal fires (best effort).
const leaveTimeout = 5 * time.Second

// leaving marks the context of a removal's control/leave: a 401 to it isn't a revocation.
type leaving struct{}

func isAppqOp(op string) bool {
	return op == "appq_list" || op == "appq_remove" || op == "appq_import"
}

// appqRefusal maps the store's not-ready errors onto refusal codes.
func appqRefusal(err error) (status int, code string, ok bool) {
	switch {
	case errors.Is(err, appq.ErrLocked):
		return 503, "storage_locked", true
	case errors.Is(err, appq.ErrLink):
		return 503, "link_unavailable", true
	case errors.Is(err, appq.ErrKeystore):
		return 503, "keystore_unavailable", true
	case errors.Is(err, appq.ErrStorage):
		return 503, "storage_unavailable", true
	case errors.Is(err, appq.ErrUnreadable):
		return 500, "tenancy_unreadable", true
	}
	return 0, "", false
}

func appqError(id string, err error) *wire.Response {
	if status, code, ok := appqRefusal(err); ok {
		return wire.Refuse(id, status, code, err.Error())
	}
	switch {
	case errors.Is(err, appq.ErrNotFound):
		return wire.Refuse(id, 404, "unknown_region", err.Error())
	case errors.Is(err, appq.ErrBadName), errors.Is(err, route.ErrBadPackage):
		return wire.Refuse(id, 400, "bad_request", err.Error())
	}
	return wire.Refuse(id, 500, "internal", err.Error())
}

// appqOp serves the appq_* ops: appq_list for the agent (and debug tools on debuggable builds),
// appq_remove for the agent, appq_import for debug tools on debuggable builds.
func (s *Server) appqOp(ctx context.Context, class string, cred peer.Cred, req *wire.Request) *wire.Response {
	debug := class == "debug" && s.cfg.Debuggable
	switch {
	case req.Op == "appq_list" && (class == "agent" || debug):
		list, err := s.appq.List()
		if err != nil {
			return appqError(req.ID, err)
		}
		return jsonResponse(200, list)
	case req.Op == "appq_remove" && class == "agent":
		return s.appqRemove(ctx, class, cred, req)
	case req.Op == "appq_import" && debug:
		return s.appqImport(class, cred, req)
	}
	s.log.Warn("op refused for caller", "class", class, "op", req.Op)
	return wire.Refuse(req.ID, 403, "caller_not_allowed", "")
}

// appqRemove tells the app the participant leaves (best effort), then deletes the tenancy.
func (s *Server) appqRemove(ctx context.Context, class string, cred peer.Cred, req *wire.Request) *wire.Response {
	i, err := s.appq.Info(req.Name)
	if err != nil {
		return appqError(req.ID, err)
	}
	left := s.appqLeave(ctx, cred, i)
	removed, err := s.appq.Remove(req.Name)
	switch {
	case errors.Is(err, appq.ErrNotFound):
		// Removed meanwhile by another request.
	case err != nil:
		return appqError(req.ID, err)
	default:
		s.recordAppq(ledger.AppqRemoved, class, cred.UID, removed, "", 0)
	}
	return jsonResponse(200, map[string]any{"name": i.Name, "removed": true, "left": left})
}

// appqLeave fires the app's control hook, {"action": "leave"}, with the tenancy's own token. The
// app may declare no control hook, and the token may be revoked already: best effort. It is a
// request like any other (a ledger row, egress kind control).
func (s *Server) appqLeave(ctx context.Context, cred peer.Cred, i appq.Info) bool {
	lctx, cancel := context.WithTimeout(context.WithValue(ctx, leaving{}, true), leaveTimeout)
	defer cancel()
	resp := s.forward(lctx, "agent", cred, &wire.Request{
		Source: wire.Source{AccountID: i.AccountID, RegionID: "appq:" + i.Name, Adapter: "appq"},
		Method: "POST", Path: "/?hook=control", Body: json.RawMessage(`{"action":"leave"}`),
		Egress: wire.Egress{Kind: "control"}, TimeoutMs: leaveTimeout.Milliseconds(),
	}, nil)
	return resp.Refused == "" && resp.Status/100 == 2
}

// appqImport seals a package given on the socket (adb bring-up, debuggable builds).
func (s *Server) appqImport(class string, cred peer.Cred, req *wire.Request) *wire.Response {
	pkg, ok := packageObject(req.Package)
	if req.Name == "" || !ok {
		return wire.Refuse(req.ID, 400, "bad_request", "name and package (an .ogpkg object) are required")
	}
	i, err := s.appq.Add(req.Name, pkg, appq.Info{AccountID: req.Source.AccountID}, appq.OriginImport)
	if err != nil {
		return appqError(req.ID, err)
	}
	s.recordAppq(ledger.AppqAdded, class, cred.UID, i, "", 0)
	return jsonResponse(200, i)
}

// packageObject is a package given as a JSON object, or as a string holding one.
func packageObject(raw json.RawMessage) ([]byte, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		var str string
		if json.Unmarshal(raw, &str) != nil {
			return nil, false
		}
		raw = bytes.TrimSpace([]byte(str))
	}
	if len(raw) == 0 || raw[0] != '{' || !json.Valid(raw) {
		return nil, false
	}
	return raw, true
}

// recordAppq writes a lifecycle row (ledger/appq.go): never the token or the package.
func (s *Server) recordAppq(event, caller string, uid uint32, i appq.Info, pathClass string, status int) {
	row := ledger.Row{
		ID: s.nextID(), Time: time.Now().UTC(), Caller: caller, UID: uid, AccountID: i.AccountID,
		RegionID: "appq:" + i.Name, Adapter: "appq", Destination: i.Host, Class: route.ClassOutgate,
		PathClass: pathClass, EgressKind: event, Kind: "other", Status: status, Mask: MaskNotRequired,
		Mode: string(s.cfg.Mode), AppID: i.AppID, Participant: i.Participant,
	}
	s.ledger.Record(&row)
	if event != ledger.AppqMigrated {
		s.log.Info("app tenancy", "event", event, "name", i.Name, "app", i.AppID, "caller", caller)
	}
}

// storeRule is the store rule for a request to global, if one matches.
func (s *Server) storeRule(method string, dest *route.Destination) *StoreRule {
	if dest.URL == nil || !s.isGlobal(dest) {
		return nil
	}
	for i := range s.cfg.Store {
		r := &s.cfg.Store[i]
		if strings.EqualFold(r.Method, method) && matchPath(r.Path, dest.URL.Path) {
			return r
		}
	}
	return nil
}

// storeNotReady refuses, before it leaves, a request whose response a store rule would keep while
// the store can't take a tenancy (CE storage locked, no og-gate-link): global would mint a
// participant whose token nobody could hold.
func (s *Server) storeNotReady(method string, dest *route.Destination) (status int, code, detail string, refuse bool) {
	if s.storeRule(method, dest) == nil {
		return 0, "", "", false
	}
	err := s.appq.Ready()
	if err == nil {
		return 0, "", "", false
	}
	status, code, _ = appqRefusal(err)
	return status, code, "app tenancies can't be stored now: " + err.Error(), true
}

// appqResponse is what the gate does with an upstream response for app tenancies: a 401 to a
// tenancy's request deletes the tenancy (revoked on the web); a store rule keeps a tenancy's package
// out of a 2xx from global, sealed, or refuses the response when it can't (the package never passes).
func (s *Server) appqResponse(ctx context.Context, class string, uid uint32, req *wire.Request, method string,
	dest *route.Destination, row *ledger.Row, status int, data []byte,
) ([]byte, *wire.Response) {
	if dest.Tenancy != "" {
		if revoked(status, data) && ctx.Value(leaving{}) == nil {
			if i, ok := s.appq.Revoke(dest.Tenancy, dest.TenancyGen); ok {
				s.recordAppq(ledger.AppqRevoked, class, uid, i, row.PathClass, status)
			}
		}
		return data, nil
	}
	if status/100 != 2 {
		return data, nil
	}
	rule := s.storeRule(method, dest)
	if rule == nil {
		return data, nil
	}
	out, i, err := s.keepTenancy(rule, req, data)
	if err != nil {
		st, code, ok := appqRefusal(err)
		if !ok {
			st, code = 503, "tenancy_not_stored"
		}
		row.Error = code
		s.log.Warn("app tenancy not stored", "reason", code, "err", err)
		r := wire.Refuse(req.ID, st, code, err.Error())
		r.Ledger, r.Class, r.Masked.Mask = row.ID, row.Class, row.Mask
		return nil, r
	}
	if i != nil {
		s.recordAppq(ledger.AppqAdded, class, uid, *i, row.PathClass, status)
	}
	return out, nil
}

// keepTenancy seals the package at rule.Field under the name at rule.NameField and puts
// {"stored": "<name>"} in its place. The object holding the name may say the thread and app name.
// A response without the field (or with null there) passes unchanged.
func (s *Server) keepTenancy(rule *StoreRule, req *wire.Request, data []byte) ([]byte, *appq.Info, error) {
	raw, ok := jsonPath(data, rule.Field)
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return data, nil, nil
	}
	var name string
	if v, ok := jsonPath(data, rule.NameField); ok {
		_ = json.Unmarshal(v, &name)
	}
	if !appq.ValidName(name) {
		return nil, nil, fmt.Errorf("no tenancy name at %s", rule.NameField)
	}
	pkg, ok := packageObject(raw)
	if !ok {
		return nil, nil, fmt.Errorf("tenancy %s: %s is not a package", name, rule.Field)
	}
	var about struct {
		AppName  string `json:"app_name"`
		ThreadID string `json:"thread_id"`
	}
	parent := ""
	if dot := strings.LastIndex(rule.NameField, "."); dot >= 0 {
		parent = rule.NameField[:dot]
	}
	if v, ok := jsonPath(data, parent); ok {
		_ = json.Unmarshal(v, &about)
	}
	i, err := s.appq.Add(name, pkg, appq.Info{AccountID: req.Source.AccountID, AppName: about.AppName, ThreadID: about.ThreadID}, appq.OriginStore)
	if err != nil {
		return nil, nil, fmt.Errorf("tenancy %s not stored: %w", name, err)
	}
	stored, _ := json.Marshal(map[string]string{"stored": name})
	out, err := setJSONPath(data, rule.Field, stored)
	if err != nil {
		return nil, nil, fmt.Errorf("tenancy %s: %w", name, err)
	}
	return out, &i, nil
}

// revoked: the app's endpoints refused the tenancy's token. Outgate answers a revoked (or unknown)
// participant token 401 invalid_token. A 403 counts only with that code: Outgate's 403s say the
// manifest doesn't declare a hook or commands, and a proxy's 403 says nothing about the token.
func revoked(status int, body []byte) bool {
	switch status {
	case 401:
		return true
	case 403:
		return errorCode(body) == "invalid_token"
	}
	return false
}

// errorCode is body's error code: {"error": {"code": …}} or {"error": "…"}.
func errorCode(body []byte) string {
	var b struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &b) != nil || len(b.Error) == 0 {
		return ""
	}
	var code string
	if json.Unmarshal(b.Error, &code) == nil {
		return code
	}
	var obj struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(b.Error, &obj)
	return obj.Code
}

// matchPath matches a path against a rule's pattern: ":name" segments match any one segment.
func matchPath(pattern, path string) bool {
	ps := strings.Split(strings.Trim(pattern, "/"), "/")
	xs := strings.Split(strings.Trim(path, "/"), "/")
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if strings.HasPrefix(ps[i], ":") {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if ps[i] != xs[i] {
			return false
		}
	}
	return true
}

// jsonPath is the value at a dotted path of object keys ("" is the whole document).
func jsonPath(doc []byte, path string) (json.RawMessage, bool) {
	cur := json.RawMessage(doc)
	if path == "" {
		return cur, true
	}
	for _, seg := range strings.Split(path, ".") {
		var m map[string]json.RawMessage
		if json.Unmarshal(cur, &m) != nil {
			return nil, false
		}
		v, ok := m[seg]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// setJSONPath replaces the value at a dotted path of object keys.
func setJSONPath(doc []byte, path string, v json.RawMessage) ([]byte, error) {
	seg, rest, nested := strings.Cut(path, ".")
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		return nil, err
	}
	if nested {
		child, err := setJSONPath(m[seg], rest, v)
		if err != nil {
			return nil, err
		}
		v = child
	}
	m[seg] = v
	return json.Marshal(m)
}

// MigrateAppq moves the bring-up's plain packages out of DE storage (<data>/appq/*.ogpkg, og-os
// M12): sealed into the store on debuggable builds once CE storage and og-gate-link allow, deleted
// on every build. It retries until done (after 1 s first, backing off to 10 s) and logs counts only.
func (s *Server) MigrateAppq(ctx context.Context) {
	de := filepath.Join(s.cfg.DataDir, "appq")
	gateUID := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	delay, last := time.Second, ""
	for {
		migrated, deleted, err := s.appq.Migrate(de, s.cfg.Debuggable)
		for _, i := range migrated {
			s.recordAppq(ledger.AppqMigrated, "gate", gateUID, i, "", 0)
		}
		if len(migrated) > 0 || deleted > 0 {
			s.log.Info("app tenancy packages moved out of DE storage", "sealed", len(migrated), "deleted", deleted)
		}
		if err == nil {
			_ = os.Remove(de) // only when empty
			return
		}
		if err.Error() != last {
			last = err.Error()
			s.log.Info("app tenancy packages wait in DE storage", "reason", last)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, 10*time.Second)
	}
}

// appqHealth is the health op's "appq": whether tenancies can be used now, and how many there are.
func (s *Server) appqHealth() map[string]any {
	h := map[string]any{"ready": true}
	if err := s.appq.Ready(); err != nil {
		h["ready"], h["reason"] = false, err.Error()
	}
	if list, err := s.appq.List(); err == nil {
		h["tenancies"] = len(list)
	}
	return h
}
