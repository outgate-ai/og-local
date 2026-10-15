package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/appq"
	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// App tenancies (og-os M12c, Q6): what the gate does with its sealed store (internal/gate/appq).
// The appq_* ops list, remove and (debuggable builds) import tenancies; the bring-up's plain DE
// packages are moved out; each change is a lifecycle row in the ledger.

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
