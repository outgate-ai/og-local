package gate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/appq"
	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/route"
)

// App tenancies (og-os M12c, Q6): what the gate does with its sealed store (internal/gate/appq).
// The bring-up's plain DE packages are moved out; each change is a lifecycle row in the ledger.

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
