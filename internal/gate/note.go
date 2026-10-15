package gate

import (
	"fmt"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// noteEvents are the tunnel launcher's lifecycle notes; noteErrorKinds why a tunnel went down.
var (
	noteEvents     = map[string]bool{"tunnel.enabled": true, "tunnel.disabled": true, "tunnel.connected": true, "tunnel.disconnected": true}
	noteErrorKinds = map[string]bool{"route": true, "token": true, "dns": true, "network": true}
)

// note records a lifecycle note of the tunnel launcher in the ledger and the health op.
func (s *Server) note(cred peer.Cred, req *wire.Request) *wire.Response {
	switch {
	case !noteEvents[req.Event]:
		return wire.Refuse(req.ID, 400, "bad_request", fmt.Sprintf("unknown event %.64q", req.Event))
	case req.ErrorKind != "" && !noteErrorKinds[req.ErrorKind]:
		return wire.Refuse(req.ID, 400, "bad_request", fmt.Sprintf("unknown error_kind %.64q", req.ErrorKind))
	case req.Links != nil && *req.Links < 0:
		return wire.Refuse(req.ID, 400, "bad_request", "links < 0")
	}
	row := ledger.Row{
		ID: s.nextID(), Time: time.Now().UTC(), Caller: callerTunnelLauncher, UID: cred.UID,
		Event: req.Event, Destination: "tunnel", Kind: "event", Status: 200,
		Mode: string(s.cfg.Mode), Mask: MaskNotRequired, Error: req.ErrorKind,
	}
	s.ledger.Record(&row)
	links := -1
	if req.Links != nil {
		links = *req.Links
	}
	s.log.Info("tunnel note", "event", req.Event, "links", links, "error_kind", req.ErrorKind)
	state := map[string]any{"event": req.Event}
	if req.Links != nil {
		state["links"] = *req.Links
	}
	if req.ErrorKind != "" {
		state["error_kind"] = req.ErrorKind
	}
	s.SetHealth("tunnel", state)
	resp := jsonResponse(200, struct{}{})
	resp.Ledger = row.ID
	return resp
}
