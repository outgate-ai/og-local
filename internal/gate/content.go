package gate

import (
	"context"
	"errors"

	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// Masker transforms request content before it leaves and restores the response.
type Masker interface {
	// Mask returns the body to send. An error refuses the request (fail closed).
	Mask(ctx context.Context, c *Call, body []byte) (out []byte, masked wire.Masked, err error)
	// Restore returns the body to hand back to the caller.
	Restore(ctx context.Context, c *Call, body []byte) (out []byte, restored []wire.Restored)
	// Ready reports whether content can be masked now, with a reason when not.
	Ready() (ready bool, reason string)
}

// ErrDetectorUnavailable refuses content while no detector is loaded.
var ErrDetectorUnavailable = errors.New("detector_unavailable")

type passthrough struct{}

func (passthrough) Mask(_ context.Context, _ *Call, body []byte) (out []byte, masked wire.Masked, err error) {
	return body, wire.Masked{}, nil
}

func (passthrough) Restore(_ context.Context, _ *Call, body []byte) (out []byte, restored []wire.Restored) {
	return body, nil
}

func (passthrough) Ready() (ready bool, reason string) { return true, "" }

// unavailable is the mask mode before a detector exists: content never leaves.
type unavailable struct{ reason string }

func (unavailable) Mask(context.Context, *Call, []byte) (out []byte, masked wire.Masked, err error) {
	return nil, wire.Masked{}, ErrDetectorUnavailable
}

func (unavailable) Restore(_ context.Context, _ *Call, body []byte) (out []byte, restored []wire.Restored) {
	return body, nil
}

func (u unavailable) Ready() (ready bool, reason string) { return false, u.reason }

// Call is one request on its way through the gate.
type Call struct {
	Caller  string
	Req     *wire.Request
	Path    string
	Kind    string
	Content bool
	// ContentType is the request body's type; Binary is set for uploads and
	// base64 bodies, whose bytes are Raw.
	ContentType string
	Binary      bool
	Raw         []byte
	// Approved: the request names an approval OG Core confirmed (uploads, step 7).
	Approved bool
	// RespContentType is the upstream response's type, set before Restore.
	RespContentType string
}

// Refusal reasons a Masker may return (errors.Is), mapped onto refused codes.
var (
	ErrNeedsApproval = errors.New("needs_approval")
	ErrStorageLocked = errors.New("storage_locked")
)

// egressKinds without user content: they pass even when content can't be masked.
var contentFree = map[string]bool{"poll": true, "presence": true, "token": true, "control": true}

// coreKind maps a request onto OG Core's ledger classes: llm, tool, upload, answer, event, other.
func coreKind(egressKind, method, pathClass string, onDevice bool) string {
	switch egressKind {
	case "report", "snapshot":
		return "tool"
	case "upload":
		return "upload"
	case "gate":
		return "answer"
	case "poll":
		return "event"
	case "presence", "token", "relay", "control":
		return "other"
	}
	switch {
	case onDevice:
		return "llm"
	case hasSuffix(pathClass, "/answer"):
		return "answer"
	case hasSuffix(pathClass, "/uploads") || hasSuffix(pathClass, "/files"):
		return "upload"
	case hasSuffix(pathClass, "/events") && method == "POST":
		return "event"
	case hasSuffix(pathClass, "/events"):
		return "event"
	}
	return "other"
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}
