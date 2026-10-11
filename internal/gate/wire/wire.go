// Package wire is the og_gate socket protocol: one JSON request line in, one JSON
// response line out, one request per connection. Callers are og-agentd (M07),
// OGChat and debug tools; the gate owns the protocol (og-agentd CONTRACT.md §12).
package wire

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const Version = 1

// MaxLine bounds one request line (uploads inline as body_b64 included).
const MaxLine = 48 << 20

type Source struct {
	AccountID string `json:"account_id,omitempty"`
	RegionID  string `json:"region_id,omitempty"`
	// Adapter is og-agentd's transport (devq, appq, local) or "chat".
	Adapter string `json:"adapter,omitempty"`
}

// Egress describes the request for the ledger and for policy.
type Egress struct {
	LaneID     string `json:"lane_id,omitempty"`
	StepIndex  *int   `json:"step_index,omitempty"`
	Kind       string `json:"kind,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	ThreadID   string `json:"thread_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
}

type Request struct {
	V  int    `json:"v,omitempty"`
	ID string `json:"id,omitempty"`
	// Op is empty for an upstream request; "download" fetches a model file from the
	// mirror into a passed descriptor; "health" and "ledger" are local.
	Op     string `json:"op,omitempty"`
	Source Source `json:"source"`
	Method string `json:"method,omitempty"`
	// URL is an absolute https URL; otherwise Path (+ Query) is resolved against
	// the destination named by Source.RegionID ("global", "oidc", a region id,
	// "appq:<tenancy>", "on-device", "provider:<id>").
	URL     string            `json:"url,omitempty"`
	Path    string            `json:"path,omitempty"`
	Query   map[string]any    `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// Body is a JSON value; BodyText and BodyB64 carry non-JSON bodies.
	Body        json.RawMessage `json:"body,omitempty"`
	BodyText    *string         `json:"body_text,omitempty"`
	BodyB64     string          `json:"body_b64,omitempty"`
	ContentType string          `json:"content_type,omitempty"`
	// File is a file the gate uploads as multipart (fields from Body, an object).
	File      string `json:"file,omitempty"`
	FileField string `json:"file_field,omitempty"`
	Egress    Egress `json:"egress"`
	// TimeoutMs is the long-poll budget; the gate answers within max(TimeoutMs, 10 s) + 2 s.
	// For a download it is the idle timeout (at least 10 s); a download has no total timeout.
	TimeoutMs int64 `json:"timeout_ms,omitempty"`
	// Offset and Size are for op "download": where the caller's partial file ends, and
	// the file's exact total size.
	Offset *int64 `json:"offset,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// Limit is for op "ledger".
	Limit int `json:"limit,omitempty"`
}

type Masked struct {
	Count   int `json:"count"`
	Blocked int `json:"blocked"`
	// Categories counts masked values per region label, e.g. {"PII": 2}.
	Categories map[string]int `json:"categories,omitempty"`
	// Mask is "on", "off" or "not_required" (traffic to Outgate isn't masked on the phone).
	Mask string `json:"mask,omitempty"`
}

type Restored struct {
	Path  string `json:"path"`
	Class string `json:"class"`
}

type Response struct {
	V  int    `json:"v"`
	ID string `json:"id,omitempty"`
	// Op is set for a download.
	Op       string            `json:"op,omitempty"`
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     json.RawMessage   `json:"body,omitempty"`
	BodyText *string           `json:"body_text,omitempty"`
	BodyB64  string            `json:"body_b64,omitempty"`
	Masked   Masked            `json:"masked"`
	Restored []Restored        `json:"restored,omitempty"`
	// Refused is set when the gate kept the request from leaving (policy, fail-closed).
	Refused string `json:"refused,omitempty"`
	Detail  string `json:"detail,omitempty"`
	// Ledger is the gate's row id for this request.
	Ledger string `json:"ledger,omitempty"`
	// Class is the destination's class: outgate, on-device, provider or mirror.
	Class string `json:"class,omitempty"`
	// ApprovalID is the 08 approval a held request waits for (refused needs_approval:
	// send the same request again, or with egress.approval_id, after it is answered).
	ApprovalID string `json:"approval_id,omitempty"`
	// Start, Written and Complete report a download once it writes: the file offset it
	// wrote from, the bytes written now, and whether the file has all its bytes.
	Start    *int64 `json:"start,omitempty"`
	Written  *int64 `json:"written,omitempty"`
	Complete *bool  `json:"complete,omitempty"`
}

var ErrTooLong = errors.New("wire: request line too long")

// ReadRequest reads one request line.
func ReadRequest(r io.Reader) (*Request, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > MaxLine {
			return nil, ErrTooLong
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			break
		}
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, fmt.Errorf("wire: bad request: %w", err)
	}
	if req.V > Version {
		return nil, fmt.Errorf("wire: version %d not supported", req.V)
	}
	return &req, nil
}

// WriteResponse writes one response line.
func WriteResponse(w io.Writer, resp *Response) error {
	resp.V = Version
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// Refuse builds a refusal; status is what HTTP-minded callers see.
func Refuse(id string, status int, reason, detail string) *Response {
	return &Response{
		ID: id, Status: status, Refused: reason, Detail: detail,
		Body: mustJSON(map[string]string{"error": reason, "detail": detail}),
	}
}

// Fail is an error the gate reports without having refused anything (the upstream
// was unreachable): Refused stays empty, so callers treat it like an HTTP error.
func Fail(id string, status int, code, detail string) *Response {
	return &Response{
		ID: id, Status: status, Detail: detail,
		Body: mustJSON(map[string]string{"error": code, "detail": detail}),
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
