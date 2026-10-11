package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/outgate-ai/og-local/internal/gate/corelink"
)

// Approver is OG Core's approvals API as the gate uses it (corelink.Link).
type Approver interface {
	Up() bool
	Raise(ctx context.Context, r *corelink.Request) (string, error)
	Get(ctx context.Context, id string) (*corelink.Approval, error)
	Cancel(id, reason string)
}

// Timings of a held request. A held request waits up to its long-poll budget (or
// holdDefault); a caller that gives up gets needs_approval with the approval id, and
// the same request sent again joins the same approval while it is pending or, once
// answered, for answerKept.
const (
	holdDefault = 25 * time.Second
	holdMax     = 110 * time.Second
	pendingKept = 15 * time.Minute
	answerKept  = 10 * time.Minute
)

// Errors of the ask flow, mapped onto refused codes.
var (
	ErrApprovalDenied    = errors.New("approval_denied")
	ErrApprovalCancelled = errors.New("approval_cancelled")
	ErrCoreUnavailable   = errors.New("core_unavailable")
)

type ask struct {
	id       string
	fp       string
	created  time.Time
	done     chan struct{}
	approval *corelink.Approval
	answered time.Time
}

type asks struct {
	ap  Approver
	now func() time.Time

	mu   sync.Mutex
	byFP map[string]*ask
	byID map[string]*ask
}

func newAsks(ap Approver) *asks {
	return &asks{ap: ap, now: time.Now, byFP: map[string]*ask{}, byID: map[string]*ask{}}
}

// Resolved is OG Core's push (IOgGateObserver.onApprovalResolved).
func (a *asks) Resolved(ap *corelink.Approval) {
	a.mu.Lock()
	defer a.mu.Unlock()
	x, ok := a.byID[ap.ID]
	if !ok || x.approval != nil {
		return
	}
	cp := *ap
	x.approval, x.answered = &cp, a.now()
	close(x.done)
}

// decision is what an answered ask lets through.
type decision struct {
	id     string
	values map[string]int
	images bool
}

// fingerprint identifies "the same request again": destination, path, lane, the
// body and the values asked about. An answer never carries over to other content.
func fingerprint(dest, path, lane string, body []byte, na *NeedsApproval) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%v\x00", dest, path, lane, na.Images)
	_, _ = h.Write(body)
	_, _ = h.Write([]byte{0})
	items := append([]AskItem(nil), na.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].Value < items[j].Value })
	for _, it := range items {
		_, _ = fmt.Fprintf(h, "%d:%s\x00", it.Category, it.Value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hold raises (or joins) the 08 approval for na and waits for it within budget.
func (a *asks) hold(ctx context.Context, c *Call, dest string, na *NeedsApproval, budget time.Duration) (*decision, string, error) {
	if a == nil || a.ap == nil || !a.ap.Up() {
		return nil, "", ErrCoreUnavailable
	}
	req := c.Req
	if id := req.Egress.ApprovalID; id != "" {
		return a.existing(ctx, id, na, budget)
	}
	fp := fingerprint(dest, c.Path, req.Egress.LaneID, c.Raw, na)
	a.mu.Lock()
	a.gc()
	x, ok := a.byFP[fp]
	a.mu.Unlock()
	if !ok {
		r := gateApproval(c, dest, na)
		id, err := a.ap.Raise(ctx, r)
		if err != nil && r.LaneID != "" {
			// OG Core refuses lanes it doesn't know (a caller's own lane id): the sheet still
			// shows, just not attached to a lane.
			r.LaneID = ""
			id, err = a.ap.Raise(ctx, r)
		}
		if err != nil {
			return nil, "", fmt.Errorf("%w: %v", ErrCoreUnavailable, err)
		}
		x = &ask{id: id, fp: fp, created: a.now(), done: make(chan struct{})}
		a.mu.Lock()
		a.byFP[fp], a.byID[id] = x, x
		a.mu.Unlock()
	}
	select {
	case <-x.done:
	case <-time.After(budget):
		return nil, x.id, ErrNeedsApproval
	case <-ctx.Done():
		return nil, x.id, ErrNeedsApproval
	}
	d, err := decide(x.approval, na, true)
	return d, x.id, err
}

// existing follows an approval someone else raised and named in the request
// (og-agentd's screenshot approvals, CONTRACT.md §6.5).
func (a *asks) existing(ctx context.Context, id string, na *NeedsApproval, budget time.Duration) (*decision, string, error) {
	deadline := a.now().Add(budget)
	for {
		ap, err := a.ap.Get(ctx, id)
		if err != nil {
			return nil, id, fmt.Errorf("%w: %v", ErrCoreUnavailable, err)
		}
		if ap == nil {
			return nil, id, ErrApprovalCancelled
		}
		if ap.State != corelink.StatePending {
			d, err := decide(ap, na, false)
			return d, id, err
		}
		if a.now().After(deadline) {
			return nil, id, ErrNeedsApproval
		}
		select {
		case <-ctx.Done():
			return nil, id, ErrNeedsApproval
		case <-time.After(time.Second):
		}
	}
}

// decide turns an answer into per-value actions. Approve: each disclosure's
// treatment (real → allow, masked → mask, blocked → block, missing → its default);
// any other role refuses. own is set for approvals the gate raised: their image
// disclosure defaults to blocked, so an image leaves only when chosen REAL. An
// approval someone else raised and named (og-agentd's screenshot grant) is a plain
// yes or no for its image.
func decide(ap *corelink.Approval, na *NeedsApproval, own bool) (*decision, error) {
	if ap.State == corelink.StateCancelled || ap.Answer == nil {
		return nil, ErrApprovalCancelled
	}
	if ap.Answer.Role != corelink.RoleApprove {
		return nil, ErrApprovalDenied
	}
	d := &decision{id: ap.ID, values: map[string]int{}}
	choice := map[string]int{}
	for _, c := range ap.Answer.Choices {
		choice[c.Item] = c.Treatment
	}
	for i, it := range na.Items {
		switch choice[disclosureID(i)] {
		case corelink.TreatReal:
			d.values[it.Value] = 2
		case corelink.TreatBlocked:
			d.values[it.Value] = 4
		default:
			d.values[it.Value] = 1
		}
	}
	if na.Images {
		d.images = choice["image"] == corelink.TreatReal || !own
	}
	return d, nil
}

func disclosureID(i int) string { return fmt.Sprintf("d%d", i) }

var fieldNames = map[string]string{
	"NAME": "name", "PHONE": "phone", "EMAIL": "email", "ADDRESS": "address", "PAYMENT": "payment",
	"CREDENTIAL": "credential", "GOV_ID": "id", "LOCATION": "location", "TRACKERS": "tracker",
}

var fieldLabels = map[string]string{
	"NAME": "Name", "PHONE": "Phone", "EMAIL": "Email", "ADDRESS": "Address", "PAYMENT": "Payment",
	"CREDENTIAL": "Password or key", "GOV_ID": "ID number", "LOCATION": "Location", "TRACKERS": "Tracker",
}

// gateApproval is the 08 sheet: what would leave, per value, with Real / Masked /
// Blocked to choose from (Masked by default).
func gateApproval(c *Call, dest string, na *NeedsApproval) *corelink.Request {
	r := &corelink.Request{
		LaneID: c.Req.Egress.LaneID, AccountID: c.Req.Source.AccountID, RegionID: c.Req.Source.RegionID,
		ThreadID: c.Req.Egress.ThreadID, Kicker: "YOUR CALL · GATE 1 OF 1", GateIndex: 1, GateCount: 1,
		Title: "Let this leave your phone?", Subtitle: "Going to " + dest,
		Footnote: "Masked values leave as placeholders and come back filled in. Nothing leaves until you answer.",
		Actions: []corelink.Action{
			{ID: "send", Label: "Send as chosen", Role: corelink.RoleApprove, Style: corelink.StylePrimary},
			{ID: "dont", Label: "Don't send", Role: corelink.RoleSkip, Style: corelink.StyleSecondary},
		},
	}
	allowed := []int{corelink.TreatReal, corelink.TreatMasked, corelink.TreatBlocked}
	for i, it := range na.Items {
		r.Disclosures = append(r.Disclosures, corelink.Disclosure{
			ID: disclosureID(i), Field: fieldNames[it.Name], Label: fieldLabels[it.Name], Preview: preview(it.Value),
			Allowed: allowed, Default: corelink.TreatMasked,
		})
	}
	if na.Images {
		r.Disclosures = append(r.Disclosures, corelink.Disclosure{
			ID: "image", Field: "image", Label: "Image", Preview: "1 image",
			Allowed: []int{corelink.TreatReal, corelink.TreatBlocked}, Default: corelink.TreatBlocked,
		})
	}
	if len(na.Items) == 0 && na.Images {
		r.Title = "Send an image?"
	}
	return r
}

// preview shows the value on the user's own sheet, cut to a line.
func preview(v string) string {
	v = strings.Join(strings.Fields(v), " ")
	if utf8.RuneCountInString(v) <= 48 {
		return v
	}
	r := []rune(v)
	return string(r[:45]) + "…"
}

// gc cancels approvals nobody came back for and forgets old answers. a.mu held.
func (a *asks) gc() {
	now := a.now()
	for fp, x := range a.byFP {
		switch {
		case x.approval == nil && now.Sub(x.created) > pendingKept:
			a.ap.Cancel(x.id, "request_expired")
		case x.approval != nil && now.Sub(x.answered) > answerKept:
		default:
			continue
		}
		delete(a.byFP, fp)
		delete(a.byID, x.id)
	}
}
