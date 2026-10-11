package mask

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/outgate-ai/og-local/internal/gate"
	"github.com/outgate-ai/og-local/internal/gate/wire"
	"github.com/outgate-ai/og-local/internal/pii"
)

// Blocked replaces a value the policy blocks: it never leaves, and nothing restores it.
const Blocked = "[blocked]"

// batchTarget is how much field text goes into one detector call. It matches
// og-local's chunk size, so a batch is one model run.
const batchTarget = 4096

// Masker implements gate.Masker.
type Masker struct {
	Store    *Store
	Detector *Detector

	mu     sync.RWMutex
	policy Policy
}

func New(store *Store, det *Detector) *Masker {
	return &Masker{Store: store, Detector: det, policy: DefaultPolicy()}
}

// SetPolicy replaces the user's policy (OG Core pushes it, CONTRACT.md 4.10).
func (m *Masker) SetPolicy(p Policy) {
	m.mu.Lock()
	m.policy = p
	m.mu.Unlock()
}

func (m *Masker) Policy() Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policy
}

func (m *Masker) Ready() (ready bool, reason string) {
	if err := m.Store.Ready(); err != nil {
		return false, err.Error()
	}
	if err := m.Detector.Usable(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// NeedsApproval reports which categories a refused request asked about.
type NeedsApproval struct {
	Categories []Category
}

// NeedsApproval is gate.ErrNeedsApproval: the policy says "ask" for something in the
// request (step 6 holds it for an 08 approval; until then it doesn't leave).
func (e *NeedsApproval) Error() string {
	names := make([]string, len(e.Categories))
	for i, c := range e.Categories {
		names[i] = c.String()
	}
	return gate.ErrNeedsApproval.Error() + ": " + strings.Join(names, ",")
}

func (e *NeedsApproval) Is(t error) bool { return t == gate.ErrNeedsApproval }

// Mask finds what the policy covers in the request's content and swaps it out.
func (m *Masker) Mask(ctx context.Context, c *gate.Call, body []byte) (out []byte, masked wire.Masked, err error) {
	if c.Binary {
		return m.maskBinary(c)
	}
	var doc any
	jsonBody := isJSONBody(c.ContentType, body)
	if jsonBody {
		if doc, err = decodeJSON(body); err != nil {
			return nil, masked, fmt.Errorf("mask: body: %w", err)
		}
	}
	var fields []field
	if jsonBody {
		walkStrings(doc, "", true, func(f field) { fields = append(fields, f) })
	} else {
		if !utf8.Valid(body) {
			return nil, masked, &NeedsApproval{Categories: []Category{Images}}
		}
		text := string(body)
		fields = []field{{path: "", text: text, set: func(n string) { text = n; body = []byte(n) }}}
	}
	if err := m.Store.Ready(); err != nil {
		return nil, masked, gate.ErrStorageLocked
	}
	findings, err := m.find(ctx, fields)
	if err != nil {
		if errors.Is(err, ErrDetectorUnavailable) {
			return nil, masked, gate.ErrDetectorUnavailable
		}
		return nil, masked, err
	}
	pol := m.Policy()
	var ask []Category
	values := map[string]Category{}
	for i := range fields {
		for _, s := range findings[i] {
			v := fields[i].text[s.Start:s.End]
			if prev, ok := values[v]; !ok || severity(s.Category) > severity(prev) {
				values[v] = s.Category
			}
		}
	}
	type sub struct {
		from, to string
		cat      Category
		action   Action
	}
	var subs []sub
	var toMint []Item
	for v, cat := range values {
		switch pol.Action(cat) {
		case Allow:
		case Ask:
			ask = append(ask, cat)
		case Block:
			to := Blocked
			if cat == Trackers {
				to = ""
			}
			subs = append(subs, sub{from: v, to: to, cat: cat, action: Block})
		default:
			subs = append(subs, sub{from: v, cat: cat, action: Mask})
			toMint = append(toMint, Item{Category: cat, Value: v})
		}
	}
	if len(ask) > 0 {
		return nil, masked, &NeedsApproval{Categories: uniqueCats(ask)}
	}
	if len(toMint) > 0 {
		phs, err := m.Store.Assign(toMint)
		if errors.Is(err, ErrLocked) {
			return nil, masked, gate.ErrStorageLocked
		}
		if err != nil {
			return nil, masked, err
		}
		j := 0
		for i := range subs {
			if subs[i].action == Mask {
				subs[i].to = phs[j]
				j++
			}
		}
	}
	if len(subs) == 0 {
		return body, masked, nil
	}
	sort.SliceStable(subs, func(i, j int) bool { return len(subs[i].from) > len(subs[j].from) })
	masked.Categories = map[string]int{}
	for _, s := range subs {
		if s.action == Block {
			masked.Blocked++
			continue
		}
		masked.Count++
		masked.Categories[s.cat.Label()]++
	}
	for i := range fields {
		t := fields[i].text
		for _, s := range subs {
			t = replaceOutsideBase64(t, s.from, s.to)
		}
		if t != fields[i].text {
			fields[i].set(t)
		}
	}
	if !jsonBody {
		return body, masked, nil
	}
	out, err = encodeJSON(doc)
	return out, masked, err
}

// severity orders categories when the same value was found as two: credentials first.
func severity(c Category) int {
	switch c {
	case Credential:
		return 5
	case Payment, GovID:
		return 4
	case Trackers:
		return 1
	default:
		return 3
	}
}

func uniqueCats(in []Category) []Category {
	seen := map[Category]bool{}
	var out []Category
	for _, c := range in {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// maskBinary: images and other binary bodies can't be masked. The IMAGES policy
// decides (decision #18: blocked unless approved on the 08 sheet).
func (m *Masker) maskBinary(c *gate.Call) (out []byte, masked wire.Masked, err error) {
	switch m.Policy().Action(Images) {
	case Allow:
		return c.Raw, masked, nil
	case Ask:
		if c.Approved {
			return c.Raw, masked, nil
		}
		return nil, masked, &NeedsApproval{Categories: []Category{Images}}
	default:
		masked.Blocked = 1
		return nil, masked, nil
	}
}

// find runs the rules on every field and the detector on batches of fields.
func (m *Masker) find(ctx context.Context, fields []field) ([][]Span, error) {
	out := make([][]Span, len(fields))
	for i, f := range fields {
		out[i] = findRules(f.text)
	}
	type member struct{ field, offset int }
	var batches []string
	var members [][]member
	var cur strings.Builder
	var curMembers []member
	flush := func() {
		if cur.Len() > 0 {
			batches = append(batches, cur.String())
			members = append(members, curMembers)
			cur.Reset()
			curMembers = nil
		}
	}
	for i, f := range fields {
		if len(f.text) < pii.MinDetectionLen {
			continue
		}
		if cur.Len() > 0 && cur.Len()+len(f.text)+2 > batchTarget {
			flush()
		}
		if cur.Len() > 0 {
			cur.WriteString("\n\n")
		}
		curMembers = append(curMembers, member{field: i, offset: cur.Len()})
		cur.WriteString(f.text)
	}
	flush()
	if len(batches) == 0 {
		return out, nil
	}
	spans, err := m.Detector.Spans(ctx, batches)
	if err != nil {
		return nil, err
	}
	for b, list := range spans {
		for _, s := range list {
			for _, mem := range members[b] {
				f := fields[mem.field]
				start, end := s.Start-mem.offset, s.End-mem.offset
				if end <= 0 || start >= len(f.text) {
					continue
				}
				start, end = max(start, 0), min(end, len(f.text))
				if end-start < pii.MinDetectionLen {
					continue
				}
				out[mem.field] = append(out[mem.field], Span{Start: start, End: end, Category: classCategory(s.Class)})
			}
		}
	}
	for i := range out {
		out[i] = resolveOverlaps(out[i])
	}
	return out, nil
}

// replaceOutsideBase64 replaces every from with to, except inside long base64
// runs (images, binary blobs) where a short value could match by chance.
func replaceOutsideBase64(text, from, to string) string {
	if from == "" || !strings.Contains(text, from) {
		return text
	}
	protected := base64Runs(text)
	var b strings.Builder
	pos := 0
	for {
		i := strings.Index(text[pos:], from)
		if i < 0 {
			break
		}
		at := pos + i
		if inRuns(at, protected) {
			b.WriteString(text[pos : at+len(from)])
		} else {
			b.WriteString(text[pos:at])
			b.WriteString(to)
		}
		pos = at + len(from)
	}
	b.WriteString(text[pos:])
	return b.String()
}

func base64Runs(s string) [][2]int {
	var out [][2]int
	start := -1
	for i := 0; i <= len(s); i++ {
		in := i < len(s) && isB64(s[i])
		if in && start < 0 {
			start = i
		}
		if !in && start >= 0 {
			if i-start >= 200 {
				out = append(out, [2]int{start, i})
			}
			start = -1
		}
	}
	return out
}

func isB64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
}

func inRuns(pos int, runs [][2]int) bool {
	for _, r := range runs {
		if pos >= r[0] && pos < r[1] {
			return true
		}
	}
	return false
}

func isJSONBody(ctype string, body []byte) bool {
	mt, _, _ := mime.ParseMediaType(ctype)
	if mt != "" && mt != "application/json" && !strings.HasSuffix(mt, "+json") {
		return false
	}
	t := bytes.TrimSpace(body)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[' || t[0] == '"')
}

// Restore puts values back for every placeholder in the map, anywhere in the
// response (replies arrive on other requests, minutes or hours later).
func (m *Masker) Restore(_ context.Context, c *gate.Call, body []byte) (out []byte, restored []wire.Restored) {
	if len(body) == 0 || !bytes.Contains(body, []byte("OG_")) || m.Store.Ready() != nil {
		return body, nil
	}
	if !isJSONBody(c.RespContentType, body) {
		if !utf8.Valid(body) {
			return body, nil
		}
		t, n := m.restoreText(string(body))
		for _, cat := range n {
			restored = append(restored, wire.Restored{Path: "", Class: cat.String()})
		}
		return []byte(t), restored
	}
	doc, err := decodeJSON(body)
	if err != nil {
		return body, nil
	}
	walkStrings(doc, "", false, func(f field) {
		if !strings.Contains(f.text, "OG_") {
			return
		}
		t, cats := m.restoreText(f.text)
		if len(cats) == 0 {
			return
		}
		f.set(t)
		for _, cat := range cats {
			restored = append(restored, wire.Restored{Path: strings.TrimPrefix(f.path, "."), Class: cat.String()})
		}
	})
	if len(restored) == 0 {
		return body, nil
	}
	sort.Slice(restored, func(i, j int) bool { return restored[i].Path < restored[j].Path })
	out, err = encodeJSON(doc)
	if err != nil {
		return body, nil
	}
	return out, restored
}

func (m *Masker) restoreText(t string) (string, []Category) {
	var cats []Category
	out := placeholderRE.ReplaceAllStringFunc(t, func(ph string) string {
		v, cat, ok := m.Store.Lookup(ph)
		if !ok {
			return ph
		}
		cats = append(cats, cat)
		return v
	})
	return out, cats
}
