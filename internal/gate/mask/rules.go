package mask

import (
	"math/big"
	"net/url"
	"regexp"
	"strings"
)

// Span is one finding in a text: bytes [Start, End) of Category.
type Span struct {
	Start    int
	End      int
	Category Category
	// Rule names the rule that found it ("" for the detector).
	Rule string
}

type rule struct {
	name     string
	category Category
	re       *regexp.Regexp
	// group selects a submatch as the value (0 = the whole match).
	group int
	valid func(string) bool
}

// rules run on every content string before the detector, in microseconds. They
// catch structured, high-risk values whatever the model does, and never replace it.
var rules = []rule{
	{
		name: "pem", category: Credential,
		re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
	},
	{
		name: "jwt", category: Credential,
		re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	},
	{
		name: "bearer", category: Credential, group: 1,
		re: regexp.MustCompile(`(?i)\bbearer(?:\s*[:=]\s*|\s+)["']?([A-Za-z0-9._~+/=-]{12,})`),
	},
	{
		name: "assignment", category: Credential, group: 1,
		re: regexp.MustCompile(`(?i)\b(?:token|api[_-]?key|secret|password|passwd|client[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{12,})`),
	},
	{
		name: "key-prefix", category: Credential,
		re: regexp.MustCompile(`\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|oghk_[A-Za-z0-9_-]{16,}|gw_[A-Za-z0-9_-]{20,}|pt_[A-Za-z0-9_-]{24,})`),
	},
	{
		name: "email", category: Email,
		re: regexp.MustCompile(`[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b`),
	},
	{
		name: "iban", category: Payment, valid: validIBAN,
		re: regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`),
	},
	{
		name: "card", category: Payment, valid: validCard,
		re: regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`),
	},
	{
		name: "ssn", category: GovID,
		re: regexp.MustCompile(`\b(?:00[1-9]|0[1-9][0-9]|[1-578][0-9]{2}|6[0-57-9][0-9]|66[0-57-9])-(?:0[1-9]|[1-9][0-9])-(?:000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})\b`),
	},
	{
		name: "phone", category: Phone, valid: validPhone,
		re: regexp.MustCompile(`(?:\+[1-9][0-9]{0,2}[ .-]?)?(?:\([0-9]{1,4}\)[ .-]?)?[0-9]{2,4}(?:[ .-]?[0-9]{2,4}){2,4}\b`),
	},
	{
		name: "geo", category: Location,
		re: regexp.MustCompile(`[-+]?(?:[1-8]?[0-9]\.[0-9]{4,}|90\.0{4,}),\s*[-+]?(?:1[0-7][0-9]|[1-9]?[0-9])\.[0-9]{4,}\b`),
	},
}

// trackerParams are query parameters that exist to track people across sites.
var trackerParams = map[string]bool{
	"fbclid": true, "gclid": true, "dclid": true, "gbraid": true, "wbraid": true, "msclkid": true,
	"mc_eid": true, "mc_cid": true, "igshid": true, "yclid": true, "_hsenc": true, "_hsmi": true,
	"twclid": true, "ttclid": true, "li_fat_id": true, "s_cid": true, "oly_enc_id": true, "oly_anon_id": true,
	"vero_id": true, "rb_clickid": true, "_openstat": true, "mkt_tok": true, "__s": true,
}

var urlRE = regexp.MustCompile(`https?://[^\s"'<>]+`)

// findRules returns the rule findings in text, longest first where they overlap.
func findRules(text string) []Span {
	var out []Span
	for _, r := range rules {
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := m[2*r.group], m[2*r.group+1]
			if s < 0 {
				continue
			}
			if r.valid != nil && !r.valid(text[s:e]) {
				continue
			}
			out = append(out, Span{Start: s, End: e, Category: r.category, Rule: r.name})
		}
	}
	out = append(out, findTrackers(text)...)
	return resolveOverlaps(out)
}

// findTrackers marks tracking parameters inside URLs ("utm_source=…") together with
// one separator, so blocking one (replacing its span with "") leaves a valid URL.
func findTrackers(text string) []Span {
	var out []Span
	for _, loc := range urlRE.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		q := strings.IndexByte(raw, '?')
		if q < 0 {
			continue
		}
		end := len(raw)
		if h := strings.IndexByte(raw, '#'); h > q {
			end = h
		}
		parts := strings.Split(raw[q+1:end], "&")
		tracker := make([]bool, len(parts))
		kept := 0
		for i, part := range parts {
			name, _, _ := strings.Cut(part, "=")
			name, _ = url.QueryUnescape(name)
			name = strings.ToLower(name)
			tracker[i] = trackerParams[name] || strings.HasPrefix(name, "utm_")
			if !tracker[i] {
				kept++
			}
		}
		// Each removed parameter takes exactly one separator with it, so the spans
		// never overlap and what is left is a valid URL: the "&" before it when a kept
		// parameter precedes it, else the "&" after it when one follows, else the "?"
		// or "&" before it (a query of trackers only disappears entirely).
		pos := loc[0] + q + 1
		keptBefore := 0
		for i, part := range parts {
			start := pos
			pos += len(part) + 1
			if !tracker[i] {
				keptBefore++
				continue
			}
			s, e := start, start+len(part)
			switch {
			case keptBefore > 0:
				s--
			case kept > 0:
				e++
			default:
				s--
			}
			out = append(out, Span{Start: s, End: e, Category: Trackers, Rule: "tracker"})
		}
	}
	return out
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// validCard: an issuer prefix with that issuer's length, passing Luhn.
func validCard(s string) bool {
	d := digits(s)
	n := len(d)
	ok := false
	switch {
	case d[0] == '4':
		ok = n == 13 || n == 16 || n == 19
	case d[:2] == "34" || d[:2] == "37":
		ok = n == 15
	case d[0] == '5' && d[1] >= '1' && d[1] <= '5', d[:2] == "22":
		ok = n == 16
	case d[:2] == "36":
		ok = n == 14
	case d[:4] == "6011", d[:2] == "65", d[:2] == "35", d[:2] == "62":
		ok = n >= 16 && n <= 19
	}
	if !ok {
		return false
	}
	sum := 0
	for i := 0; i < n; i++ {
		v := int(d[n-1-i] - '0')
		if i%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return sum%10 == 0
}

// validIBAN: ISO 13616 mod-97 check.
func validIBAN(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	r := s[4:] + s[:4]
	var b strings.Builder
	for _, c := range r {
		switch {
		case c >= '0' && c <= '9':
			b.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			b.WriteString(big.NewInt(int64(c - 'A' + 10)).String())
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(b.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

// validPhone keeps 8–15 digit numbers and drops what is more likely a date, a
// time, a version or an amount.
var dateLike = regexp.MustCompile(`^(?:[0-9]{4}[-./][0-9]{1,2}[-./][0-9]{1,2}|[0-9]{1,2}[-./][0-9]{1,2}[-./][0-9]{2,4})$`)

func validPhone(s string) bool {
	if dateLike.MatchString(s) {
		return false
	}
	d := digits(s)
	if len(d) < 8 || len(d) > 15 {
		return false
	}
	if strings.Count(s, ".") >= 2 && !strings.HasPrefix(s, "+") {
		return false
	}
	if !strings.ContainsAny(s, " -.()") && !strings.HasPrefix(s, "+") && len(d) > 11 {
		return false
	}
	return true
}

// resolveOverlaps keeps the longest of overlapping spans (credentials win ties).
func resolveOverlaps(in []Span) []Span {
	if len(in) < 2 {
		return in
	}
	sortSpans(in)
	out := in[:0]
	for _, s := range in {
		if n := len(out); n > 0 && s.Start < out[n-1].End {
			last := &out[n-1]
			if s.End-s.Start > last.End-last.Start || (s.End-s.Start == last.End-last.Start && s.Category == Credential) {
				*last = s
			}
			continue
		}
		out = append(out, s)
	}
	return out
}
