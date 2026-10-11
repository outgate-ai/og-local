// Package mask is the gate's content layer: it finds personal data and
// credentials in what leaves the phone (a rules layer plus the privacy-filter
// detector), applies the user's masking policy per category, swaps masked values
// for region placeholders keyed by a device secret, keeps the placeholder map, and
// restores placeholders in what comes back.
package mask

import "github.com/outgate-ai/og-local/internal/pii"

// Category is OG Core's MaskingCategory (CONTRACT.md 4.10); the wire values match.
type Category int

const (
	Name       Category = 1
	Phone      Category = 2
	Email      Category = 3
	Address    Category = 4
	Payment    Category = 5
	Credential Category = 6
	GovID      Category = 7
	Location   Category = 8
	Trackers   Category = 9
	Images     Category = 10
	// Other is personal data no OG Core category covers (dates, personal URLs). It
	// follows no user setting: always masked.
	Other Category = 100
)

var categoryNames = map[Category]string{
	Name: "NAME", Phone: "PHONE", Email: "EMAIL", Address: "ADDRESS", Payment: "PAYMENT",
	Credential: "CREDENTIAL", GovID: "GOV_ID", Location: "LOCATION", Trackers: "TRACKERS",
	Images: "IMAGES", Other: "OTHER",
}

func (c Category) String() string {
	if n, ok := categoryNames[c]; ok {
		return n
	}
	return "UNKNOWN"
}

// Label is the region guardrail's label for c: the region recognises only
// OG_(CREDENTIAL|PII|SENSITIVE|INJECTION|MALICIOUS)_<hex> as its own tokens.
func (c Category) Label() string {
	switch c {
	case Credential:
		return "CREDENTIAL"
	case Payment, GovID:
		return "SENSITIVE"
	default:
		return "PII"
	}
}

// Action is OG Core's MaskingAction.
type Action int

const (
	Mask  Action = 1
	Allow Action = 2
	Ask   Action = 3
	Block Action = 4
)

func (a Action) String() string {
	switch a {
	case Mask:
		return "MASK"
	case Allow:
		return "ALLOW"
	case Ask:
		return "ASK"
	case Block:
		return "BLOCK"
	}
	return "UNKNOWN"
}

// Policy maps categories to actions. Defaults are OG Core's MaskingPolicy.DEFAULTS
// (decisions #18, #20): mask PII and credentials, block trackers, ask for images.
type Policy map[Category]Action

func DefaultPolicy() Policy {
	return Policy{
		Name: Mask, Phone: Mask, Email: Mask, Address: Mask, Payment: Mask,
		Credential: Mask, GovID: Mask, Location: Mask, Trackers: Block, Images: Ask,
	}
}

// Action returns the action for c; categories without a rule are masked.
func (p Policy) Action(c Category) Action {
	if c == Other {
		return Mask
	}
	if a, ok := p[c]; ok && a >= Mask && a <= Block {
		return a
	}
	if a, ok := DefaultPolicy()[c]; ok {
		return a
	}
	return Mask
}

// Merge returns p with the given rules applied; unknown categories and actions are dropped.
func (p Policy) Merge(rules map[Category]Action) Policy {
	out := Policy{}
	for k, v := range p {
		out[k] = v
	}
	for c, a := range rules {
		if _, ok := categoryNames[c]; ok && c != Other && a >= Mask && a <= Block {
			out[c] = a
		}
	}
	return out
}

// classCategory maps the detector's classes onto OG Core's categories.
func classCategory(c pii.Class) Category {
	switch c {
	case pii.ClassPerson:
		return Name
	case pii.ClassPhone:
		return Phone
	case pii.ClassEmail:
		return Email
	case pii.ClassAddress:
		return Address
	case pii.ClassAccountNumber:
		return Payment
	case pii.ClassSecret:
		return Credential
	default:
		return Other
	}
}
