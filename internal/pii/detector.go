package pii

import "context"

type Class string

const (
	ClassAccountNumber Class = "account_number"
	ClassAddress       Class = "private_address"
	ClassDate          Class = "private_date"
	ClassEmail         Class = "private_email"
	ClassPerson        Class = "private_person"
	ClassPhone         Class = "private_phone"
	ClassURL           Class = "private_url"
	ClassSecret        Class = "secret"
)

type Span struct {
	Start int
	End   int
	Class Class
	Score float32
}

type Detector interface {
	Detect(ctx context.Context, text string) ([]Span, error)
}
