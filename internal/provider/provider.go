package provider

import "encoding/json"

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		//coverage:ignore reason=marshaling values decoded from valid JSON cannot fail.
		panic(err)
	}
	return b
}

type Kind int

const (
	Passthrough Kind = iota
	Anthropic
	OpenAIChat
	OpenAIResponses
)

type StreamFormat int

const (
	StreamNone StreamFormat = iota
	StreamSSE
)

type FieldRef struct {
	Text string
	set  func(redacted string)
}

func (f FieldRef) Set(redacted string) { f.set(redacted) }

type extractFn func(body []byte) ([]FieldRef, func() ([]byte, error), error)

type Endpoint struct {
	Kind    Kind
	Stream  StreamFormat
	extract extractFn
	delta   DeltaCodec
}

func (e Endpoint) Redactable() bool { return e.extract != nil }

func (e Endpoint) DeltaCodec() DeltaCodec { return e.delta }

type DeltaCodec interface {
	Event(payload []byte) (Event, bool)
}

type EventKind int

const (
	EvOther EventKind = iota
	EvDelta
	EvBlockStop
	EvDone
)

type Event struct {
	Text     string
	Kind     EventKind
	Reencode func(text string) []byte
}

func (e Endpoint) Fields(body []byte) (refs []FieldRef, reassemble func() ([]byte, error), err error) {
	if e.extract == nil {
		return nil, func() ([]byte, error) { return body, nil }, nil
	}
	return e.extract(body)
}
