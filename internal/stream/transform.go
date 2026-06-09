package stream

import (
	"bytes"
	"io"

	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
)

const dataPrefix = "data: "

type Transformer struct {
	dst     io.Writer
	flush   func()
	codec   provider.DeltaCodec
	mapping pii.Mapping

	rawBuf       []byte
	content      string
	sent         int
	lastReencode func(string) []byte
}

type Option func(*Transformer)

func WithFlush(flush func()) Option {
	return func(t *Transformer) { t.flush = flush }
}

func New(dst io.Writer, codec provider.DeltaCodec, m pii.Mapping, opts ...Option) *Transformer {
	t := &Transformer{dst: dst, codec: codec, mapping: m}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

func (t *Transformer) Write(p []byte) (int, error) {
	t.rawBuf = append(t.rawBuf, p...)
	for {
		nl := bytes.IndexByte(t.rawBuf, '\n')
		if nl < 0 {
			break
		}
		line := append([]byte(nil), t.rawBuf[:nl]...)
		t.rawBuf = append([]byte(nil), t.rawBuf[nl+1:]...)
		if err := t.line(line); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (t *Transformer) Close() error {
	if len(t.rawBuf) > 0 {
		line := t.rawBuf
		t.rawBuf = nil
		if err := t.line(line); err != nil {
			return err
		}
	}
	return t.resetBlock()
}

func (t *Transformer) line(line []byte) error {
	if !bytes.HasPrefix(line, []byte(dataPrefix)) {
		return t.emit(append(line, '\n'))
	}
	payload := line[len(dataPrefix):]
	ev, ok := t.codec.Event(payload)
	if !ok {
		return t.emitData(payload)
	}
	switch ev.Kind {
	case provider.EvDelta:
		return t.delta(ev)
	case provider.EvBlockStop, provider.EvDone:
		if err := t.resetBlock(); err != nil {
			return err
		}
		return t.emitData(payload)
	default:
		return t.emitData(payload)
	}
}

// emitData passes a non-delta data payload through, restoring placeholders in
// it. Terminal events (e.g. output_text.done, output_item.done) carry the full
// message the agent reads as the final answer, so they need restoring too.
func (t *Transformer) emitData(payload []byte) error {
	restored := t.mapping.Restore(string(payload))
	return t.emit([]byte(dataPrefix + restored + "\n"))
}

func (t *Transformer) delta(ev provider.Event) error {
	t.content += ev.Text
	t.lastReencode = ev.Reencode
	restored := t.mapping.Restore(t.content)
	keep := t.mapping.PartialSuffixLen(restored)
	safe := len(restored) - keep
	if safe > t.sent {
		chunk := restored[t.sent:safe]
		t.sent = safe
		return t.emitReencoded(ev.Reencode, chunk)
	}
	return t.emitReencoded(ev.Reencode, "")
}

func (t *Transformer) resetBlock() error {
	restored := t.mapping.Restore(t.content)
	if len(restored) > t.sent && t.lastReencode != nil {
		chunk := restored[t.sent:]
		if err := t.emitReencoded(t.lastReencode, chunk); err != nil {
			return err
		}
	}
	t.content = ""
	t.sent = 0
	t.lastReencode = nil
	return nil
}

func (t *Transformer) emitReencoded(reencode func(string) []byte, text string) error {
	out := reencode(text)
	return t.emit([]byte(dataPrefix + string(out) + "\n"))
}

func (t *Transformer) emit(b []byte) error {
	if _, err := t.dst.Write(b); err != nil {
		return err
	}
	if t.flush != nil {
		t.flush()
	}
	return nil
}
