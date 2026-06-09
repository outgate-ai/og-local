package pii

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type Mapping []Pair

type Redactor struct {
	nonce []byte
}

func NewRedactor() (*Redactor, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		//coverage:ignore reason=crypto/rand.Read does not fail on supported platforms.
		return nil, err
	}
	return newRedactor(n), nil
}

func newRedactor(nonce []byte) *Redactor {
	return &Redactor{nonce: nonce}
}

func (r *Redactor) placeholder(class Class, value string) string {
	h := sha256.New()
	h.Write(r.nonce)
	h.Write([]byte(value))
	sum := hex.EncodeToString(h.Sum(nil))
	return "OG_" + strings.ToUpper(string(class)) + "_" + sum[:6]
}

func (r *Redactor) Apply(text string, spans []Span) (string, Mapping) {
	seen := make(map[string]string)
	var m Mapping
	for _, s := range spans {
		if s.Start < 0 || s.End > len(text) || s.Start >= s.End {
			continue
		}
		value := text[s.Start:s.End]
		if _, ok := seen[value]; ok {
			continue
		}
		token := r.placeholder(s.Class, value)
		seen[value] = token
		m = append(m, Pair{From: value, To: token})
	}
	redacted, _ := substitute(text, m)
	return redacted, m
}

func (m Mapping) Restore(text string) string {
	inverse := make([]Pair, len(m))
	for i, p := range m {
		inverse[i] = Pair{From: p.To, To: p.From}
	}
	out, _ := substitute(text, inverse)
	return out
}
