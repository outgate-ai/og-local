// Package sealtest stands in for og-gate-link's keystore2 key in tests: AES-256-GCM under a key the
// test holds, with og-gate-link's limit on what it seals.
package sealtest

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
)

// MaxPlain is og-gate-link's limit on one seal (link/src/kek.rs).
const MaxPlain = 1024

// Sealer seals with a key of its own. Down makes every call fail, as a stopped helper or a
// refusing keystore does.
type Sealer struct {
	key  []byte
	Down atomic.Bool
	// Seals counts the seal calls.
	Seals atomic.Int64
}

func New(t testing.TB) *Sealer {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return &Sealer{key: k}
}

func (f *Sealer) gcm() cipher.AEAD {
	b, _ := aes.NewCipher(f.key)
	g, _ := cipher.NewGCM(b)
	return g
}

func (f *Sealer) Seal(_ context.Context, plain, aad []byte) ([]byte, error) {
	if f.Down.Load() {
		return nil, errors.New("keystore down")
	}
	if len(plain) > MaxPlain {
		return nil, errors.New("plaintext too large")
	}
	f.Seals.Add(1)
	g := f.gcm()
	nonce := make([]byte, g.NonceSize())
	_, _ = rand.Read(nonce)
	return g.Seal(nonce, nonce, plain, aad), nil
}

func (f *Sealer) Open(_ context.Context, sealed, aad []byte) ([]byte, error) {
	if f.Down.Load() {
		return nil, errors.New("keystore down")
	}
	g := f.gcm()
	if len(sealed) < g.NonceSize() {
		return nil, errors.New("short")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}
