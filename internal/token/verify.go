package token

import (
	"crypto/hmac"
	"encoding/binary"
	"strings"
	"time"
)

// Verify validates a token and returns its claims, or one of the package's
// sentinel errors. Expiry is stateless (the token carries expiresAt = mintedAt +
// ttl); there is no roll-forward in v0.1. The token's pid must match the
// Minter's pid (ErrWrongProcess otherwise).
func (m *Minter) Verify(tok string) (Claims, error) {
	claims, err := m.verify(tok)
	if err != nil {
		return Claims{}, err
	}
	if claims.PID != m.pid {
		return Claims{}, ErrWrongProcess
	}
	return claims, nil
}

// VerifySignature validates the signature and expiry of a token but treats the
// embedded pid as informational, returning it in the claims without requiring a
// match. Use this when the verifier cannot observe the caller's pid (for
// example across a loopback network hop to a child process).
func (m *Minter) VerifySignature(tok string) (Claims, error) {
	return m.verify(tok)
}

func (m *Minter) verify(tok string) (Claims, error) {
	rest, ok := strings.CutPrefix(tok, prefix)
	if !ok {
		return Claims{}, ErrMalformed
	}

	body, err := b32.DecodeString(rest)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	if len(body) != payloadLen+tagLen {
		return Claims{}, ErrMalformed
	}

	payload := body[:payloadLen]
	tag := body[payloadLen:]

	if !hmac.Equal(tag, m.sign(payload)) {
		return Claims{}, ErrBadSignature
	}

	pid := int32(binary.BigEndian.Uint32(payload[0:4]))         //nolint:gosec
	mintedAt := int64(binary.BigEndian.Uint64(payload[4:12]))   //nolint:gosec
	expiresAt := int64(binary.BigEndian.Uint64(payload[12:20])) //nolint:gosec

	if !m.clock.Now().Before(time.Unix(expiresAt, 0)) {
		return Claims{}, ErrExpired
	}

	return Claims{
		PID:       pid,
		MintedAt:  time.Unix(mintedAt, 0),
		ExpiresAt: time.Unix(expiresAt, 0),
	}, nil
}
