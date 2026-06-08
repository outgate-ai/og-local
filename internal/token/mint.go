package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	prefix     = "ogl_live_"
	maxTTL     = 30 * 24 * time.Hour
	payloadLen = 4 + 8 + 8 // pid, minted, expires
	tagLen     = sha256.Size
)

var (
	ErrMalformed    = errors.New("token: malformed")
	ErrBadSignature = errors.New("token: bad signature")
	ErrExpired      = errors.New("token: expired")
	ErrWrongProcess = errors.New("token: wrong process")
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type Clock interface {
	Now() time.Time
}

// Minter mints and verifies tokens bound to a single process. The per-process
// secret never leaves the struct, so a token from one Minter fails verification
// in any other.
type Minter struct {
	secret [32]byte
	pid    int32
	clock  Clock
	ttl    time.Duration
}

type Claims struct {
	PID       int32
	MintedAt  time.Time
	ExpiresAt time.Time
}

// NewMinter binds the Minter to pid and clamps ttl to a 30-day ceiling. pid is
// injected rather than read via os.Getpid so the package imports nothing that
// can touch the filesystem (asserted by TestNoFilesystemImports).
func NewMinter(pid int32, clock Clock, ttl time.Duration) (*Minter, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("token: ttl must be positive, got %v", ttl)
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	m := &Minter{pid: pid, clock: clock, ttl: ttl}
	if _, err := rand.Read(m.secret[:]); err != nil {
		//coverage:ignore reason=crypto/rand.Read does not fail on supported platforms.
		return nil, fmt.Errorf("token: read random secret: %w", err)
	}
	return m, nil
}

func (m *Minter) Mint() string {
	now := m.clock.Now()

	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint32(payload[0:4], uint32(m.pid))                   //nolint:gosec
	binary.BigEndian.PutUint64(payload[4:12], uint64(now.Unix()))             //nolint:gosec
	binary.BigEndian.PutUint64(payload[12:20], uint64(now.Add(m.ttl).Unix())) //nolint:gosec

	body := make([]byte, 0, payloadLen+tagLen)
	body = append(body, payload...)
	body = append(body, m.sign(payload)...)
	return prefix + b32.EncodeToString(body)
}

func (m *Minter) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, m.secret[:])
	mac.Write(payload)
	return mac.Sum(nil)
}
