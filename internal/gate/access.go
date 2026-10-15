package gate

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
)

const (
	// accessCertsPath is where a Cloudflare Access team publishes its signing keys (JWKS).
	accessCertsPath = "/cdn-cgi/access/certs"
	accessCertsTTL  = time.Hour
	// accessCertsRetry: the certs are fetched again for an unknown kid (or after a failure) at most this often.
	accessCertsRetry   = time.Minute
	accessCertsTimeout = 10 * time.Second
	accessCertsMax     = 256 << 10
	accessKeysMax      = 32
	// accessSkew is the clock skew allowed on exp, nbf and iat.
	accessSkew = time.Minute
)

// accessError says why an Access JWT was refused; it never holds a claim's value.
type accessError string

func (e accessError) Error() string { return string(e) }

const (
	errAccessMissing   accessError = "missing"
	errAccessMalformed accessError = "malformed"
	errAccessAlg       accessError = "alg"
	errAccessKid       accessError = "kid"
	errAccessSignature accessError = "signature"
	errAccessIss       accessError = "iss"
	errAccessAud       accessError = "aud"
	errAccessExpired   accessError = "expired"
	errAccessNotYet    accessError = "not_yet_valid"
)

// accessClaims are the claims the tunnel front reads from a verified Access JWT.
type accessClaims struct {
	Aud        json.RawMessage `json:"aud"`
	Iss        string          `json:"iss"`
	Exp        *float64        `json:"exp"`
	Nbf        *float64        `json:"nbf"`
	Iat        *float64        `json:"iat"`
	Email      string          `json:"email"`
	CommonName string          `json:"common_name"`
}

// verifyAccessJWT checks a Cloudflare Access JWT: RS256 only, signed by the team's key kid,
// issued by the team for the audience tag aud, and valid now (with accessSkew).
func verifyAccessJWT(token string, now time.Time, team, aud string, key func(kid string) (*rsa.PublicKey, error)) (*accessClaims, error) {
	if token == "" {
		return nil, errAccessMissing
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errAccessMalformed
	}
	var hdr struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
	}
	if b, err := b64url(parts[0]); err != nil || json.Unmarshal(b, &hdr) != nil {
		return nil, errAccessMalformed
	}
	if hdr.Alg != "RS256" || hdr.Crit != nil {
		return nil, errAccessAlg
	}
	sig, err := b64url(parts[2])
	if err != nil || hdr.Kid == "" {
		return nil, errAccessMalformed
	}
	pub, err := key(hdr.Kid)
	if err != nil {
		return nil, errAccessKid
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) != nil {
		return nil, errAccessSignature
	}
	var c accessClaims
	if b, err := b64url(parts[1]); err != nil || json.Unmarshal(b, &c) != nil {
		return nil, errAccessMalformed
	}
	if c.Iss != "https://"+team {
		return nil, errAccessIss
	}
	if !audContains(c.Aud, aud) {
		return nil, errAccessAud
	}
	sec := float64(now.Unix())
	skew := accessSkew.Seconds()
	if c.Exp == nil || *c.Exp <= sec-skew {
		return nil, errAccessExpired
	}
	if (c.Nbf != nil && *c.Nbf > sec+skew) || (c.Iat != nil && *c.Iat > sec+skew) {
		return nil, errAccessNotYet
	}
	return &c, nil
}

func audContains(raw json.RawMessage, aud string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == aud
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, a := range many {
		if a == aud {
			return true
		}
	}
	return false
}

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// accessCerts caches one team's RSA signing keys by kid.
type accessCerts struct {
	mu      sync.Mutex
	team    string
	keys    map[string]*rsa.PublicKey
	fetched time.Time
	tried   time.Time
}

// key returns the team's key kid. The certs are fetched when the cache is an hour old or
// doesn't know kid, at most once a minute; when a fetch fails the keys already known are kept.
func (t *tunnelFront) key(ctx context.Context, team, kid string) (*rsa.PublicKey, error) {
	c := &t.certs
	c.mu.Lock()
	defer c.mu.Unlock()
	now := t.now()
	if c.team != team {
		c.team, c.keys, c.fetched, c.tried = team, nil, time.Time{}, time.Time{}
	}
	k, ok := c.keys[kid]
	if ok && !c.fetched.IsZero() && now.Sub(c.fetched) < accessCertsTTL {
		return k, nil
	}
	if c.tried.IsZero() || now.Sub(c.tried) >= accessCertsRetry || now.Before(c.tried) {
		c.tried = now
		if keys, err := t.fetchCerts(ctx, team); err == nil {
			c.keys, c.fetched = keys, now
		} else {
			t.s.log.Warn("access certs", "team", team, "err", err)
		}
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, errAccessKid
}

// fetchCerts gets https://<team>/cdn-cgi/access/certs with the gate's own client (no
// redirects) and records the fetch in the ledger.
func (t *tunnelFront) fetchCerts(ctx context.Context, team string) (map[string]*rsa.PublicKey, error) {
	s := t.s
	start := time.Now()
	row := ledger.Row{
		ID: s.nextID(), Time: start.UTC(), Caller: "gate", UID: uint32(os.Getuid()), //nolint:gosec // uids fit uint32
		Destination: team, Class: "access-certs", Method: http.MethodGet, PathClass: accessCertsPath,
		Kind: "other", Mode: string(s.cfg.Mode), Mask: MaskNotRequired,
	}
	defer func() {
		row.DurationMs = time.Since(start).Milliseconds()
		s.ledger.Record(&row)
	}()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), accessCertsTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+team+accessCertsPath, nil)
	if err != nil {
		row.Error = "request"
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		row.Error = errClass(err)
		return nil, errors.New(row.Error)
	}
	defer func() { _ = resp.Body.Close() }()
	row.Status = resp.StatusCode
	b, err := io.ReadAll(io.LimitReader(resp.Body, accessCertsMax+1))
	row.BytesIn = int64(len(b))
	switch {
	case err != nil:
		row.Error = errClass(err)
	case resp.StatusCode != http.StatusOK:
		row.Error = "status"
	case len(b) > accessCertsMax:
		row.Error = "too_large"
	}
	if row.Error != "" {
		return nil, errors.New(row.Error)
	}
	keys, err := parseAccessCerts(b)
	if err != nil {
		row.Error = "bad_certs"
		return nil, err
	}
	return keys, nil
}

// parseAccessCerts reads a JWKS's RSA signing keys of at least 2048 bits; other keys are ignored.
func parseAccessCerts(b []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, errors.New("certs: not a JWKS")
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err1 := b64url(strings.TrimRight(k.N, "="))
		e, err2 := b64url(strings.TrimRight(k.E, "="))
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 || pub.E < 3 || pub.E%2 == 0 {
			continue
		}
		keys[k.Kid] = pub
		if len(keys) == accessKeysMax {
			break
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("certs: no RSA signing keys")
	}
	return keys, nil
}
