package mask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// HexLen is the placeholder's hash length: decision #16 asks for at least 12, and
// the region's own-token pattern accepts 6 to 24.
const HexLen = 16

// placeholderRE matches every placeholder this gate can mint (any length it may
// extend to on a collision); restore only replaces those found in the map.
var placeholderRE = regexp.MustCompile(`OG_(?:CREDENTIAL|PII|SENSITIVE)_[0-9a-f]{12,24}`)

// mint returns the placeholder for value in category c, n hex long:
// OG_<label>_<HMAC-SHA256(key, category ":" value)[:n]>. Stable for a device, so
// re-sent history stays byte-identical and provider prompt caches keep hitting.
func mint(key []byte, c Category, value string, n int) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(c.Label()))
	m.Write([]byte{':'})
	m.Write([]byte(value))
	sum := hex.EncodeToString(m.Sum(nil))
	if n > len(sum) {
		n = len(sum)
	}
	return "OG_" + c.Label() + "_" + sum[:n]
}

// Placeholders lists the placeholders in text.
func Placeholders(text string) []string {
	return placeholderRE.FindAllString(text, -1)
}
