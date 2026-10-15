package mask

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// ErrLocked means the credential-encrypted storage holding the map isn't
// available yet (before the first unlock): content can't be masked or restored.
var ErrLocked = errors.New("storage_locked")

// ErrKeystore means the key that seals the map's own keys can't be used (no
// Sealer, og-gate-link down, keystore2 refusing). The map then stays closed:
// content can't be masked or restored, and nothing is read or written in the
// clear (og-os M12).
var ErrKeystore = errors.New("keystore_unavailable")

// Sealer seals the map's own 32-byte keys with a key-encryption key that never
// leaves the phone's keystore (og-gate-link's keystore2 key, og-os M12).
type Sealer interface {
	Seal(ctx context.Context, plain, aad []byte) ([]byte, error)
	Open(ctx context.Context, sealed, aad []byte) ([]byte, error)
}

const (
	keysFile      = "keys.json"
	mapFile       = "map.v2.jsonl"
	legacyKeyFile = "key"       // Phase 1: the plain placeholder HMAC key
	legacyMapFile = "map.jsonl" // Phase 1: the plain map
	sealTimeout   = 5 * time.Second
)

// Store is the placeholder map: placeholder → value, kept in credential-encrypted
// storage for 30 days (decision #17). Since og-os M12 nothing in it is plain:
//   - keys.json holds the placeholder HMAC key and one AES-256 key per day, each
//     sealed by the Sealer (keystore2);
//   - map.v2.jsonl is an append-only log of records whose value is AES-256-GCM
//     under the key of the record's last-seen day, compacted when it opens and
//     once a day; a day key goes when no kept record uses it (crypto-erase).
//
// A Phase-1 plain map is moved in once (migrate) and deleted. Without a working
// Sealer the store doesn't open (ErrKeystore): masking fails closed.
type Store struct {
	dir       string
	retention time.Duration
	maxItems  int
	now       func() time.Time
	// Sealer is set by the gate before the first request (serve.go: og-gate-link).
	Sealer Sealer

	mu      sync.Mutex
	open    bool
	key     []byte
	kf      keyFile
	days    map[int64][]byte
	byPH    map[string]*entry
	byValue map[valueKey]string
	log     *os.File
	w       *bufio.Writer
	lastGC  time.Time
}

type valueKey struct {
	label string
	value string
}

type entry struct {
	P string   `json:"p"`
	C Category `json:"c"`
	V string   `json:"v"`
	F int64    `json:"f"`
	L int64    `json:"l"`
}

// record is an entry on disk: V sealed under day D's key (hex nonce || ciphertext).
type record struct {
	P string   `json:"p"`
	C Category `json:"c"`
	D int64    `json:"d"`
	X string   `json:"x"`
	F int64    `json:"f"`
	L int64    `json:"l"`
}

// keyFile holds the sealed keys (hex). Days are keyed by Unix day number.
type keyFile struct {
	V    int               `json:"v"`
	HMAC string            `json:"hmac"`
	Days map[string]string `json:"days"`
}

var errNoDayKey = errors.New("mask: no key for that day")

func NewStore(dir string, retention time.Duration, maxItems int) *Store {
	return &Store{dir: dir, retention: retention, maxItems: maxItems, now: time.Now}
}

// ensure opens the map once its directory exists (init creates it when CE storage
// unlocks) and the Sealer works.
func (s *Store) ensure() error {
	if s.open {
		return nil
	}
	if fi, err := os.Stat(s.dir); err != nil || !fi.IsDir() {
		return ErrLocked
	}
	if s.Sealer == nil {
		return ErrKeystore
	}
	s.days = map[int64][]byte{}
	s.byPH, s.byValue = map[string]*entry{}, map[valueKey]string{}
	if err := s.loadKeys(); err != nil {
		return err
	}
	if err := s.migrate(); err != nil {
		return err
	}
	if err := s.load(); err != nil {
		return err
	}
	if err := s.compact(); err != nil {
		return err
	}
	s.open = true
	return nil
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

func keystoreErr(err error) error { return fmt.Errorf("%w (%v)", ErrKeystore, err) }

func (s *Store) seal(plain []byte, aad string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sealTimeout)
	defer cancel()
	b, err := s.Sealer.Seal(ctx, plain, []byte(aad))
	if err != nil {
		return nil, keystoreErr(err)
	}
	return b, nil
}

func (s *Store) unseal(sealed []byte, aad string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sealTimeout)
	defer cancel()
	b, err := s.Sealer.Open(ctx, sealed, []byte(aad))
	if err != nil {
		return nil, keystoreErr(err)
	}
	return b, nil
}

const aadHMAC = "og-gate-map:hmac"

func aadDay(d int64) string { return "og-gate-map:day:" + strconv.FormatInt(d, 10) }

func aadRecord(p string, c Category, d int64) []byte {
	return []byte(fmt.Sprintf("og-gate-map:rec:%s:%d:%d", p, c, d))
}

// loadKeys opens keys.json, or creates it: with the Phase-1 HMAC key when there is
// one, so the placeholders already handed out keep their values.
func (s *Store) loadKeys() error {
	b, err := os.ReadFile(s.path(keysFile))
	if errors.Is(err, os.ErrNotExist) {
		hmac, err := os.ReadFile(s.path(legacyKeyFile))
		if err != nil || len(hmac) != 32 {
			hmac = make([]byte, 32)
			if _, err := rand.Read(hmac); err != nil {
				return err
			}
		}
		sealed, err := s.seal(hmac, aadHMAC)
		if err != nil {
			return err
		}
		s.kf = keyFile{V: 1, HMAC: hex.EncodeToString(sealed), Days: map[string]string{}}
		if err := s.saveKeys(); err != nil {
			return err
		}
		s.key = hmac
		return nil
	}
	if err != nil {
		return err
	}
	var kf keyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		// Never replaced by a fresh file: that would orphan the map. Closed until repaired.
		return fmt.Errorf("mask: %s unreadable: %w", keysFile, err)
	}
	if kf.Days == nil {
		kf.Days = map[string]string{}
	}
	sealed, err := hex.DecodeString(kf.HMAC)
	if err != nil {
		return fmt.Errorf("mask: %s: hmac: %w", keysFile, err)
	}
	hmac, err := s.unseal(sealed, aadHMAC)
	if err != nil {
		return err
	}
	if len(hmac) != 32 {
		return fmt.Errorf("mask: %s: hmac key of %d bytes", keysFile, len(hmac))
	}
	s.kf, s.key = kf, hmac
	return nil
}

// saveKeys writes keys.json through a temp file and a rename, then syncs the directory.
func (s *Store) saveKeys() error {
	b, _ := json.Marshal(&s.kf)
	return writeAtomic(s.dir, keysFile, b)
}

func writeAtomic(dir, name string, b []byte) error {
	tmp := filepath.Join(dir, name+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// dayKey returns day d's key, unsealing it on first use; with create, a missing one
// is made and persisted (sealed) before it is used.
func (s *Store) dayKey(d int64, create bool) ([]byte, error) {
	if k, ok := s.days[d]; ok {
		return k, nil
	}
	ds := strconv.FormatInt(d, 10)
	if w, ok := s.kf.Days[ds]; ok {
		sealed, err := hex.DecodeString(w)
		if err != nil {
			return nil, errNoDayKey
		}
		k, err := s.unseal(sealed, aadDay(d))
		if err != nil {
			return nil, err
		}
		s.days[d] = k
		return k, nil
	}
	if !create {
		return nil, errNoDayKey
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	sealed, err := s.seal(k, aadDay(d))
	if err != nil {
		return nil, err
	}
	s.kf.Days[ds] = hex.EncodeToString(sealed)
	if err := s.saveKeys(); err != nil {
		delete(s.kf.Days, ds)
		return nil, err
	}
	s.days[d] = k
	return k, nil
}

func gcm(k []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// sealEntry is e as a record under the key of its last-seen day.
func (s *Store) sealEntry(e *entry) (*record, error) {
	d := e.L / 86400
	k, err := s.dayKey(d, true)
	if err != nil {
		return nil, err
	}
	g, err := gcm(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	x := g.Seal(nonce, nonce, []byte(e.V), aadRecord(e.P, e.C, d))
	return &record{P: e.P, C: e.C, D: d, X: hex.EncodeToString(x), F: e.F, L: e.L}, nil
}

// openRecord is r's entry; errNoDayKey when its day key is gone (expired) or the
// record doesn't decrypt.
func (s *Store) openRecord(r *record) (*entry, error) {
	k, err := s.dayKey(r.D, false)
	if err != nil {
		return nil, err
	}
	g, err := gcm(k)
	if err != nil {
		return nil, err
	}
	x, err := hex.DecodeString(r.X)
	if err != nil || len(x) < g.NonceSize() {
		return nil, errNoDayKey
	}
	v, err := g.Open(nil, x[:g.NonceSize()], x[g.NonceSize():], aadRecord(r.P, r.C, r.D))
	if err != nil {
		return nil, errNoDayKey
	}
	return &entry{P: r.P, C: r.C, V: string(v), F: r.F, L: r.L}, nil
}

// migrate moves a Phase-1 plain map into the sealed one, once (og-os M12). Crash-safe:
// keys.json exists first (loadKeys, with the Phase-1 HMAC key), then map.v2.jsonl
// appears whole through a temp file and a rename, then the plain files go. A start
// interrupted anywhere redoes what's missing; once map.v2.jsonl exists the plain map
// is only deleted, never read. Without a working Sealer this never runs and the plain
// files stay as they were.
func (s *Store) migrate() error {
	legacy := s.path(legacyMapFile)
	if _, err := os.Stat(legacy); err == nil {
		if _, err := os.Stat(s.path(mapFile)); errors.Is(err, os.ErrNotExist) {
			if err := s.convertLegacy(legacy); err != nil {
				return err
			}
		}
	}
	removed := false
	for _, n := range []string{legacyMapFile, legacyMapFile + ".tmp", legacyKeyFile, legacyKeyFile + ".tmp"} {
		if os.Remove(s.path(n)) == nil {
			removed = true
		}
	}
	if removed {
		return syncDir(s.dir)
	}
	return nil
}

func (s *Store) convertLegacy(legacy string) error {
	f, err := os.Open(legacy)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var out []byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.P == "" {
			continue
		}
		r, err := s.sealEntry(&e)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(r)
		out = append(append(out, b...), '\n')
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return writeAtomic(s.dir, mapFile, out)
}

func (s *Store) load() error {
	f, err := os.Open(s.path(mapFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var r record
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.P == "" {
			continue
		}
		e, err := s.openRecord(&r)
		if errors.Is(err, errNoDayKey) {
			continue
		}
		if err != nil {
			// The Sealer failed: closed, and nothing is compacted away.
			return err
		}
		s.put(e)
	}
	return sc.Err()
}

func (s *Store) put(e *entry) {
	if old, ok := s.byPH[e.P]; ok {
		if e.L > old.L {
			old.L = e.L
		}
		return
	}
	s.byPH[e.P] = e
	s.byValue[valueKey{e.C.Label(), e.V}] = e.P
}

// compact drops entries older than the retention (or beyond the size cap, oldest
// first), rewrites the log, then forgets the day keys no kept record uses (today's
// stays).
func (s *Store) compact() error {
	cutoff := s.now().Add(-s.retention).Unix()
	keep := make([]*entry, 0, len(s.byPH))
	for _, e := range s.byPH {
		if e.L >= cutoff {
			keep = append(keep, e)
		}
	}
	if s.maxItems > 0 && len(keep) > s.maxItems {
		sortByLastSeen(keep)
		keep = keep[len(keep)-s.maxItems:]
	}
	s.byPH, s.byValue = map[string]*entry{}, map[valueKey]string{}
	used := map[int64]bool{s.now().Unix() / 86400: true}
	var out []byte
	for _, e := range keep {
		r, err := s.sealEntry(e)
		if err != nil {
			return err
		}
		used[r.D] = true
		s.put(e)
		b, _ := json.Marshal(r)
		out = append(append(out, b...), '\n')
	}
	if s.log != nil {
		_ = s.w.Flush()
		_ = s.log.Close()
		s.log = nil
	}
	if err := writeAtomic(s.dir, mapFile, out); err != nil {
		return err
	}
	var err error
	s.log, err = os.OpenFile(s.path(mapFile), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s.w = bufio.NewWriter(s.log)
	s.lastGC = s.now()
	dropped := false
	for ds := range s.kf.Days {
		d, err := strconv.ParseInt(ds, 10, 64)
		if err != nil || !used[d] {
			delete(s.kf.Days, ds)
			delete(s.days, d)
			dropped = true
		}
	}
	if dropped {
		return s.saveKeys()
	}
	return nil
}

func (s *Store) appendEntry(e *entry) error {
	r, err := s.sealEntry(e)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(r)
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return s.w.Flush()
}

// Assign returns the placeholder for each value, minting and persisting new ones.
// Values are keyed by their region label, so a name and an address that happen to
// be the same string share one placeholder.
func (s *Store) Assign(items []Item) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		return nil, err
	}
	now := s.now()
	if now.Sub(s.lastGC) > 24*time.Hour {
		if err := s.compact(); err != nil {
			return nil, err
		}
	}
	day := now.Unix() / 86400
	out := make([]string, len(items))
	for i, it := range items {
		k := valueKey{it.Category.Label(), it.Value}
		if ph, ok := s.byValue[k]; ok {
			e := s.byPH[ph]
			if e.L/86400 != day {
				e.L = now.Unix()
				if err := s.appendEntry(e); err != nil {
					return nil, err
				}
			}
			out[i] = ph
			continue
		}
		ph := ""
		for n := HexLen; n <= 24; n += 4 {
			cand := mint(s.key, it.Category, it.Value, n)
			if e, taken := s.byPH[cand]; !taken || e.V == it.Value {
				ph = cand
				break
			}
		}
		if ph == "" {
			return nil, fmt.Errorf("mask: placeholder collision")
		}
		e := &entry{P: ph, C: it.Category, V: it.Value, F: now.Unix(), L: now.Unix()}
		s.put(e)
		if err := s.appendEntry(e); err != nil {
			return nil, err
		}
		out[i] = ph
	}
	if err := s.log.Sync(); err != nil {
		return nil, err
	}
	return out, nil
}

// Lookup returns the value and category behind a placeholder.
func (s *Store) Lookup(ph string) (string, Category, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ensure() != nil {
		return "", 0, false
	}
	e, ok := s.byPH[ph]
	if !ok || e.L < s.now().Add(-s.retention).Unix() {
		return "", 0, false
	}
	return e.V, e.C, true
}

// Ready reports whether the map is usable now.
func (s *Store) Ready() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ensure()
}

// Len is the number of placeholders kept.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byPH)
}

// Item is one value to assign a placeholder to.
type Item struct {
	Category Category
	Value    string
}
