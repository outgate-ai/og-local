package mask

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrLocked means the credential-encrypted storage holding the map isn't
// available yet (before the first unlock): content can't be masked or restored.
var ErrLocked = errors.New("storage_locked")

// Store is the placeholder map: placeholder → value, kept in credential-encrypted
// storage (decision #17: CE, 30 days, a plain file in Phase 1; Keystore in M12).
// It is an append-only JSONL log, compacted when it opens and once a day.
type Store struct {
	dir       string
	retention time.Duration
	maxItems  int
	now       func() time.Time

	mu      sync.Mutex
	open    bool
	key     []byte
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

func NewStore(dir string, retention time.Duration, maxItems int) *Store {
	return &Store{dir: dir, retention: retention, maxItems: maxItems, now: time.Now}
}

// ensure opens the map once its directory exists (init creates it when CE storage
// unlocks).
func (s *Store) ensure() error {
	if s.open {
		return nil
	}
	if fi, err := os.Stat(s.dir); err != nil || !fi.IsDir() {
		return ErrLocked
	}
	key, err := s.loadKey()
	if err != nil {
		return err
	}
	s.key = key
	s.byPH, s.byValue = map[string]*entry{}, map[valueKey]string{}
	if err := s.load(); err != nil {
		return err
	}
	if err := s.compact(); err != nil {
		return err
	}
	s.open = true
	return nil
}

func (s *Store) loadKey() ([]byte, error) {
	path := filepath.Join(s.dir, "key")
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Store) load() error {
	f, err := os.Open(filepath.Join(s.dir, "map.jsonl"))
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
		var e entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.P == "" {
			continue
		}
		s.put(&e)
	}
	return nil
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
// first) and rewrites the log.
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
	path := filepath.Join(s.dir, "map.jsonl")
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, e := range keep {
		s.put(e)
		b, _ := json.Marshal(e)
		_, _ = w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	_ = f.Close()
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if s.log != nil {
		_ = s.w.Flush()
		_ = s.log.Close()
	}
	s.log, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s.w = bufio.NewWriter(s.log)
	s.lastGC = s.now()
	return nil
}

func (s *Store) appendEntry(e *entry) error {
	b, _ := json.Marshal(e)
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
