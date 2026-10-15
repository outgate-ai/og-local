// Package appq keeps the phone's app tenancies (og-os M12c, Q6): participants of Outgate apps whose
// command queue drives lanes on the phone (og-agentd's appq transport). A tenancy is its .ogpkg
// package, which carries the participant's join token; the gate alone holds it, sealed in its
// credential-encrypted directory, and adds the token to the tenancy's requests.
//
// Files in the store's directory (<ce>/appq):
//
//	<name>.pkg   nonce || AES-256-GCM(package), AAD "appq:<name>", under a key of its own
//	<name>.key   that 32-byte key, sealed by the Sealer (og-gate-link's keystore2 key), AAD
//	             "og-gate-appq:key:<name>"
//	<name>.meta  what appq_list shows, no token: participant, app, thread, account, when added
//
// Each is written through a temp file, fsync and rename, in that order: a tenancy exists once its
// .meta does. Removal goes the other way, and without its key the package can't be opened
// (crypto-erase). Packages are opened on first use and kept in memory while in use.
package appq

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/corelink"
	"github.com/outgate-ai/og-local/internal/gate/route"
)

// Sealer seals the tenancies' own keys with a key-encryption key that never leaves the phone's
// keystore (og-gate-link, the same key as the masking map's).
type Sealer interface {
	Seal(ctx context.Context, plain, aad []byte) ([]byte, error)
	Open(ctx context.Context, sealed, aad []byte) ([]byte, error)
}

// Errors; the not-ready ones are the gate's refusal codes.
var (
	// ErrLocked: the gate's credential-encrypted directory isn't there (before the first unlock).
	ErrLocked = errors.New("storage_locked")
	// ErrLink: og-gate-link isn't running (or the gate has none), so no key can be sealed or opened.
	ErrLink = errors.New("link_unavailable")
	// ErrKeystore: og-gate-link runs but its keystore key refused.
	ErrKeystore = errors.New("keystore_unavailable")
	// ErrStorage: the store's directory or files can't be made or written.
	ErrStorage = errors.New("storage_unavailable")
	// ErrUnreadable: a tenancy's key opened but its package doesn't (damaged or moved files).
	ErrUnreadable = errors.New("tenancy_unreadable")
	// ErrBadName: not [A-Za-z0-9._-]{1,64}.
	ErrBadName = errors.New("bad tenancy name")
	// ErrNotFound is route.ErrUnknownRegion: appq:<name> is a region id that doesn't exist.
	ErrNotFound = fmt.Errorf("%w: no such app tenancy", route.ErrUnknownRegion)
)

// Tenancy states in appq_list.
const (
	StateActive = "active"
	// StateUnreadable: its package didn't open the last time it was used.
	StateUnreadable = "unreadable"
)

// Origins of a tenancy (its .meta, and the ledger row that added it).
const (
	OriginStore    = "store"    // a store rule kept it from global's response
	OriginImport   = "import"   // appq_import (adb, debuggable builds)
	OriginMigrated = "migrated" // a plain DE package of the bring-up
)

// Info is a tenancy as appq_list shows it. No token, no package.
type Info struct {
	Name        string    `json:"name"`
	Participant string    `json:"participant"`
	AccountID   string    `json:"account_id,omitempty"`
	AppID       string    `json:"app_id"`
	AppName     string    `json:"app_name,omitempty"`
	ThreadID    string    `json:"thread_id,omitempty"`
	State       string    `json:"state"`
	AddedAt     time.Time `json:"added_at"`
	// Host is the app endpoints' host (ledger rows).
	Host string `json:"-"`
}

type metaFile struct {
	V int `json:"v"`
	Info
	Host   string `json:"host"`
	Gen    string `json:"gen"`
	Origin string `json:"origin"`
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidName reports whether name may name a tenancy: [A-Za-z0-9._-]{1,64}, not "." or "..".
func ValidName(name string) bool {
	return nameRE.MatchString(name) && name != "." && name != ".."
}

// idle is how long an opened package stays in memory without a request.
const idle = 10 * time.Minute

const sealTimeout = 5 * time.Second

// Store is the sealed tenancy store. Safe for concurrent use.
type Store struct {
	dir    string
	sealer Sealer
	now    func() time.Time

	mu     sync.Mutex
	open   map[string]*opened
	broken map[string]bool
}

type opened struct {
	t    route.Tenancy
	used time.Time
}

// New returns the store in dir (<ce>/appq; "" for none: never ready). Its parent is the gate's
// credential-encrypted directory, which init makes when CE storage unlocks; dir itself is made on
// first use. sealer may be nil (no og-gate-link): nothing can then be added or opened.
func New(dir string, sealer Sealer) *Store {
	return &Store{dir: dir, sealer: sealer, now: time.Now, open: map[string]*opened{}, broken: map[string]bool{}}
}

// ready checks the directory: its parent must exist (CE storage unlocked); dir is made if missing.
func (s *Store) ready() error {
	if s.dir == "" {
		return ErrLocked
	}
	if fi, err := os.Stat(filepath.Dir(s.dir)); err != nil || !fi.IsDir() {
		return ErrLocked
	}
	if err := os.Mkdir(s.dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: %v", ErrStorage, err)
	}
	return nil
}

// Ready reports whether tenancies can be listed, added and opened now (without asking the keystore).
func (s *Store) Ready() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return err
	}
	if s.sealer == nil {
		return ErrLink
	}
	return nil
}

func (s *Store) path(name, ext string) string { return filepath.Join(s.dir, name+ext) }

func aadPackage(name string) []byte { return []byte("appq:" + name) }

func aadKey(name string) []byte { return []byte("og-gate-appq:key:" + name) }

func keyErr(err error) error {
	if errors.Is(err, corelink.ErrLinkUnavailable) {
		return fmt.Errorf("%w: %v", ErrLink, err)
	}
	return fmt.Errorf("%w: %v", ErrKeystore, err)
}

func (s *Store) sealKey(key []byte, name string) ([]byte, error) {
	if s.sealer == nil {
		return nil, ErrLink
	}
	ctx, cancel := context.WithTimeout(context.Background(), sealTimeout)
	defer cancel()
	b, err := s.sealer.Seal(ctx, key, aadKey(name))
	if err != nil {
		return nil, keyErr(err)
	}
	return b, nil
}

func (s *Store) openKey(sealed []byte, name string) ([]byte, error) {
	if s.sealer == nil {
		return nil, ErrLink
	}
	ctx, cancel := context.WithTimeout(context.Background(), sealTimeout)
	defer cancel()
	b, err := s.sealer.Open(ctx, sealed, aadKey(name))
	if err != nil {
		return nil, keyErr(err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: a key of %d bytes", ErrUnreadable, len(b))
	}
	return b, nil
}

func sealPackage(key, plain, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, aad), nil
}

func openPackage(key, sealed, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, ErrUnreadable
	}
	b, err := g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
	if err != nil {
		return nil, ErrUnreadable
	}
	return b, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Add seals pkg (an .ogpkg package) as tenancy name, replacing one of that name. info gives what
// the package doesn't say (account, thread; the app name if the package has none). The key is sealed
// before anything on disk changes, so a keystore failure leaves an older tenancy as it was.
func (s *Store) Add(name string, pkg []byte, info Info, origin string) (Info, error) {
	if !ValidName(name) {
		return Info{}, ErrBadName
	}
	t, err := route.ParsePackage(pkg)
	if err != nil {
		return Info{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return Info{}, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return Info{}, err
	}
	wrapped, err := s.sealKey(key, name)
	if err != nil {
		return Info{}, err
	}
	sealed, err := sealPackage(key, pkg, aadPackage(name))
	if err != nil {
		return Info{}, err
	}
	gen, err := randomHex(8)
	if err != nil {
		return Info{}, err
	}
	info.Name, info.Participant, info.AppID, info.State = name, t.Participant, t.AppID, StateActive
	if info.AppName == "" {
		info.AppName = t.AppName
	}
	info.AddedAt = s.now().UTC().Truncate(time.Second)
	info.Host = hostOf(t.Hook)
	meta, err := json.Marshal(&metaFile{V: 1, Info: info, Host: info.Host, Gen: gen, Origin: origin})
	if err != nil {
		return Info{}, err
	}
	s.removeFiles(name)
	for _, f := range []struct {
		ext string
		b   []byte
	}{{".pkg", sealed}, {".key", wrapped}, {".meta", meta}} {
		if err := writeAtomic(s.dir, name+f.ext, f.b); err != nil {
			s.removeFiles(name)
			return Info{}, fmt.Errorf("%w: %v", ErrStorage, err)
		}
	}
	t.Name, t.Gen = name, gen
	s.open[name] = &opened{t: t, used: s.now()}
	delete(s.broken, name)
	return info, nil
}

// Get opens tenancy name for a request: its package, token included. It stays in memory while
// requests keep coming (an idle one is dropped after 10 minutes).
func (s *Store) Get(name string) (route.Tenancy, error) {
	if !ValidName(name) {
		return route.Tenancy{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweep(now)
	if o, ok := s.open[name]; ok {
		o.used = now
		return o.t, nil
	}
	if err := s.ready(); err != nil {
		return route.Tenancy{}, err
	}
	m, err := s.readMeta(name)
	if err != nil {
		return route.Tenancy{}, err
	}
	wrapped, err1 := os.ReadFile(s.path(name, ".key"))
	sealed, err2 := os.ReadFile(s.path(name, ".pkg"))
	if err1 != nil || err2 != nil {
		s.broken[name] = true
		return route.Tenancy{}, fmt.Errorf("%w: files missing", ErrUnreadable)
	}
	key, err := s.openKey(wrapped, name)
	if err != nil {
		if errors.Is(err, ErrUnreadable) {
			s.broken[name] = true
		}
		return route.Tenancy{}, err
	}
	pkg, err := openPackage(key, sealed, aadPackage(name))
	if err != nil {
		s.broken[name] = true
		return route.Tenancy{}, err
	}
	t, err := route.ParsePackage(pkg)
	if err != nil {
		s.broken[name] = true
		return route.Tenancy{}, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	t.Name, t.Gen = name, m.Gen
	s.open[name] = &opened{t: t, used: now}
	delete(s.broken, name)
	return t, nil
}

// sweep drops packages no request used for a while.
func (s *Store) sweep(now time.Time) {
	for n, o := range s.open {
		if now.Sub(o.used) > idle {
			delete(s.open, n)
		}
	}
}

func (s *Store) readMeta(name string) (*metaFile, error) {
	b, err := os.ReadFile(s.path(name, ".meta"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorage, err)
	}
	var m metaFile
	if err := json.Unmarshal(b, &m); err != nil || m.Name != name {
		return nil, fmt.Errorf("%w: %s.meta", ErrUnreadable, name)
	}
	m.Info.Host = m.Host
	return &m, nil
}

// Info returns tenancy name as appq_list shows it.
func (s *Store) Info(name string) (Info, error) {
	if !ValidName(name) {
		return Info{}, ErrBadName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return Info{}, err
	}
	m, err := s.readMeta(name)
	if err != nil {
		return Info{}, err
	}
	return s.view(m), nil
}

func (s *Store) view(m *metaFile) Info {
	i := m.Info
	i.State = StateActive
	if s.broken[i.Name] {
		i.State = StateUnreadable
	}
	return i
}

// List returns every tenancy, by name. It needs the directory only, not the keystore. Leftovers of
// an interrupted add or removal (files without a .meta, temp files) are deleted.
func (s *Store) List() ([]Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorage, err)
	}
	have := map[string]bool{}
	for _, e := range entries {
		have[e.Name()] = true
	}
	out := []Info{}
	for _, e := range entries {
		file := e.Name()
		name, ext := strings.TrimSuffix(file, filepath.Ext(file)), filepath.Ext(file)
		switch {
		case ext == ".tmp":
			_ = os.Remove(filepath.Join(s.dir, file))
		case (ext == ".pkg" || ext == ".key") && !have[name+".meta"]:
			_ = os.Remove(filepath.Join(s.dir, file))
		case ext == ".meta" && ValidName(name):
			m, err := s.readMeta(name)
			if err != nil {
				continue
			}
			if !have[name+".pkg"] || !have[name+".key"] {
				s.broken[name] = true
			}
			out = append(out, s.view(m))
		}
	}
	slices.SortFunc(out, func(a, b Info) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Names lists the tenancies' names ("" on any error; health).
func (s *Store) Names() []string {
	list, _ := s.List()
	out := make([]string, 0, len(list))
	for _, i := range list {
		out = append(out, i.Name)
	}
	return out
}

// Remove deletes tenancy name: its .meta, its key, its package. It returns what it was.
func (s *Store) Remove(name string) (Info, error) {
	return s.remove(name, "")
}

// Revoke deletes tenancy name when it is still generation gen (a request with its token was refused
// as revoked); a newer tenancy of the same name stays. ok is false when there was nothing to delete.
func (s *Store) Revoke(name, gen string) (Info, bool) {
	if gen == "" {
		return Info{}, false
	}
	i, err := s.remove(name, gen)
	return i, err == nil
}

func (s *Store) remove(name, gen string) (Info, error) {
	if !ValidName(name) {
		return Info{}, ErrBadName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return Info{}, err
	}
	m, err := s.readMeta(name)
	if errors.Is(err, ErrNotFound) {
		return Info{}, err
	}
	if gen != "" && (m == nil || m.Gen != gen) {
		return Info{}, ErrNotFound
	}
	var i Info
	if m != nil {
		i = s.view(m)
	}
	i.Name = name
	if err := s.removeFiles(name); err != nil {
		return i, fmt.Errorf("%w: %v", ErrStorage, err)
	}
	return i, nil
}

// removeFiles deletes a tenancy's files, .meta first, and forgets its opened package.
func (s *Store) removeFiles(name string) error {
	delete(s.open, name)
	delete(s.broken, name)
	var first error
	for _, ext := range []string{".meta", ".key", ".pkg", ".pkg.tmp", ".key.tmp", ".meta.tmp"} {
		if err := os.Remove(s.path(name, ext)); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = err
		}
	}
	if err := syncDir(s.dir); err != nil && first == nil {
		first = err
	}
	return first
}

// Migrate moves the bring-up's plain packages (<deDir>/<name>.ogpkg, og-os M12) into the store
// (seal: debuggable builds) and deletes them (every build). A tenancy already in the store keeps
// its sealed copy; a file that isn't a usable package is only deleted. It returns the tenancies it
// sealed and the number of files it deleted; an error means the store isn't ready yet (call again).
func (s *Store) Migrate(deDir string, seal bool) (migrated []Info, deleted int, err error) {
	entries, rerr := os.ReadDir(deDir)
	if rerr != nil {
		return nil, 0, nil
	}
	defer func() {
		if deleted > 0 {
			_ = syncDir(deDir)
		}
	}()
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".ogpkg")
		if !ok || !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(deDir, e.Name())
		if seal && ValidName(name) {
			if b, err := os.ReadFile(path); err == nil {
				if _, perr := route.ParsePackage(b); perr == nil {
					_, ierr := s.Info(name)
					switch {
					case ierr == nil:
					case errors.Is(ierr, ErrNotFound):
						i, aerr := s.Add(name, b, Info{}, OriginMigrated)
						if aerr != nil && notReady(aerr) {
							return migrated, deleted, aerr
						}
						if aerr == nil {
							migrated = append(migrated, i)
						}
					default:
						return migrated, deleted, ierr
					}
				}
			}
		}
		if os.Remove(path) == nil {
			deleted++
		}
	}
	return migrated, deleted, nil
}

// notReady: the store can't take tenancies now, but may later.
func notReady(err error) bool {
	return errors.Is(err, ErrLocked) || errors.Is(err, ErrLink) || errors.Is(err, ErrKeystore) || errors.Is(err, ErrStorage)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
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
