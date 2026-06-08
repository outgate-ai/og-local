package memory

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/outgate-ai/og-local/internal/storage"
)

// Store is an entry-count-capped LRU implementation of storage.Store, backed by
// hashicorp/golang-lru. The backing cache is internally synchronized, so this
// wrapper adds no locking of its own.
type Store[V any] struct {
	c *lru.Cache[string, V]
}

var _ storage.Store[int] = (*Store[int])(nil)

// New returns a Store holding at most maxEntries entries. maxEntries must be
// positive.
func New[V any](maxEntries int) (*Store[V], error) {
	if maxEntries <= 0 {
		return nil, fmt.Errorf("memory: maxEntries must be positive, got %d", maxEntries)
	}
	c, err := lru.New[string, V](maxEntries)
	if err != nil {
		//coverage:ignore reason=lru.New only errors on size <= 0, already rejected above.
		return nil, fmt.Errorf("memory: new lru: %w", err)
	}
	return &Store[V]{c: c}, nil
}

func (s *Store[V]) Get(key string) (V, bool) { return s.c.Get(key) }

func (s *Store[V]) Put(key string, value V) { s.c.Add(key, value) }

func (s *Store[V]) Len() int { return s.c.Len() }

func (s *Store[V]) Purge() { s.c.Purge() }
