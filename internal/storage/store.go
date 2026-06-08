package storage

// Store is a fixed-capacity, content-addressed cache. Keys are caller-supplied
// content hashes, treated as opaque strings; the caller is responsible for
// choosing a collision-resistant key function. Implementations must be safe for
// concurrent use.
type Store[V any] interface {
	Get(key string) (V, bool)
	// Put inserts or updates key, evicting the least-recently-used entry first
	// when at capacity.
	Put(key string, value V)
	Len() int
	Purge()
}
