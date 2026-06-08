package memory

import (
	"fmt"
	"sync"
	"testing"
)

func TestPutGetRoundTrip(t *testing.T) {
	s, err := New[string](4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Put("k", "v")
	if got, ok := s.Get("k"); !ok || got != "v" {
		t.Fatalf("Get(k) = %q, %v; want \"v\", true", got, ok)
	}
	if _, ok := s.Get("absent"); ok {
		t.Fatalf("Get(absent) reported present")
	}
}

func TestEvictionOrder(t *testing.T) {
	s, err := New[int](2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Put("a", 1)
	s.Put("b", 2)
	// Touch "a" so "b" becomes least-recently-used.
	if _, ok := s.Get("a"); !ok {
		t.Fatal("a missing before eviction")
	}
	s.Put("c", 3) // evicts "b"

	if _, ok := s.Get("b"); ok {
		t.Error("b should have been evicted")
	}
	if _, ok := s.Get("a"); !ok {
		t.Error("a should have survived")
	}
	if _, ok := s.Get("c"); !ok {
		t.Error("c should be present")
	}
}

func TestUpdateExistingKey(t *testing.T) {
	s, err := New[int](2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Put("k", 1)
	s.Put("k", 2)
	if got, _ := s.Get("k"); got != 2 {
		t.Errorf("Get(k) = %d, want 2", got)
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1", s.Len())
	}
}

func TestPurge(t *testing.T) {
	s, err := New[int](4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Put("a", 1)
	s.Put("b", 2)
	s.Purge()
	if s.Len() != 0 {
		t.Errorf("Len after Purge = %d, want 0", s.Len())
	}
	if _, ok := s.Get("a"); ok {
		t.Error("Get after Purge reported present")
	}
}

func TestNewRejectsNonPositiveCapacity(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := New[int](n); err == nil {
			t.Errorf("New(%d): expected error", n)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	s, err := New[int](64)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const workers = 16
	const ops = 1000
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range ops {
				key := fmt.Sprintf("k%d", (w*ops+i)%128)
				s.Put(key, i)
				s.Get(key)
				_ = s.Len()
			}
		}(w)
	}
	wg.Wait()
	if s.Len() > 64 {
		t.Errorf("Len = %d, exceeds capacity 64", s.Len())
	}
}

func TestGenericValueTypes(t *testing.T) {
	type entry struct {
		spans   []int
		mapping map[string]string
	}
	si, err := New[int](2)
	if err != nil {
		t.Fatalf("New[int]: %v", err)
	}
	si.Put("n", 7)
	if got, _ := si.Get("n"); got != 7 {
		t.Errorf("int value = %d, want 7", got)
	}

	ss, err := New[entry](2)
	if err != nil {
		t.Fatalf("New[entry]: %v", err)
	}
	e := entry{spans: []int{1, 2}, mapping: map[string]string{"a": "b"}}
	ss.Put("e", e)
	if got, _ := ss.Get("e"); got.mapping["a"] != "b" || len(got.spans) != 2 {
		t.Errorf("struct value = %+v, want %+v", got, e)
	}
}
