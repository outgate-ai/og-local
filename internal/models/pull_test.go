package models

import (
	"errors"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	if m, err := resolve(""); err != nil || m.Name != Default().Name {
		t.Errorf("resolve(\"\") = %q, %v; want default", m.Name, err)
	}
	if m, err := resolve("openai/privacy-filter"); err != nil || m.Name != "openai/privacy-filter" {
		t.Errorf("resolve(named) = %q, %v", m.Name, err)
	}
	var ue *UnknownModelError
	if _, err := resolve("nope/missing"); !errors.As(err, &ue) {
		t.Errorf("resolve(unknown) err = %v, want *UnknownModelError", err)
	}
}

func TestUnknownModelError(t *testing.T) {
	e := &UnknownModelError{Name: "x/y"}
	if !strings.Contains(e.Error(), "x/y") {
		t.Errorf("Error() = %q, want it to mention x/y", e.Error())
	}
}
