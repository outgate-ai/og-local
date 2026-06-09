//go:build !onnx

package detector

import (
	"errors"
	"testing"
)

func TestNewUnavailableInPureGoBuild(t *testing.T) {
	det, closeFn, err := New(Config{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if det != nil {
		t.Errorf("detector = %v, want nil", det)
	}
	if closeFn != nil {
		t.Errorf("close = non-nil, want nil")
	}
}

func TestNewUnavailableIgnoresConfig(t *testing.T) {
	if _, _, err := New(Config{ModelName: "openai/privacy-filter", LibPath: "/x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable regardless of config", err)
	}
}
