//go:build onnx

package onnx

import (
	"fmt"

	"github.com/daulet/tokenizers"
)

type tokenizer struct {
	tk *tokenizers.Tokenizer
}

func loadTokenizer(path string) (*tokenizer, error) {
	tk, err := tokenizers.FromFile(path)
	if err != nil {
		return nil, fmt.Errorf("onnx: load tokenizer: %w", err)
	}
	return &tokenizer{tk: tk}, nil
}

func (t *tokenizer) close() {
	if t.tk != nil {
		_ = t.tk.Close()
	}
}

func (t *tokenizer) encode(text string) (ids []int64, offsets [][2]int) {
	enc := t.tk.EncodeWithOptions(text, false, tokenizers.WithReturnOffsets())
	ids = make([]int64, len(enc.IDs))
	for i, id := range enc.IDs {
		ids[i] = int64(id)
	}
	offsets = make([][2]int, len(enc.Offsets))
	for i, o := range enc.Offsets {
		offsets[i] = [2]int{int(o[0]), int(o[1])}
	}
	return ids, offsets
}
