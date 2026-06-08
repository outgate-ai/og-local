package pii

import (
	"testing"
)

// label indices for a single-class test alphabet.
const (
	lO = iota
	lB
	lI
	lE
	lS
)

func testDecoder() *Decoder {
	return NewDecoder([]string{"O", "B-secret", "I-secret", "E-secret", "S-secret"}, TransitionBiases{})
}

// logitsFor builds a logit matrix that strongly favors the given label per token.
func logitsFor(seq []int) [][]float32 {
	out := make([][]float32, len(seq))
	for i, want := range seq {
		row := make([]float32, 5)
		for j := range row {
			row[j] = 0
		}
		row[want] = 10
		out[i] = row
	}
	return out
}

func offsetsFor(n int) [][2]int {
	out := make([][2]int, n)
	for i := range out {
		out[i] = [2]int{i, i + 1}
	}
	return out
}

func TestDecodeEmpty(t *testing.T) {
	if got := testDecoder().Decode(nil, nil); got != nil {
		t.Errorf("Decode(nil) = %v, want nil", got)
	}
}

func TestDecodeAllOutside(t *testing.T) {
	d := testDecoder()
	logits := logitsFor([]int{lO, lO, lO})
	if got := d.Decode(logits, offsetsFor(3)); len(got) != 0 {
		t.Errorf("all-O decoded to spans: %v", got)
	}
}

func TestDecodeSingleton(t *testing.T) {
	d := testDecoder()
	logits := logitsFor([]int{lO, lS, lO})
	got := d.Decode(logits, offsetsFor(3))
	want := []Span{{Start: 1, End: 2, Class: ClassSecret}}
	if len(got) != 1 || got[0].Start != want[0].Start || got[0].End != want[0].End || got[0].Class != want[0].Class {
		t.Fatalf("singleton: got %+v, want one S-span at [1,2)", got)
	}
	if got[0].Score <= 0.5 {
		t.Errorf("score = %v, want high (>0.5)", got[0].Score)
	}
}

func TestDecodeBeginEnd(t *testing.T) {
	d := testDecoder()
	logits := logitsFor([]int{lB, lE})
	got := d.Decode(logits, offsetsFor(2))
	if len(got) != 1 || got[0].Start != 0 || got[0].End != 2 || got[0].Class != ClassSecret {
		t.Fatalf("B-E: got %+v, want one span [0,2)", got)
	}
}

func TestDecodeBeginInsideEnd(t *testing.T) {
	d := testDecoder()
	logits := logitsFor([]int{lB, lI, lI, lE})
	got := d.Decode(logits, offsetsFor(4))
	if len(got) != 1 || got[0].Start != 0 || got[0].End != 4 {
		t.Fatalf("B-I-I-E: got %+v, want one span [0,4)", got)
	}
}

func TestDecodeTwoEntities(t *testing.T) {
	d := testDecoder()
	logits := logitsFor([]int{lS, lO, lS})
	got := d.Decode(logits, offsetsFor(3))
	if len(got) != 2 {
		t.Fatalf("got %d spans, want 2", len(got))
	}
}

func TestDecodeIllegalStartIsCorrected(t *testing.T) {
	// Logits scream "I-secret" at position 0, which is illegal as a sequence
	// start. Viterbi must pick a legal path instead of emitting a broken span.
	d := testDecoder()
	logits := logitsFor([]int{lI, lE})
	got := d.Decode(logits, offsetsFor(2))
	for _, s := range got {
		if s.Start == 0 && s.End == 1 {
			t.Errorf("decoder emitted a span from an illegal I-start: %+v", got)
		}
	}
}

func TestDecodeMultibyteOffsets(t *testing.T) {
	d := testDecoder()
	logits := logitsFor([]int{lS})
	// A token spanning bytes [0,4) (e.g. a 4-byte emoji).
	got := d.Decode(logits, [][2]int{{0, 4}})
	if len(got) != 1 || got[0].Start != 0 || got[0].End != 4 {
		t.Fatalf("offset passthrough: got %+v, want [0,4)", got)
	}
}

func TestDecodeOutsideToInsideIsIllegal(t *testing.T) {
	// O followed by strong I: the O->I transition is illegal, so the decoder
	// must route to a legal path and not produce a span spanning token 1.
	d := testDecoder()
	logits := logitsFor([]int{lO, lI})
	got := d.Decode(logits, offsetsFor(2))
	for _, s := range got {
		if s.Start == 1 {
			t.Errorf("O->I produced a span: %+v", got)
		}
	}
}

func TestDecodeUnterminatedBegin(t *testing.T) {
	// B with no following E (forced by making E/I emissions impossible after).
	// The decoder must not emit a span and must not panic.
	d := testDecoder()
	logits := logitsFor([]int{lB, lO})
	got := d.Decode(logits, offsetsFor(2))
	for _, s := range got {
		if s.Start == 0 {
			t.Errorf("unterminated B produced a span: %+v", got)
		}
	}
}

func TestDecodeEndToBeginChain(t *testing.T) {
	// S, then immediately B-E: exercises end-to-start transition + a second span.
	d := testDecoder()
	logits := logitsFor([]int{lS, lB, lE})
	got := d.Decode(logits, offsetsFor(3))
	if len(got) != 2 {
		t.Fatalf("got %d spans, want 2 (S then B-E)", len(got))
	}
}

func TestNewDecoderHandlesMalformedLabels(t *testing.T) {
	d := NewDecoder([]string{"O", "weird", "B-x"}, TransitionBiases{})
	if d.tags[1].prefix != 'O' {
		t.Errorf("label without dash should map to O, got %c", d.tags[1].prefix)
	}
}

func TestDecodeRespectsTransitionBias(t *testing.T) {
	d := NewDecoder(
		[]string{"O", "B-secret", "I-secret", "E-secret", "S-secret"},
		TransitionBiases{BackgroundToStart: -100},
	)
	// Token 0 is clearly O; token 1's emission slightly favors S, but the
	// strong negative O->start bias should make the decoder keep it O.
	logits := [][]float32{
		{10, 0, 0, 0, 0},
		{0.4, 0, 0, 0, 0.5},
	}
	if got := d.Decode(logits, offsetsFor(2)); len(got) != 0 {
		t.Errorf("strong negative start bias should suppress the singleton, got %+v", got)
	}
}
