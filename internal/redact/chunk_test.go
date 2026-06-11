package redact

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/outgate-ai/og-local/internal/pii"
)

func TestSplitChunksSingle(t *testing.T) {
	for _, text := range []string{"", "short", strings.Repeat("a", 16)} {
		got := splitChunks(text, 16, 4)
		if len(got) != 1 || got[0] != (chunk{start: 0, text: text}) {
			t.Errorf("%q: got %+v, want single soft chunk", text, got)
		}
	}
}

func TestSplitChunksNewlineCut(t *testing.T) {
	text := strings.Repeat("a", 10) + "\n" + "bob@x.io 12345\n" + strings.Repeat("c", 10)
	got := splitChunks(text, 16, 4)
	want := []chunk{
		{start: 0, text: strings.Repeat("a", 10) + "\n"},
		{start: 11, text: "bob@x.io 12345\n"},
		{start: 26, text: strings.Repeat("c", 10)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestSplitChunksNewlineBeforeFloorIgnored(t *testing.T) {
	// The only newline sits in the window's first half; a space in the second
	// half wins, so chunks never degenerate below half the target.
	text := "ab\n" + strings.Repeat("c", 8) + " " + strings.Repeat("d", 20)
	got := splitChunks(text, 16, 4)
	if got[0].text != "ab\n"+strings.Repeat("c", 8)+" " {
		t.Errorf("first chunk = %q, want cut at the space", got[0].text)
	}
	if got[0].hardRight {
		t.Error("space cut must not be hard")
	}
}

func TestSplitChunksHardCut(t *testing.T) {
	text := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
	got := splitChunks(text, 16, 4)
	want := []chunk{
		{start: 0, text: "abcdefghijklmnop", hardRight: true},
		{start: 12, text: "mnopqrstuvwxyzAB", hardLeft: true, hardRight: true},
		{start: 24, text: "yzABCDEFGHIJKLMN", hardLeft: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestSplitChunksRuneBoundaries(t *testing.T) {
	text := strings.Repeat("日", 20)
	got := splitChunks(text, 16, 4)
	for i, c := range got {
		if !utf8.ValidString(c.text) {
			t.Errorf("chunk %d not valid UTF-8: %q", i, c.text)
		}
		if c.text == "" {
			t.Errorf("chunk %d empty", i)
		}
		if len(c.text) > 16 {
			t.Errorf("chunk %d exceeds target: %d", i, len(c.text))
		}
	}
}

func TestSplitChunksCoverage(t *testing.T) {
	texts := []string{
		strings.Repeat("x", 100),
		strings.Repeat("word ", 40),
		strings.Repeat("line\n", 30),
		strings.Repeat("日本語テキスト", 10),
		strings.Repeat("a", 17),
	}
	for _, text := range texts {
		chunks := splitChunks(text, 16, 4)
		end := 0
		for i, c := range chunks {
			if c.start > end {
				t.Fatalf("%q: gap before chunk %d (start %d, covered %d)", text[:10], i, c.start, end)
			}
			if got := c.start + len(c.text); got > end {
				end = got
			}
			if c.text == "" || len(c.text) > 16 {
				t.Errorf("chunk %d bad length %d", i, len(c.text))
			}
			if text[c.start:c.start+len(c.text)] != c.text {
				t.Errorf("chunk %d text does not match its offset", i)
			}
		}
		if end != len(text) {
			t.Errorf("covered %d of %d bytes", end, len(text))
		}
	}
}

func TestSplitChunksPrefixStable(t *testing.T) {
	base := strings.Repeat("log line one two three\n", 10)
	grown := base + "appended tail line\n"
	a, b := splitChunks(base, 32, 8), splitChunks(grown, 32, 8)
	if len(b) < len(a) {
		t.Fatalf("grown text produced fewer chunks: %d vs %d", len(b), len(a))
	}
	for i := 0; i < len(a)-1; i++ {
		if !reflect.DeepEqual(a[i], b[i]) {
			t.Errorf("chunk %d changed after append: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestSplitChunksOverlapClamp(t *testing.T) {
	text := strings.Repeat("x", 100)
	chunks := splitChunks(text, 16, 1000)
	prev := -1
	for _, c := range chunks {
		if c.start <= prev {
			t.Fatalf("no forward progress: start %d after %d", c.start, prev)
		}
		prev = c.start
	}
}

func TestMergeSpansRemapAndEdges(t *testing.T) {
	chunks := []chunk{
		{start: 0, text: "abcdefghijklmnop", hardRight: true},
		{start: 12, text: "mnopqrstuvwxyzAB", hardLeft: true, hardRight: true},
		{start: 24, text: "yzABCDEFGHIJKLMN", hardLeft: true},
	}
	perChunk := [][]pii.Span{
		{
			{Start: 2, End: 6, Class: pii.ClassPerson, Score: 0.9},
			{Start: 13, End: 16, Class: pii.ClassSecret, Score: 0.8}, // touches hard right edge
		},
		{
			{Start: 0, End: 4, Class: pii.ClassSecret, Score: 0.7}, // touches hard left edge
			{Start: 1, End: 4, Class: pii.ClassSecret, Score: 0.9}, // interior: the re-detected tail
		},
		{
			{Start: 4, End: 8, Class: pii.ClassPhone, Score: 0.6},
		},
	}
	got := mergeSpans(chunks, perChunk)
	want := []pii.Span{
		{Start: 2, End: 6, Class: pii.ClassPerson, Score: 0.9},
		{Start: 13, End: 16, Class: pii.ClassSecret, Score: 0.9},
		{Start: 28, End: 32, Class: pii.ClassPhone, Score: 0.6},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestMergeSpansSoftEdgesKept(t *testing.T) {
	chunks := []chunk{
		{start: 0, text: "line one\n"},
		{start: 9, text: "bob@x.io rest"},
	}
	perChunk := [][]pii.Span{
		nil,
		{{Start: 0, End: 8, Class: pii.ClassEmail, Score: 0.9}},
	}
	got := mergeSpans(chunks, perChunk)
	want := []pii.Span{{Start: 9, End: 17, Class: pii.ClassEmail, Score: 0.9}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("line-initial span after a soft cut must survive: got %+v", got)
	}
}

func TestMergeSpansDedupe(t *testing.T) {
	chunks := []chunk{{start: 0, text: "abcdefghij"}}
	perChunk := [][]pii.Span{{
		{Start: 1, End: 9, Class: pii.ClassPerson, Score: 0.5},
		{Start: 1, End: 9, Class: pii.ClassPerson, Score: 0.8},
		{Start: 2, End: 5, Class: pii.ClassEmail, Score: 0.9}, // contained in the wider span
	}}
	got := mergeSpans(chunks, perChunk)
	want := []pii.Span{{Start: 1, End: 9, Class: pii.ClassPerson, Score: 0.8}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}
