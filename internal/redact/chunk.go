package redact

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/outgate-ai/og-local/internal/pii"
)

type chunk struct {
	start     int
	text      string
	hardLeft  bool
	hardRight bool
}

// splitChunks cuts text into detector-sized pieces, greedy from the start so
// boundaries are stable under appends. Cuts prefer the last newline in the
// window's second half, then the last space; otherwise a hard cut at a rune
// boundary, re-entering overlap bytes earlier so a span truncated by the cut
// is seen whole by the next chunk.
func splitChunks(text string, target, overlap int) []chunk {
	if overlap > target/4 {
		overlap = target / 4
	}
	if len(text) <= target {
		return []chunk{{text: text}}
	}
	var out []chunk
	pos := 0
	hardLeft := false
	for len(text)-pos > target {
		window := text[pos : pos+target]
		half := target / 2
		var cut int
		hard := false
		if i := strings.LastIndexByte(window[half:], '\n'); i >= 0 {
			cut = pos + half + i + 1
		} else if i := strings.LastIndexByte(window[half:], ' '); i >= 0 {
			cut = pos + half + i + 1
		} else {
			b := pos + target
			for !utf8.RuneStart(text[b]) {
				b--
			}
			cut, hard = b, true
		}
		out = append(out, chunk{start: pos, text: text[pos:cut], hardLeft: hardLeft, hardRight: hard})
		if hard {
			pos = cut - overlap
			for !utf8.RuneStart(text[pos]) {
				pos++
			}
		} else {
			pos = cut
		}
		hardLeft = hard
	}
	return append(out, chunk{start: pos, text: text[pos:], hardLeft: hardLeft})
}

// mergeSpans remaps chunk-relative spans into field coordinates. Spans
// touching a hard-cut edge are dropped as potentially truncated — the overlap
// re-detects them whole in the neighboring chunk. Soft-cut and field edges
// keep their spans.
func mergeSpans(chunks []chunk, perChunk [][]pii.Span) []pii.Span {
	var out []pii.Span
	for i, c := range chunks {
		for _, s := range perChunk[i] {
			if c.hardRight && s.End == len(c.text) {
				continue
			}
			if c.hardLeft && s.Start == 0 {
				continue
			}
			s.Start += c.start
			s.End += c.start
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].End > out[j].End
	})
	kept := out[:0]
	for _, s := range out {
		if n := len(kept); n > 0 && s.Start >= kept[n-1].Start && s.End <= kept[n-1].End {
			last := &kept[n-1]
			if s.Start == last.Start && s.End == last.End && s.Class == last.Class && s.Score > last.Score {
				last.Score = s.Score
			}
			continue
		}
		kept = append(kept, s)
	}
	return kept
}
