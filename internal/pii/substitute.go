package pii

import (
	"sort"
	"strings"
)

type Pair struct {
	From string
	To   string
}

func substitute(text string, pairs []Pair) (out string, count int) {
	ordered := make([]Pair, 0, len(pairs))
	for _, p := range pairs {
		if p.From != "" {
			ordered = append(ordered, p)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(ordered[i].From) > len(ordered[j].From)
	})

	out = text
	for _, p := range ordered {
		protected := protectedRanges(out)
		var b strings.Builder
		from := 0
		for {
			idx := strings.Index(out[from:], p.From)
			if idx < 0 {
				break
			}
			pos := from + idx
			if inRanges(pos, protected) {
				b.WriteString(out[from : pos+len(p.From)])
				from = pos + len(p.From)
				continue
			}
			b.WriteString(out[from:pos])
			b.WriteString(p.To)
			from = pos + len(p.From)
			count++
		}
		b.WriteString(out[from:])
		out = b.String()
	}
	return out, count
}
