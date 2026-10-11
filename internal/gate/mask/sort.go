package mask

import "sort"

func sortByLastSeen(es []*entry) {
	sort.Slice(es, func(i, j int) bool { return es[i].L < es[j].L })
}

func sortSpans(s []Span) {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Start != s[j].Start {
			return s[i].Start < s[j].Start
		}
		return s[i].End-s[i].Start > s[j].End-s[j].Start
	})
}
