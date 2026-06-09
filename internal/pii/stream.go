package pii

func (m Mapping) PartialSuffixLen(buf string) int {
	if buf == "" {
		return 0
	}
	longest := 0
	for _, p := range m {
		tok := p.To
		if len(tok) < 2 {
			continue
		}
		limit := len(tok) - 1
		if limit > len(buf) {
			limit = len(buf)
		}
		for n := limit; n > longest; n-- {
			if buf[len(buf)-n:] == tok[:n] {
				longest = n
				break
			}
		}
	}
	return longest
}
