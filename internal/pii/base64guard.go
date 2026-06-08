package pii

import "regexp"

const base64MinLen = 40

var quotedBase64 = regexp.MustCompile(`"([A-Za-z0-9+/_-]+={0,2})"`)

func protectedRanges(s string) [][2]int {
	var ranges [][2]int
	for _, loc := range quotedBase64.FindAllStringSubmatchIndex(s, -1) {
		start, end := loc[2], loc[3]
		if end-start >= base64MinLen {
			ranges = append(ranges, [2]int{start, end})
		}
	}
	return ranges
}

func inRanges(pos int, ranges [][2]int) bool {
	for _, r := range ranges {
		if pos >= r[0] && pos < r[1] {
			return true
		}
	}
	return false
}
