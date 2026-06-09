package pii

import (
	"math"
	"strings"
)

type TransitionBiases struct {
	BackgroundStay    float64
	BackgroundToStart float64
	EndToBackground   float64
	EndToStart        float64
	InsideToContinue  float64
	InsideToEnd       float64
}

type tag struct {
	prefix byte // 'O', 'B', 'I', 'E', 'S'
	class  Class
}

type Decoder struct {
	tags   []tag
	biases TransitionBiases
}

func NewDecoder(id2label []string, biases TransitionBiases) *Decoder {
	tags := make([]tag, len(id2label))
	for i, lbl := range id2label {
		if lbl == "O" || lbl == "" {
			tags[i] = tag{prefix: 'O'}
			continue
		}
		dash := strings.IndexByte(lbl, '-')
		if dash < 0 {
			tags[i] = tag{prefix: 'O'}
			continue
		}
		tags[i] = tag{prefix: lbl[0], class: Class(lbl[dash+1:])}
	}
	return &Decoder{tags: tags, biases: biases}
}

var neginf = math.Inf(-1)

func (d *Decoder) transition(from, to tag) float64 {
	switch from.prefix {
	case 'O', 'E', 'S':
		switch to.prefix {
		case 'O':
			if from.prefix == 'O' {
				return d.biases.BackgroundStay
			}
			return d.biases.EndToBackground
		case 'B', 'S':
			if from.prefix == 'O' {
				return d.biases.BackgroundToStart
			}
			return d.biases.EndToStart
		default:
			return neginf
		}
	case 'B', 'I':
		if (to.prefix == 'I' || to.prefix == 'E') && to.class == from.class {
			if to.prefix == 'I' {
				return d.biases.InsideToContinue
			}
			return d.biases.InsideToEnd
		}
		return neginf
	default:
		//coverage:ignore reason=every tag prefix is O/B/I/E/S; no other value is constructed.
		return neginf
	}
}

func (d *Decoder) Decode(logits [][]float32, offsets [][2]int) []Span {
	n := len(logits)
	if n == 0 {
		return nil
	}
	k := len(d.tags)

	score := make([][]float64, n)
	back := make([][]int, n)
	for i := range score {
		score[i] = make([]float64, k)
		back[i] = make([]int, k)
	}

	for j := 0; j < k; j++ {
		if d.tags[j].prefix == 'I' || d.tags[j].prefix == 'E' {
			score[0][j] = neginf
		} else {
			score[0][j] = float64(logits[0][j])
		}
		back[0][j] = -1
	}

	for i := 1; i < n; i++ {
		for j := 0; j < k; j++ {
			best := neginf
			bestPrev := 0
			for p := 0; p < k; p++ {
				if math.IsInf(score[i-1][p], -1) {
					continue
				}
				cand := score[i-1][p] + d.transition(d.tags[p], d.tags[j])
				if cand > best {
					best = cand
					bestPrev = p
				}
			}
			score[i][j] = best + float64(logits[i][j])
			back[i][j] = bestPrev
		}
	}

	last, bestEnd := 0, neginf
	for j := 0; j < k; j++ {
		if score[n-1][j] > bestEnd {
			bestEnd = score[n-1][j]
			last = j
		}
	}

	path := make([]int, n)
	for i := n - 1; i >= 0; i-- {
		path[i] = last
		last = back[i][last]
		if last < 0 {
			break
		}
	}

	return d.assemble(path, logits, offsets)
}

func TrimSpans(text string, spans []Span) []Span {
	out := spans[:0]
	for _, s := range spans {
		for s.Start < s.End && isSpace(text[s.Start]) {
			s.Start++
		}
		for s.End > s.Start && isSpace(text[s.End-1]) {
			s.End--
		}
		if s.Start < s.End {
			out = append(out, s)
		}
	}
	return out
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func (d *Decoder) assemble(path []int, logits [][]float32, offsets [][2]int) []Span {
	var spans []Span
	i := 0
	for i < len(path) {
		t := d.tags[path[i]]
		switch t.prefix {
		case 'S':
			spans = append(spans, Span{
				Start: offsets[i][0], End: offsets[i][1], Class: t.class,
				Score: prob(logits[i], path[i]),
			})
			i++
		case 'B':
			start := offsets[i][0]
			scoreSum := prob(logits[i], path[i])
			count := 1
			j := i + 1
			for j < len(path) {
				tj := d.tags[path[j]]
				if (tj.prefix == 'I' || tj.prefix == 'E') && tj.class == t.class {
					scoreSum += prob(logits[j], path[j])
					count++
					if tj.prefix == 'E' {
						spans = append(spans, Span{
							Start: start, End: offsets[j][1], Class: t.class,
							Score: scoreSum / float32(count),
						})
						break
					}
					j++
					continue
				}
				break
			}
			i = j + 1
		default:
			i++
		}
	}
	return spans
}

func prob(logits []float32, idx int) float32 {
	maxv := logits[0]
	for _, v := range logits {
		if v > maxv {
			maxv = v
		}
	}
	var sum float64
	for _, v := range logits {
		sum += math.Exp(float64(v - maxv))
	}
	return float32(math.Exp(float64(logits[idx]-maxv)) / sum)
}
