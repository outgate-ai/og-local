package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/outgate-ai/og-local/internal/detector"
	"github.com/outgate-ai/og-local/internal/redact"
)

const benchUsage = `Usage:
  ogl detect-bench [--threads N] [--sizes 1024,4096,...] [--reps N] [--model-file F]
                   [--save-optimized PATH] [--profile PREFIX]

Loads the detector (OGL_CACHE_DIR, OGL_ONNXRUNTIME_LIB as usual), then prints one JSON
line per measurement: load time and memory, then the latency of detecting synthetic text
of each size through the redaction pipeline (4 KiB chunks, no span cache).
`

type benchLine struct {
	Event     string   `json:"event"`
	Threads   int      `json:"threads,omitempty"`
	Bytes     int      `json:"bytes,omitempty"`
	Tokens    int      `json:"tokens,omitempty"`
	Reps      int      `json:"reps,omitempty"`
	MedianMs  float64  `json:"median_ms,omitempty"`
	MinMs     float64  `json:"min_ms,omitempty"`
	MaxMs     float64  `json:"max_ms,omitempty"`
	MsPerKB   float64  `json:"ms_per_kb,omitempty"`
	Spans     int      `json:"spans,omitempty"`
	LoadMs    float64  `json:"load_ms,omitempty"`
	RSSKB     int64    `json:"rss_kb,omitempty"`
	HWMKB     int64    `json:"hwm_kb,omitempty"`
	AnonKB    int64    `json:"rss_anon_kb,omitempty"`
	FileKB    int64    `json:"rss_file_kb,omitempty"`
	GoArch    string   `json:"goarch,omitempty"`
	NumCPU    int      `json:"num_cpu,omitempty"`
	Error     string   `json:"error,omitempty"`
	SpanClass []string `json:"classes,omitempty"`
}

func runDetectBench(args []string) int {
	fs := flag.NewFlagSet("detect-bench", flag.ContinueOnError)
	fs.Usage = func() { _, _ = os.Stderr.WriteString(benchUsage) }
	threads := fs.Int("threads", 0, "intra-op threads (0 = runtime default)")
	sizesFlag := fs.String("sizes", "1024,4096,16384,65536", "text sizes in bytes")
	reps := fs.Int("reps", 3, "repetitions per size")
	modelFile := fs.String("model-file", "", "graph inside the model directory (default onnx/model_q4f16.onnx)")
	optimized := fs.String("save-optimized", "", "write the optimised graph to this path")
	profile := fs.String("profile", "", "write a per-node runtime profile with this prefix")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var sizes []int
	for _, f := range strings.Split(*sizesFlag, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "bad size %q\n", f)
			return 2
		}
		sizes = append(sizes, n)
	}
	out := json.NewEncoder(os.Stdout)
	emit := func(l benchLine) { _ = out.Encode(l) }

	start := time.Now()
	det, closeFn, err := detector.New(detector.Config{
		LibPath: os.Getenv("OGL_ONNXRUNTIME_LIB"), Threads: *threads,
		ModelFile: *modelFile, OptimizedPath: *optimized, ProfilePrefix: *profile,
	})
	if err != nil {
		emit(benchLine{Event: "load", Error: err.Error()})
		return 1
	}
	defer func() { _ = closeFn() }()
	l := benchLine{Event: "load", Threads: *threads, LoadMs: ms(time.Since(start)), GoArch: runtime.GOARCH, NumCPU: runtime.NumCPU()}
	fillMem(&l)
	emit(l)

	p, err := redact.New(det, nil)
	if err != nil {
		emit(benchLine{Event: "pipeline", Error: err.Error()})
		return 1
	}
	counter, _ := det.(interface{ CountTokens(string) int })
	ctx := context.Background()
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // reproducible synthetic text, not secrets

	t := time.Now()
	spans, err := p.Spans(ctx, syntheticText(rng, 1024))
	if err != nil {
		emit(benchLine{Event: "first", Error: err.Error()})
		return 1
	}
	f := benchLine{Event: "first", Bytes: 1024, MedianMs: ms(time.Since(t)), Spans: len(spans)}
	fillMem(&f)
	emit(f)

	for _, size := range sizes {
		var durs []float64
		var nspans, ntok int
		classes := map[string]bool{}
		for r := 0; r < *reps; r++ {
			text := syntheticText(rng, size)
			if counter != nil && r == 0 {
				ntok = counter.CountTokens(text)
			}
			t := time.Now()
			sp, err := p.Spans(ctx, text)
			if err != nil {
				emit(benchLine{Event: "size", Bytes: size, Error: err.Error()})
				return 1
			}
			durs = append(durs, ms(time.Since(t)))
			nspans = len(sp)
			for _, s := range sp {
				classes[string(s.Class)] = true
			}
		}
		sort.Float64s(durs)
		med := durs[len(durs)/2]
		row := benchLine{
			Event: "size", Threads: *threads, Bytes: size, Tokens: ntok, Reps: *reps,
			MedianMs: med, MinMs: durs[0], MaxMs: durs[len(durs)-1],
			MsPerKB: med / (float64(size) / 1024), Spans: nspans,
		}
		for c := range classes {
			row.SpanClass = append(row.SpanClass, c)
		}
		sort.Strings(row.SpanClass)
		fillMem(&row)
		emit(row)
	}
	return 0
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func fillMem(l *benchLine) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		switch k {
		case "VmRSS":
			l.RSSKB = n
		case "VmHWM":
			l.HWMKB = n
		case "RssAnon":
			l.AnonKB = n
		case "RssFile":
			l.FileKB = n
		}
	}
}

// syntheticText builds English prose of about n bytes with obviously fictional personal
// data sprinkled in, so the detector does its usual amount of work.
func syntheticText(rng *rand.Rand, n int) string {
	filler := []string{
		"The meeting moved to the small room on the third floor because the projector in the big one was broken again.",
		"We still need to decide whether the release goes out on Thursday or waits for the translation fixes.",
		"Lunch was the usual soup and bread, and somebody brought a cake for the team's anniversary.",
		"The train was twenty minutes late, so the first agenda item started without half of the people.",
		"Please review the attached draft before Friday and leave comments directly in the document.",
		"The weather forecast promises rain all week, which is good news for the garden and bad news for the picnic.",
		"Our quarterly numbers look stable, although the support queue grew faster than we expected.",
		"I tried the new keyboard shortcuts and they save a surprising amount of time in long sessions.",
	}
	fakes := []string{
		"Contact Jane Testperson at jane.testperson@example.com or +1 202 555 0143.",
		"Ship it to Max Mustermann, 1 Example Street, Springfield, before 12 March 2031.",
		"John Example asked to be called back on 555-0100 after six.",
		"Her account at Example Bank is DE00 0000 0000 0000 0000 00.",
	}
	var b strings.Builder
	for b.Len() < n {
		if rng.Intn(6) == 0 {
			b.WriteString(fakes[rng.Intn(len(fakes))])
		} else {
			b.WriteString(filler[rng.Intn(len(filler))])
		}
		if rng.Intn(5) == 0 {
			b.WriteString("\n")
		} else {
			b.WriteString(" ")
		}
	}
	s := b.String()
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}
