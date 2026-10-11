//go:build onnx

package onnx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	ort "github.com/yalue/onnxruntime_go"

	"github.com/outgate-ai/og-local/internal/pii"
)

var initOnce sync.Once

type Detector struct {
	session    *ort.DynamicAdvancedSession
	tok        *tokenizer
	decoder    *pii.Decoder
	inputNames []string
	numLabels  int
	mu         sync.Mutex
}

// Option tunes the ONNX session.
type Option func(*settings)

type settings struct {
	intraOpThreads int
	modelFile      string
	optimizedPath  string
	profilePrefix  string
}

// WithThreads caps the session's intra-op thread pool; 0 keeps the runtime
// default (one thread per physical core).
func WithThreads(n int) Option {
	return func(s *settings) { s.intraOpThreads = n }
}

// WithModelFile picks another graph of the model repo, relative to its
// directory (default onnx/model_q4f16.onnx).
func WithModelFile(rel string) Option {
	return func(s *settings) { s.modelFile = rel }
}

// WithOptimizedModelPath makes the runtime write its optimised graph there, so a
// later session can load it without optimising again.
func WithOptimizedModelPath(path string) Option {
	return func(s *settings) { s.optimizedPath = path }
}

// WithProfiling writes the runtime's per-node profile to <prefix>_<time>.json.
func WithProfiling(prefix string) Option {
	return func(s *settings) { s.profilePrefix = prefix }
}

func New(modelDir, libPath string, opts ...Option) (*Detector, error) {
	var cfg settings
	for _, opt := range opts {
		opt(&cfg)
	}
	var initErr error
	initOnce.Do(func() {
		ort.SetSharedLibraryPath(libPath)
		initErr = ort.InitializeEnvironment()
	})
	if initErr != nil {
		return nil, fmt.Errorf("onnx: init runtime: %w", initErr)
	}

	id2label, err := readLabels(filepath.Join(modelDir, "config.json"))
	if err != nil {
		return nil, err
	}
	biases, err := readBiases(filepath.Join(modelDir, "viterbi_calibration.json"))
	if err != nil {
		return nil, err
	}

	tok, err := loadTokenizer(filepath.Join(modelDir, "tokenizer.json"))
	if err != nil {
		return nil, err
	}

	modelPath := filepath.Join(modelDir, "onnx", "model_q4f16.onnx")
	if cfg.modelFile != "" {
		modelPath = filepath.Join(modelDir, filepath.FromSlash(cfg.modelFile))
	}
	inInfo, outInfo, err := ort.GetInputOutputInfo(modelPath)
	if err != nil {
		tok.close()
		return nil, fmt.Errorf("onnx: read model io: %w", err)
	}
	inputNames := pickInputs(inInfo)
	outputName := outInfo[0].Name

	so, err := sessionOptions(cfg)
	if err != nil {
		tok.close()
		return nil, err
	}
	session, err := ort.NewDynamicAdvancedSession(modelPath, inputNames, []string{outputName}, so)
	if so != nil {
		_ = so.Destroy()
	}
	if err != nil {
		tok.close()
		return nil, fmt.Errorf("onnx: new session: %w", err)
	}

	return &Detector{
		session:    session,
		tok:        tok,
		decoder:    pii.NewDecoder(id2label, biases),
		inputNames: inputNames,
		numLabels:  len(id2label),
	}, nil
}

func sessionOptions(cfg settings) (*ort.SessionOptions, error) {
	if cfg.intraOpThreads <= 0 && cfg.optimizedPath == "" && cfg.profilePrefix == "" {
		return nil, nil
	}
	so, err := ort.NewSessionOptions()
	if err != nil {
		return nil, fmt.Errorf("onnx: session options: %w", err)
	}
	fail := func(what string, err error) (*ort.SessionOptions, error) {
		_ = so.Destroy()
		return nil, fmt.Errorf("onnx: %s: %w", what, err)
	}
	if cfg.intraOpThreads > 0 {
		if err := so.SetIntraOpNumThreads(cfg.intraOpThreads); err != nil {
			return fail("intra-op threads", err)
		}
		if err := so.SetInterOpNumThreads(1); err != nil {
			return fail("inter-op threads", err)
		}
	}
	if cfg.optimizedPath != "" {
		if err := so.SetOptimizedModelFilePath(cfg.optimizedPath); err != nil {
			return fail("optimized model path", err)
		}
	}
	if cfg.profilePrefix != "" {
		if err := so.EnableProfiling(cfg.profilePrefix); err != nil {
			return fail("profiling", err)
		}
	}
	return so, nil
}

func (d *Detector) Close() {
	_ = d.session.Destroy()
	d.tok.close()
}

func (d *Detector) Detect(ctx context.Context, text string) ([]pii.Span, error) {
	if text == "" {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ids, offsets := d.tok.encode(text)
	if len(ids) == 0 {
		return nil, nil
	}

	logits, err := d.run(ids)
	if err != nil {
		return nil, err
	}
	return pii.TrimSpans(text, d.decoder.Decode(logits, offsets)), nil
}

func (d *Detector) run(ids []int64) ([][]float32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	seq := int64(len(ids))
	shape := ort.NewShape(1, seq)
	mask := make([]int64, len(ids))
	for i := range mask {
		mask[i] = 1
	}

	values := make([]ort.Value, len(d.inputNames))
	defer func() {
		for _, v := range values {
			if v != nil {
				_ = v.Destroy()
			}
		}
	}()
	for i, name := range d.inputNames {
		data := ids
		if name == "attention_mask" {
			data = mask
		}
		t, err := ort.NewTensor(shape, data)
		if err != nil {
			return nil, fmt.Errorf("onnx: new input tensor %q: %w", name, err)
		}
		values[i] = t
	}

	outputs := []ort.Value{nil}
	if err := d.session.Run(values, outputs); err != nil {
		return nil, fmt.Errorf("onnx: run: %w", err)
	}
	out := outputs[0].(*ort.Tensor[float32])
	defer func() { _ = out.Destroy() }()

	return reshape(out.GetData(), len(ids), d.numLabels), nil
}

func reshape(flat []float32, seq, labels int) [][]float32 {
	out := make([][]float32, seq)
	for i := 0; i < seq; i++ {
		out[i] = flat[i*labels : (i+1)*labels]
	}
	return out
}

func pickInputs(info []ort.InputOutputInfo) []string {
	names := make([]string, 0, len(info))
	for _, in := range info {
		if in.Name == "input_ids" || in.Name == "attention_mask" {
			names = append(names, in.Name)
		}
	}
	if len(names) == 0 {
		for _, in := range info {
			names = append(names, in.Name)
		}
	}
	sort.SliceStable(names, func(i, j int) bool { return names[i] == "input_ids" })
	return names
}

func readLabels(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("onnx: read config: %w", err)
	}
	var cfg struct {
		ID2Label map[string]string `json:"id2label"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("onnx: parse config: %w", err)
	}
	if len(cfg.ID2Label) == 0 {
		return nil, fmt.Errorf("onnx: config has no id2label")
	}
	labels := make([]string, len(cfg.ID2Label))
	for k, v := range cfg.ID2Label {
		idx, err := strconv.Atoi(k)
		if err != nil || idx < 0 || idx >= len(labels) {
			return nil, fmt.Errorf("onnx: bad id2label key %q", k)
		}
		labels[idx] = v
	}
	return labels, nil
}

func readBiases(path string) (pii.TransitionBiases, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pii.TransitionBiases{}, fmt.Errorf("onnx: read calibration: %w", err)
	}
	return pii.ParseBiases(data, "default")
}

// CountTokens reports how many tokens the model sees for text.
func (d *Detector) CountTokens(text string) int {
	ids, _ := d.tok.encode(text)
	return len(ids)
}
