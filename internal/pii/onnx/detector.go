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

func New(modelDir, libPath string) (*Detector, error) {
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
	inInfo, outInfo, err := ort.GetInputOutputInfo(modelPath)
	if err != nil {
		tok.close()
		return nil, fmt.Errorf("onnx: read model io: %w", err)
	}
	inputNames := pickInputs(inInfo)
	outputName := outInfo[0].Name

	session, err := ort.NewDynamicAdvancedSession(modelPath, inputNames, []string{outputName}, nil)
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
