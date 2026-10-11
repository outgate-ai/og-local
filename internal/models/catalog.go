package models

type Model struct {
	Name     string
	Repo     string
	Revision string
	Files    []File
}

// DefaultGraph is the privacy-filter graph og-local has always loaded.
const DefaultGraph = "onnx/model_q4f16.onnx"

// graphs names the ONNX graph of catalog entries that don't load DefaultGraph,
// relative to the model directory.
var graphs = map[string]string{
	"openai/privacy-filter-q4": "onnx/model_q4.onnx",
}

// GraphPath returns the graph the detector loads for m.
func (m *Model) GraphPath() string {
	if g, ok := graphs[m.Name]; ok {
		return g
	}
	return DefaultGraph
}

type File struct {
	Path   string
	Size   int64
	SHA256 string
}

func (m Model) TotalSize() int64 {
	var n int64
	for _, f := range m.Files {
		n += f.Size
	}
	return n
}

var catalog = []Model{
	{
		Name:     "openai/privacy-filter",
		Repo:     "openai/privacy-filter",
		Revision: "7ffa9a043d54d1be65afb281eddf0ffbe629385b",
		Files: []File{
			{Path: "onnx/model_q4f16.onnx", Size: 165744},
			{Path: "onnx/model_q4f16.onnx_data", Size: 809061992},
			{Path: "tokenizer.json", Size: 27868174},
			{Path: "tokenizer_config.json", Size: 234},
			{Path: "config.json", Size: 3039},
			{Path: "viterbi_calibration.json", Size: 372},
		},
	},
	// The same model as a 4-bit graph with fp32 activations: on CPUs without fast
	// fp16 (phones, the OG OS emulator) it is as fast as q4f16 and needs ~25% less
	// memory. It shares the snapshot directory with the entry above.
	{
		Name:     "openai/privacy-filter-q4",
		Repo:     "openai/privacy-filter",
		Revision: "7ffa9a043d54d1be65afb281eddf0ffbe629385b",
		Files: []File{
			{Path: "onnx/model_q4.onnx", Size: 160219},
			{Path: "onnx/model_q4.onnx_data", Size: 917120144},
			{Path: "tokenizer.json", Size: 27868174},
			{Path: "tokenizer_config.json", Size: 234},
			{Path: "config.json", Size: 3039},
			{Path: "viterbi_calibration.json", Size: 372},
		},
	},
	{
		Name:     "knowledgator/gliner-pii-small-v1.0",
		Repo:     "knowledgator/gliner-pii-small-v1.0",
		Revision: "d21aad5b4a7ec82b3d0970fd1ac74a12c087d85e",
		Files: []File{
			{Path: "onnx/model.onnx", Size: 326820148},
			{Path: "tokenizer.json", Size: 3583593},
			{Path: "tokenizer_config.json", Size: 21214},
			{Path: "special_tokens_map.json", Size: 694},
			{Path: "gliner_config.json", Size: 4316},
		},
	},
}

func Lookup(name string) (Model, bool) {
	for _, m := range catalog {
		if m.Name == name {
			return m, true
		}
	}
	return Model{}, false
}

func Default() Model { return catalog[0] }

func All() []Model {
	out := make([]Model, len(catalog))
	copy(out, catalog)
	return out
}
