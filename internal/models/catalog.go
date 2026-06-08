package models

type Model struct {
	Name     string
	Repo     string
	Revision string
	Files    []File
}

type File struct {
	Path   string
	Size   int64
	SHA256 string
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
