package launch

import "testing"

func TestDetectorConfigFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"unset", map[string]string{}, ""},
		{"empty", map[string]string{"OGL_ONNXRUNTIME_LIB": ""}, ""},
		{"set", map[string]string{"OGL_ONNXRUNTIME_LIB": "/opt/onnx/libonnxruntime.so"}, "/opt/onnx/libonnxruntime.so"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := detectorConfigFromEnv(func(k string) string { return c.env[k] })
			if cfg.LibPath != c.want {
				t.Errorf("LibPath = %q, want %q", cfg.LibPath, c.want)
			}
		})
	}
}
