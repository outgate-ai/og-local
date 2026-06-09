package launch

import (
	"strings"
	"testing"
)

func TestRenderCodexConfig(t *testing.T) {
	base := "http://127.0.0.1:5000/_k/ogl_live_tok/v1"
	got := renderCodexConfig(base)

	wants := []string{
		`profile = "ogl"`,
		`[model_providers.ogl]`,
		`name = "ogl"`,
		`base_url = "` + base + `"`,
		`wire_api = "responses"`,
		`requires_openai_auth = true`,
		`[profiles.ogl]`,
		`model_provider = "ogl"`,
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("config missing %q in:\n%s", w, got)
		}
	}
}

func TestRenderCodexConfigEmbedsBaseURLVerbatim(t *testing.T) {
	base := "http://127.0.0.1:65535/_k/abc123/v1"
	if !strings.Contains(renderCodexConfig(base), `base_url = "`+base+`"`) {
		t.Errorf("base_url not embedded verbatim")
	}
}
