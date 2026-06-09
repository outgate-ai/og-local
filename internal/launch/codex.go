package launch

func renderCodexConfig(baseURL string) string {
	return `profile = "ogl"

[model_providers.ogl]
name = "ogl"
base_url = "` + baseURL + `"
wire_api = "responses"
requires_openai_auth = true

[profiles.ogl]
model_provider = "ogl"
`
}
