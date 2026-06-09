package launch

import (
	"fmt"
	"strings"

	"github.com/outgate-ai/og-local/internal/provider"
)

type providerEnv struct {
	keyVar      string
	baseURLVar  string
	defaultBase string
}

func envFor(kind provider.Kind) (providerEnv, bool) {
	switch kind {
	case provider.Anthropic:
		return providerEnv{
			keyVar:      "ANTHROPIC_API_KEY",
			baseURLVar:  "ANTHROPIC_BASE_URL",
			defaultBase: "https://api.anthropic.com",
		}, true
	case provider.OpenAIChat:
		return providerEnv{
			keyVar:      "OPENAI_API_KEY",
			baseURLVar:  "OPENAI_BASE_URL",
			defaultBase: "https://api.openai.com",
		}, true
	default:
		return providerEnv{}, false
	}
}

type Resolved struct {
	UpstreamBase string
	ChildEnv     map[string]string
}

// Resolve returns the upstream base URL (a pre-set provider base-URL var, else
// the provider default) and the child env overlay, which points only the
// provider's base-URL var at loopbackURL + /_k/<token>. The agent's own
// credentials are left untouched and no provider key is required.
func Resolve(kind provider.Kind, env map[string]string, loopbackURL, loopbackToken string) (Resolved, error) {
	pe, ok := envFor(kind)
	if !ok {
		return Resolved{}, fmt.Errorf("launch: unsupported provider kind %v", kind)
	}

	upstream := pe.defaultBase
	if b := env[pe.baseURLVar]; b != "" {
		upstream = b
	}

	overlay := map[string]string{
		pe.baseURLVar: strings.TrimRight(loopbackURL, "/") + "/_k/" + loopbackToken,
	}

	return Resolved{
		UpstreamBase: upstream,
		ChildEnv:     overlay,
	}, nil
}
