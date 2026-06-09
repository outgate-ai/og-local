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

// Resolve decides the upstream the proxy should target and the environment
// overlay the child agent needs, given the user's current environment. If the
// user already set the provider's base-URL variable, that becomes the proxy's
// own upstream (chaining); otherwise the provider default is used. The overlay
// only repoints the agent's base-URL at the loopback proxy, embedding the
// loopback token in the path as /_k/<token>; the agent's own credential
// (env key, OAuth bearer, or login cache) is left untouched so it flows through
// to the upstream. No provider key is required to launch.
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
