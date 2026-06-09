package launch

import (
	"fmt"

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
	UpstreamKey  string
	ChildEnv     map[string]string
}

// Resolve decides the upstream the proxy should target and the environment
// overlay the child agent needs, given the user's current environment. If the
// user already set the provider's base-URL variable, that becomes the proxy's
// own upstream (chaining); otherwise the provider default is used. The overlay
// repoints the agent at loopbackURL and swaps its API key for loopbackToken so
// the agent talks to the proxy instead of the provider.
func Resolve(kind provider.Kind, env map[string]string, loopbackURL, loopbackToken string) (Resolved, error) {
	pe, ok := envFor(kind)
	if !ok {
		return Resolved{}, fmt.Errorf("launch: unsupported provider kind %v", kind)
	}

	key := env[pe.keyVar]
	if key == "" {
		return Resolved{}, fmt.Errorf("launch: %s is not set", pe.keyVar)
	}

	upstream := pe.defaultBase
	if b := env[pe.baseURLVar]; b != "" {
		upstream = b
	}

	overlay := map[string]string{
		pe.baseURLVar: loopbackURL,
		pe.keyVar:     loopbackToken,
	}

	return Resolved{
		UpstreamBase: upstream,
		UpstreamKey:  key,
		ChildEnv:     overlay,
	}, nil
}
