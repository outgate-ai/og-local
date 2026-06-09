package provider

import "strings"

func Route(method, path string) Endpoint {
	if method != "POST" {
		return Endpoint{Kind: Passthrough}
	}
	path = strings.TrimRight(path, "/")
	switch {
	case strings.HasSuffix(path, "/v1/messages"):
		return Endpoint{Kind: Anthropic, Stream: StreamSSE, extract: anthropicExtract}
	case strings.HasSuffix(path, "/v1/chat/completions"):
		return Endpoint{Kind: OpenAIChat, Stream: StreamSSE, extract: openAIChatExtract}
	default:
		return Endpoint{Kind: Passthrough}
	}
}
