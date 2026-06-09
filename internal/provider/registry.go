package provider

import "strings"

func Route(method, path string) Endpoint {
	if method != "POST" {
		return Endpoint{Kind: Passthrough}
	}
	path = strings.TrimRight(path, "/")
	switch {
	case strings.HasSuffix(path, "/v1/messages"):
		return Endpoint{Kind: Anthropic, Stream: StreamSSE, extract: anthropicExtract, delta: anthropicDelta{}}
	case strings.HasSuffix(path, "/v1/chat/completions"):
		return Endpoint{Kind: OpenAIChat, Stream: StreamSSE, extract: openAIChatExtract, delta: openAIChatDelta{}}
	case strings.HasSuffix(path, "/v1/responses"):
		return Endpoint{Kind: OpenAIResponses, Stream: StreamSSE, extract: openAIResponsesExtract, delta: openAIResponsesDelta{}}
	default:
		return Endpoint{Kind: Passthrough}
	}
}
