# og-local

> A local privacy proxy for coding agents.

[![CI](https://github.com/outgate-ai/og-local/actions/workflows/ci.yml/badge.svg)](https://github.com/outgate-ai/og-local/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/outgate-ai/og-local/graph/badge.svg)](https://codecov.io/gh/outgate-ai/og-local)
[![Go Report Card](https://goreportcard.com/badge/github.com/outgate-ai/og-local)](https://goreportcard.com/report/github.com/outgate-ai/og-local)
[![License: BSL 1.1](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](LICENSE)

When your coding agent reads a file, the file gets shipped to a third-party LLM. Often that's fine. The file is open-source, or your team has a vendor agreement that covers it. Sometimes it isn't: a `.env` slipped into a diff, a customer email in a test fixture, an API key in a comment, a stack trace from a private service.

**og-local** is a single binary that runs on your machine, intercepts the API calls your agent makes, detects PII and secrets in the prompt body before it leaves localhost, swaps them with opaque placeholders, forwards the redacted prompt upstream, and transparently restores the originals in the response. The agent never sees the difference. The upstream provider never sees the secrets.

Detection runs in-process via the [`openai/privacy-filter`](https://huggingface.co/openai/privacy-filter) ONNX model. There's no cloud round-trip and no network call to anywhere except the upstream provider you were already calling. The model downloads once on first run; everything after that is local.

## Status

**v0.1 is under active development.** This branch ships the project skeleton: build, lint, test, coverage, CI. The proxy itself lands across milestones 1-7 ahead of v0.1.0. If you want to track progress, watch the repo or follow the release notes.

## Install

```sh
go install github.com/outgate-ai/og-local/cmd/ogl@latest
```

Or grab a signed pre-built binary from [Releases](https://github.com/outgate-ai/og-local/releases) once v0.1.0 ships. Linux, macOS, and Windows are supported on amd64 and arm64 (no windows/arm64 yet, because ONNX Runtime upstream doesn't publish one).

## Quickstart

> Coming in v0.1.0. The intended shape is:

```sh
# Anthropic-flavored agent
ogl claude "fix the failing test in cmd/server"

# OpenAI-flavored agent
ogl codex --model gpt-5.1 "review this PR"
```

`ogl` starts a local proxy on a random loopback port, points the child agent at it, and `exec`s the agent as a child process. Your full environment forwards to the child, and the agent keeps using whatever credentials it already has — `ogl` only redirects where the requests go. When the agent exits, `ogl` exits.

Most agents are redirected with their `*_BASE_URL` env var. Codex ignores that variable, so `ogl codex` instead writes a dedicated provider config under `~/.codex/ogl` (via `CODEX_HOME`) pointing Codex at the proxy; your own `~/.codex/config.toml` is left untouched.

`ogl codex` works with both Codex sign-in modes. With an API key (`OPENAI_API_KEY`, or `auth_mode = "apikey"` in `~/.codex/auth.json`) it forwards to `api.openai.com`. With a ChatGPT subscription login it forwards to `chatgpt.com/backend-api/codex`, the endpoint that login's token is scoped for — sending those requests to `api.openai.com` would fail. The mode is read from `~/.codex/auth.json`, with `OPENAI_API_KEY` taking precedence; either way the proxy forwards your existing Codex credentials and redacts the prompt body in between.

No daemon, no PID file, no global state.

## How it works (one paragraph)

For each outbound request, `ogl` extracts the user-supplied content fields (`messages[].content`, `system`), runs the ONNX-based PII detector locally over each field independently, replaces detected spans with opaque placeholders (`OG_PRIVATE_EMAIL_<hex>`, `OG_SECRET_<hex>`, and the like), forwards the rewritten body upstream, and inverts the substitution on the response, including streaming responses where placeholders may split across SSE events. Request frame fields (`model`, `temperature`, tool schemas, ids) are passed through unchanged.

## Supported providers (planned for v0.1)

- OpenAI Chat Completions (`/v1/chat/completions`), streaming and non-streaming
- OpenAI Responses (`/v1/responses`)
- Anthropic Messages (`/v1/messages`), streaming and non-streaming, including tool use
- AWS Bedrock and GCP Vertex: passthrough with SigV4 / ADC, redaction applied to the same provider-native shapes above

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The TL;DR:

```sh
git clone https://github.com/outgate-ai/og-local
cd og-local
make setup    # one-time: installs git hooks
make ci       # lint + tests + coverage + build
```

PRs against `main` require a passing CI run and one review. Conventional-commits subject lines are CI-enforced.

## License

Business Source License 1.1, converting automatically to Apache 2.0 on **2030-06-08**. See [LICENSE](LICENSE) for the precise terms.

In plain English: free to use, modify, and redistribute, including in commercial software. The one restriction until the change date is that you can't offer og-local (or a substantially-similar service) to third parties as a hosted multi-tenant service. After the change date, that restriction lifts and it's just Apache 2.0.

Licensor: Gatewise UG (haftungsbeschränkt). For commercial alternatives or questions: support@outgate.ai.
