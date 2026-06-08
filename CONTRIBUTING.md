# Contributing to og-local

Thank you for your interest in contributing.

## Setup

```sh
git clone https://github.com/outgate-ai/og-local
cd og-local
make setup    # installs git hooks; idempotent
make ci       # lint + tests + coverage + build
```

## Development loop

- Write Go in any package under `internal/`.
- Add tests next to source as `*_test.go`. The aspiration is 100% line coverage on every package under `internal/`; the merge gate enforces that a PR's coverage must not regress versus `main`.
- Run `make test` for the fast loop and `make test-coverage` before pushing.
- Commits use the conventional-commit prefixes (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`, `perf:`, `build:`, `ci:`, `style:`, `revert:`). CI enforces the format.

## Submitting changes

- Open a PR against `main`.
- One review is required.
- CI must be green (lint, the cross-OS test and build matrix, goreleaser-check, commit-lint).
- Squash-merge keeps `main` history linear.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report incidents to support@outgate.ai.
