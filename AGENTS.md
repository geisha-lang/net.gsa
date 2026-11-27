# AGENTS.md — Maintenance & PR Rules (`net.gsa`)

Unified networking stack for Geisha (`ByteStream`, OpenSSL TLS 1.2/1.3, HTTP/HTTPS, and RFC 6455 WebSocket `ws://`/`wss://`).

## Branch, Worktree & Pull Request Workflow (No Direct Push to `main`)

`main` is protected on GitHub and gated by `Test (linux-x86_64)` and `Test (darwin-arm64)`.

1. **Never edit or commit directly on `main` in `~/code/net.gsa`**:
   - Keep `~/code/net.gsa` strictly on clean `main` (`git pull --ff-only`).
   - Always open an isolated `git worktree` on a feature/fix branch (`git -C ~/code/net.gsa worktree add -b <type>/<topic> <workspace>/net-wt origin/main`).
2. **Open a Pull Request & wait for CI before merging**:
   - Push your branch (`git push -u origin <branch>`), open a PR via `gh pr create`, and merge only after both `Test (linux-x86_64)` and `Test (darwin-arm64)` pass.
   - Do not self-merge breaking public API changes without user review.

## Engineering Rules & Verification

- Keep `net.ws` and `net.http` generic over `concept ByteStream` (`net.stream`) so plain `ws://` / `http://` remain pure Geisha without requiring OpenSSL, while `net.tls` / `net.wss` / `https*` layer TLS cleanly on top.
- Use `[[target.native.when]]` in `geisha.toml` (`os = "macos"` Homebrew OpenSSL 3; `os = "linux"` `pkg_config = "openssl"`) rather than hardcoding macOS-only paths.
- Verify locally before opening a PR:
  ```sh
  MACOSX_DEPLOYMENT_TARGET=14.0 geisha test
  ```
