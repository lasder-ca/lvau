# Contributing to Lvau

Lvau handles security-sensitive data. Keep changes focused, reviewable, and
covered by tests. Read [AGENTS.md](AGENTS.md),
[docs/FORMAT.md](docs/FORMAT.md), and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before changing cryptographic or
format code.

## Environment

The maintained development environment is WSL2 with Ubuntu 26.04, stable Rust,
Cargo, `rustfmt`, and Clippy. Native Windows and macOS behavior is exercised in
GitHub Actions.

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
rustup component add rustfmt clippy
cargo build --locked --workspace
```

Linux GUI builds also require the X11, Wayland, input, and OpenGL development
packages listed in `.github/workflows/ci.yml`.

## Required checks

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
cargo run --locked --quiet --package lvau-cli -- self-test
```

Run `cargo audit` when available. Do not suppress an advisory without recording
its exact scope, reason, owner, and review deadline in `.cargo/audit.toml`.

## Behavior changes

- Add a failing regression test before fixing a bug.
- Preserve CLI commands, arguments, exit behavior, JSON fields, and automation
  streams unless the SemVer and migration impact is explicitly accepted.
- Do not change the `.lvau` format without a versioned decoder path, bounds and
  tamper tests, `docs/FORMAT.md`, `CHANGELOG.md`, and migration instructions.
- Do not invent cryptographic primitives or describe experimental composition
  as audited, production-proven, unbreakable, or “military-grade.”
- Never put real secrets, credentials, customer data, private endpoints, or
  production identifiers in source, fixtures, output, or documentation.
- Keep `README.md` and `README_ja.md` behaviorally synchronized.

## CLI and GUI

```sh
cargo run --locked --package lvau-cli -- --help
cargo run --locked --release --package lvau-gui
```

Use prompts or private password files instead of password command-line values.
Automation output belongs on stdout; warnings, diagnostics, prompts, and
progress belong on stderr. GUI changes must continue to call `lvau-core` for
cryptography and should be manually checked for progress, cancellation,
keyboard use, narrow layouts, and secret persistence.

## Pull requests and releases

Explain security and compatibility impact, list verification performed, and
call out anything untested. Update all workspace crate versions together for a
release, use SemVer, and add a matching `CHANGELOG.md` section.

Do not push, create tags, publish a GitHub Release, or deploy the API/site
without explicit maintainer authorization. Follow
[docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) only after that approval.

Report sensitive issues through [SECURITY.md](SECURITY.md), never a public
issue.
