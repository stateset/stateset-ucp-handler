# Contributing

Thanks for taking the time to contribute.

## Development Setup

- Install Rust (stable toolchain).
- Install Node.js 20+ if you plan to work on the Node bindings.
- Ensure SQLite development headers are available (`libsqlite3-dev` on Ubuntu).

## Quality Checks

Run these before opening a PR:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

Optional end-to-end demo:

```bash
./demo_test.sh
```

## Pull Requests

- Keep changes focused and explain the why.
- Add or update tests for behavior changes.
- Update `README.md` or `CHANGELOG.md` when user-facing behavior changes.
