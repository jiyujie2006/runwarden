# Contributing

Run the local gates before opening a change:

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
pnpm test
pnpm build
```

Security-boundary changes require tests that prove both allowed and denied behavior.

