# vulnerable-cli

Deliberately vulnerable Rust CLI for Quarry prove-subsystem testing.

**DO NOT deploy in any real environment.**

## Vulnerabilities (intentional)

1. **Command injection** (`--run-cmd`): passes user input directly to `sh -c`.
2. **Path traversal** (`--read-file`): reads any path without canonicalization.

## Build

```bash
cargo build --release
# Binary: target/release/vulnerable-cli
```

## Usage

```bash
./target/release/vulnerable-cli --run-cmd "echo hello"
./target/release/vulnerable-cli --read-file corpus/project/config.toml
```

## Corpus

`corpus/project/` contains a minimal sample project the CLI can operate against,
used by the Quarry prove sandbox to materialize a realistic working environment.

## Test fixture

`tests/golden/ground_truth/vulnerable-cli.json` defines the expected ground-truth
findings for benchmark scoring.
