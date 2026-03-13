# storecold

`storecold` is a Linux-first Rust backup tool that watches configured paths,
encrypts file contents client-side, batches uploads into pack objects, and
publishes a hot index alongside cold data in S3 or Azure Blob.

## Current capabilities

- YAML config at `~/.storecold.yaml`
- Long-running daemon mode with filesystem notifications and periodic rescans
- Client-side encryption using a passphrase or local key file
- SHA-512 content addressing and keyed path hashing
- Version retention on content change
- Metadata-only reuse when a file moves without changing content
- Separate hot index publishing for catalog and encrypted manifests
- S3 and Azure Blob upload backends

## Commands

```bash
storecold init
storecold status
storecold sync
storecold daemon
```

## Developer tasks

This repo uses `just` as its command runner.

Install the local tooling:

```bash
brew install just gitleaks
cargo install --locked cargo-deny
```

Common tasks:

```bash
just build
just release
just test
just deny
just secrets
just sec
just ci
```

`just build` now runs the security checks before compiling.
`just deny` runs `cargo-deny` with the repo's [`deny.toml`](deny.toml).
`just secrets` runs `gitleaks` against the git history, preferring the newer
`gitleaks git` subcommand but falling back to `detect` for older installs.

## Credentials

Passphrase mode expects the environment variable configured in `key_source`.
The sample config uses `STORECOLD_PASSPHRASE`.

Azure Blob can authenticate with either:

- `AZURE_STORAGE_ACCESS_KEY`
- a full connection string environment variable

S3 uses the standard AWS SDK credential chain.

## Daemon usage

The intended production model is to run `storecold daemon` under `systemd`.
A starter unit file is provided in `contrib/systemd/storecold.service`.
Copy `contrib/systemd/storecold.env.example` to
`/etc/storecold/storecold.env`, fill in the secrets, and set mode `0600`.
