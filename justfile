set shell := ["sh", "-eu", "-c"]

default:
  @just --list --unsorted

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

check:
  cargo check --all-targets --all-features

build: sec
  cargo build

release:
  cargo build --release

test:
  cargo test

deny:
  cargo deny check bans advisories sources

secrets:
  if gitleaks git --help >/dev/null 2>&1; then \
    gitleaks git . --redact; \
  else \
    gitleaks detect --source . --redact; \
  fi

sec: deny secrets

ci: fmt-check check test sec
