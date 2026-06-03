# AGENTS.md

## Project Overview

OpenLake is a high-performance distributed object storage system designed for AI and GPU workloads.

The project is written in Rust and focuses on low-latency, high-throughput data movement using technologies such as:

* io_uring
* RDMA
* GPUDirect Storage
* Erasure Coding

Contributors should understand the surrounding architecture before making large changes.

---

## Repository Structure

* `crates/` - Core Rust crates and services
* `cli/` - CLI-related functionality
* `benchmarks/` - Performance benchmarking tools
* `docs/` - Documentation and architecture references
* `assets/` - Images and static assets
* `.github/` - CI workflows and repository automation

---

## Build Commands

Build the entire workspace:

```bash
cargo build --workspace
```

Build optimized release binaries:

```bash
cargo build --release --workspace
```

---

## Testing

Run tests before submitting changes:

```bash
cargo test
```

Validate compilation:

```bash
cargo check
```

Format code:

```bash
cargo fmt
```

Run linting if available:

```bash
cargo clippy --all-targets --all-features
```

---

## Code Style Guidelines

* Follow existing Rust conventions.
* Keep changes small and focused.
* Reuse existing abstractions where possible.
* Avoid introducing duplicate functionality.
* Prefer readability and maintainability.

---

## Documentation

When changing behavior:

* Update relevant documentation.
* Add examples where appropriate.
* Keep documentation aligned with implementation.

---

## Pull Requests

Before opening a PR:

1. Run formatting and tests.
2. Verify the workspace builds successfully.
3. Keep the PR focused on a single feature or fix.
4. Reference related issues when applicable.

Suggested commit format:

```text
docs: update AGENTS.md guidance
fix: resolve storage issue
feat: add new CLI command
```

---

## Guidance for AI Agents

1. Read `README.md` and `CONTRIBUTING.md` before making changes.
2. Inspect the relevant crate before editing code.
3. Preserve existing behavior unless explicitly instructed otherwise.
4. Avoid large-scale refactors in unrelated code.
5. Consider performance implications for storage, networking, and runtime paths.
6. Update documentation alongside code changes.
