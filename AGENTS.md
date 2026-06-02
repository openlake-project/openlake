\# AGENTS.md



\## Purpose



This document provides guidance for AI agents and contributors working on the OpenLake codebase.



\## Project Overview



OpenLake is a high-performance distributed object storage system designed for AI and GPU workloads. The project is written in Rust and focuses on minimizing storage-to-GPU latency through technologies such as `io\_uring`, RDMA, GPUDirect Storage, and efficient erasure coding.



Agents should prioritize correctness, performance awareness, and consistency with existing architectural patterns.



\---



\## Repository Structure



\* `crates/` – Core Rust crates that implement storage, networking, runtime, and server functionality.

\* `cli/` – CLI-related components and commands.

\* `benchmarks/` – Performance benchmarking and diagnostics.

\* `docs/` – Documentation, architecture notes, and supporting material.

\* `assets/` – Images and project assets used in documentation.

\* `.github/` – GitHub workflows and repository configuration.



\---



\## Development Guidelines



\### Follow Existing Patterns



\* Match the style and conventions used in nearby code.

\* Reuse existing abstractions before introducing new ones.

\* Keep implementations consistent with the project's performance-oriented design.



\### Keep Changes Focused



\* Prefer small, targeted pull requests.

\* Avoid unrelated refactoring.

\* Modify only the components necessary for the task.



\### Documentation



When behavior changes:



\* Update relevant documentation.

\* Add usage examples when appropriate.

\* Keep README and documentation aligned with implementation.



\---



\## Rust Workflow



Before submitting changes, run:



```bash

cargo fmt

cargo check

cargo test

```



For performance-sensitive changes, consider whether benchmark updates or validation are needed.



\---



\## Pull Requests



Pull requests should:



\* Reference an associated issue when available.

\* Clearly describe the purpose of the change.

\* Remain focused on a single feature or fix.

\* Include documentation updates when applicable.



\---



\## Guidance for AI Agents



1\. Read `README.md` and `CONTRIBUTING.md` before making changes.

2\. Understand the relevant crate and module structure before editing code.

3\. Preserve existing behavior unless the task explicitly requires changes.

4\. Prefer incremental improvements over broad redesigns.

5\. Be mindful of performance implications, especially in storage, networking, and runtime-related code.

6\. Keep generated code idiomatic Rust and compatible with the existing workspace structure.



