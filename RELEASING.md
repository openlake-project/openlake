# Releasing `openlake-vllm`

The `openlake-vllm` wheel embeds both a native Python extension and the
`openlaked` Linux executable. Release artifacts must therefore be built in the
pinned manylinux environment in `.github/workflows/release-python.yml`, never
on a developer workstation.

## v0.8 scope

- Distribution: `openlake-vllm`
- Version: `0.8.0` (Git tag: `v0.8.0`)
- Artifact: `cp310-abi3-manylinux_2_28_x86_64`
- Supported interpreter family: regular CPython 3.10 and newer
- Transport: non-RDMA local/H2 build

The v0.8 PyPI release does not include an sdist, the RDMA/UCX build, the ExANS
CUDA codec, or the control-plane UI. The current RDMA build skips auditwheel
and has external UCX/verbs/mlx5 runtime requirements; release it separately
only after its packaging and clean-host tests are defined.

## One-time repository setup

Before creating a release tag:

1. Protect `main` and `v*` tags against direct or mutable updates.
2. Create protected GitHub environments named `release-staging`, `testpypi`,
   and `pypi`, and require an approval before each deployment. Enable
   prevention of self-review after the repository has a second release
   maintainer; at present the organization has only one member.
3. Add Trusted Publishers on TestPyPI and PyPI with these exact values:

   - Owner: `openlake-project`
   - Repository: `openlake`
   - Workflow: `release-python.yml`
   - Environment: `testpypi` or `pypi`, respectively

No long-lived PyPI token is required by the workflow.

## Release procedure

1. Merge the version and release-workflow PR only after its Linux package job
   passes.
2. Update local `main` with a fast-forward pull and verify that it is clean.
3. Create and push an annotated tag:

   ```bash
   git switch main
   git pull --ff-only origin main
   git status --short
   git tag -a v0.8.0 -m "OpenLake v0.8.0"
   git push origin v0.8.0
   ```

4. The tag workflow builds one wheel, audits both ELF files, validates package
   contents and versions, and installs on CPython 3.10 and 3.14. A pinned
   minimal Debian image checks imports and ELF dependencies with no build-time
   packages available to hide a missing runtime library; the Linux host then
   runs the packaged daemon and a local KV put/get round trip with `io_uring`.
5. Download that run's `openlake-vllm-*` artifact. On the staging H100, install
   the wheel by file path and run the local-mode CUDA/vLLM miss → store → hit
   test. Verify its SHA-256 against the included `SHA256SUMS`. In the protected
   environment approval record, record that SHA-256 and link the retained
   staging test output, then approve the `release-staging` job.
6. Approve `testpypi`. The workflow uploads the same wheel, downloads it again,
   and compares it byte-for-byte with the candidate.
7. Approve `pypi` only after TestPyPI verification succeeds. The production job
   checks the digest and confirms that the version is still unused immediately
   before upload.
8. Verify a clean production install by exact version and confirm the published
   attestation on PyPI.

Never rebuild between validation and publication, publish from macOS, use
`--skip-existing`, or upload a wheel manually. PyPI release files are
immutable.
