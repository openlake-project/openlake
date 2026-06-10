.. OpenLake Windows Developer Setup Guide
.. ========================================
.. This document is part of the Developer Guide → Environment Setup section.

OpenLake: Windows Developer Setup Guide
========================================

| **Audience:** First-time contributors on Windows
| **Workflow:** Docker + WSL2 + VS Code Dev Containers

.. contents:: Table of Contents
   :depth: 3
   :local:
   :backlinks: none

----

Introduction
------------

OpenLake is a distributed storage engine built in Rust. Its development and
test infrastructure is Linux-oriented: CI pipelines run on Linux, integration
tests assume POSIX semantics, and several build-time scripts rely on GNU
tooling that behaves differently — or is simply unavailable — on native Windows.

To align closely with the Linux-based CI and runtime environment, the
recommended approach for Windows contributors is to develop **inside a Linux
container** and interact with it through VS Code's Dev Containers extension.
Your editor, Git client, and browser stay on Windows; the compiler, test
runner, and source tree all live inside Docker.

Why containers instead of native Windows Rust?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- The MSVC toolchain targets ``x86_64-pc-windows-msvc`` and cannot produce or
  run the Linux binaries — including ``openlaked`` — used in integration tests.
- Line-ending differences (``CRLF`` vs. ``LF``) routinely break shell scripts
  and Cargo post-build hooks when source files live on the Windows file system.
- Case-insensitive NTFS and Windows-style path separators cause subtle test
  failures that are difficult to reproduce or diagnose from a CI log.
- The container environment is near-identical to CI, which dramatically
  shortens the "works on my machine" feedback loop.

.. note::

   If you are on macOS or Linux you do not need this guide. Refer to the
   standard ``CONTRIBUTING.md`` instead.

----

Prerequisites
-------------

Before you begin, install the following software **in the order listed**.
Later steps depend on earlier ones — in particular, Docker Desktop must be
installed and WSL2 must be enabled before you open VS Code.

.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Tool
     - Purpose
     - Minimum Version
   * - Docker Desktop
     - Runs Linux containers on Windows via WSL2
     - 4.x
   * - WSL2 (Windows Subsystem for Linux)
     - Kernel backend used by Docker Desktop
     - Kernel 5.15+
   * - Ubuntu (WSL2 distro)
     - Base Linux environment
     - 22.04 LTS
   * - Visual Studio Code
     - Primary editor
     - 1.85+
   * - Dev Containers extension
     - Attaches VS Code to a running container
     - Latest
   * - Git for Windows
     - Repository management on the host
     - 2.40+

.. note::

   You do **not** need to install Rust, Cargo, or any build tools on your
   Windows host. All compilation, testing, and formatting happens inside the
   container. A host-side Rust installation can actually cause PATH conflicts
   inside WSL2 — see the troubleshooting section for details.

----

Installing Docker Desktop and Enabling WSL2
-------------------------------------------

Step 1 — Enable WSL2 on Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Open **PowerShell as Administrator** and run:

.. code-block:: powershell

   wsl --install

This installs the WSL2 kernel and the default Ubuntu distribution.
Reboot when prompted.

.. warning::

   If you already have WSL installed, it may be running WSL1. After rebooting,
   verify and enforce WSL2 as the default:

.. code-block:: powershell

   wsl --set-default-version 2

Expected output::

   For information on key differences with WSL 1 please visit
   https://aka.ms/wsl2
   The operation completed successfully.

To list installed distributions and confirm their WSL version:

.. code-block:: powershell

   wsl --list --verbose

Expected output::

     NAME            STATE           VERSION
   * Ubuntu-22.04    Running         2

If Ubuntu did not install automatically, add it explicitly:

.. code-block:: powershell

   wsl --install -d Ubuntu-22.04

Step 2 — Install Docker Desktop
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Download the installer from https://www.docker.com/products/docker-desktop/.
2. Run the installer. On the *Configuration* screen, make sure
   **Use WSL2 instead of Hyper-V** is checked.
3. Complete the installation and launch Docker Desktop.

Step 3 — Verify Docker Desktop uses WSL2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In Docker Desktop go to **Settings → General** and confirm that
*Use the WSL2 based engine* is enabled.

Then open **Settings → Resources → WSL Integration** and toggle on the Ubuntu
distro you installed. Without this step, Docker commands issued from inside
WSL2 will not reach the Docker daemon.

Step 4 — Verify Docker is working
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Open a PowerShell (no elevation required) or Windows Terminal and run:

.. code-block:: powershell

   docker version

Expected output (versions will vary)::

   Client:
    Cloud integration: v1.0.35+desktop.10
    Version:           26.1.1
    API version:       1.45
    OS/Arch:           windows/amd64

   Server: Docker Desktop 4.30.0 (149282)
    Engine:
     Version:          26.1.1
     API version:      1.45 (minimum version 1.24)
     OS/Arch:          linux/amd64

The **Server OS/Arch** line must read ``linux/amd64``. If it reads
``windows/amd64``, the engine is not in Linux container mode — right-click the
Docker Desktop tray icon and select *Switch to Linux containers*.

----

Pulling and Running a Linux Container
--------------------------------------

Pull the Ubuntu 22.04 image
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   docker pull ubuntu:22.04

Expected output::

   22.04: Pulling from library/ubuntu
   7b1a6ab2e44d: Pull complete
   Digest: sha256:0bced47fffa3361afa981854fcabcd4577cd43cebbb808cea2b1f33a3dd7f508
   Status: Downloaded newer image for ubuntu:22.04
   docker.io/library/ubuntu:22.04

Run an interactive container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For day-to-day development you will use the Dev Container defined in the
repository (see the VS Code section below). The manual workflow below is
useful for one-off debugging or exploring the base image:

.. code-block:: bash

   docker run -it --name openlake-dev ubuntu:22.04 bash

You will land at a root shell inside the container::

   root@3f7a2c91b4e0:/#

Type ``exit`` to leave without deleting the container. To resume it later:

.. code-block:: bash

   docker start -ai openlake-dev

.. tip::

   For normal contributor work you rarely need to manage containers manually.
   The ``devcontainer`` workflow described later handles container lifecycle
   automatically, including volume mounts and extension installation.

----

Cloning OpenLake Inside the Linux Environment
---------------------------------------------

All source code must live inside the Linux container or WSL2 file system.
**Do not clone into a Windows path** (``C:\Users\...``). The Windows NTFS
mount (``/mnt/c/``) is accessible from inside WSL2 and containers, but I/O
through that path is significantly slower and does not support all POSIX
operations that the build system requires. When in doubt: if the path starts
with ``/mnt/c/``, move it.

Option A — Clone inside WSL2 Ubuntu (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Open a WSL2 terminal (search *Ubuntu* in the Start Menu):

.. code-block:: bash

   # Move to your home directory inside WSL2
   cd ~

   # Clone your fork — replace YOUR_USERNAME with your GitHub handle
   git clone https://github.com/openlake-project/openlake.git

   # Enter the project directory
   cd openlake

Expected output::

   Cloning into 'openlake'...
   remote: Enumerating objects: 18243, done.
   remote: Counting objects: 100% (18243/18243), done.
   remote: Compressing objects: 100% (5120/5120), done.
   Receiving objects: 100% (18243/18243), 24.31 MiB | 9.47 MiB/s, done.
   Resolving deltas: 100% (11872/11872), done.

Option B — Clone directly inside a running container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you started the container manually in the previous section:

.. code-block:: bash

   # Inside the container — install git first
   apt-get update && apt-get install -y git

   git clone https://github.com/openlake-project/openlake.git
   cd openlake

.. note::

   Changes made inside an ephemeral container (one started without a named
   volume) are lost when the container is removed. Use a named volume or the
   Dev Container workflow to ensure your work persists across restarts.

----

Installing Rust Inside the Linux Environment
---------------------------------------------

All commands in this section run inside your WSL2 Ubuntu terminal or the
container shell — not in PowerShell or Command Prompt.

Step 1 — Install system dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   sudo apt-get update
   sudo apt-get install -y \
       build-essential \
       curl \
       pkg-config \
       libssl-dev \
       git

Step 2 — Install Rust via rustup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

The installer will ask you to choose an installation type. Accept the default
by pressing ``Enter``::

   1) Proceed with installation (default)
   2) Customize installation
   3) Cancel installation

   >

Expected completion output::

   info: installing component 'rustc'
   info: installing component 'rust-std'
   info: installing component 'cargo'
   info: installing component 'rust-docs'

     stable-x86_64-unknown-linux-gnu installed - rustc 1.78.0 (9b00956e5 2024-04-29)

   Rust is installed now. Great!

   To get started you may need to restart your current shell.
   Run the following in your shell then log in again:
   source "$HOME/.cargo/env"

Step 3 — Activate the Rust environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   source "$HOME/.cargo/env"

To make this permanent so that every new shell has ``cargo`` available,
add the source line to your shell profile:

.. code-block:: bash

   echo 'source "$HOME/.cargo/env"' >> ~/.bashrc

Step 4 — Verify the installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   rustc --version
   cargo --version

Expected output::

   rustc 1.78.0 (9b00956e5 2024-04-29)
   cargo 1.78.0 (54d8815d0 2024-03-26)

Step 5 — Install the stable toolchain components used by OpenLake
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   rustup component add clippy rustfmt

These are required: ``rustfmt`` enforces code style and ``clippy`` is run as
part of CI. Both commands will fail if these components are absent.

----

Building OpenLake
-----------------

All commands below run from the root of the cloned repository inside the
Linux environment. If you are not already there:

.. code-block:: bash

   cd ~/openlake

Compile the project
~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   cargo build

On the first run, Cargo downloads and compiles all dependencies from scratch.
This can take several minutes. Subsequent incremental builds are much faster.
Expected tail of output::

   Compiling openlake-storage v0.1.0 (/root/openlake)
   Compiling openlake v0.1.0 (/root/openlake)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3m 14s

Run the test suite
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   cargo test

All tests must pass before opening a pull request. Expected tail of output::

   running 142 tests
   test storage::segment::tests::test_segment_write ... ok
   test storage::index::tests::test_btree_lookup ... ok
   test cluster::replication::tests::test_quorum_write ... ok
   ...
   test result: ok. 142 passed; 0 failed; 0 ignored; 0 measured; 0 filtered

Format the code
~~~~~~~~~~~~~~~~

OpenLake enforces ``rustfmt`` formatting. Run this before every commit:

.. code-block:: bash

   cargo fmt

To check for formatting violations without modifying files (the same check CI
runs):

.. code-block:: bash

   cargo fmt -- --check

Run the linter
~~~~~~~~~~~~~~~

.. code-block:: bash

   cargo clippy -- -D warnings

A clean run produces no output. Any warning is treated as an error in CI, so
address all Clippy output before pushing.

Build the release binary
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   cargo build --release

The optimised daemon binary is placed at ``target/release/openlaked``. Use
this path when running integration tests locally or smoke-testing a release
build:

.. code-block:: bash

   ./target/release/openlaked --version

----

Opening the Codebase in VS Code via Dev Containers
---------------------------------------------------

This section describes the recommended editing workflow: VS Code runs on
Windows but reads, edits, and executes code entirely inside the Linux
container. The result is a native Linux development experience with a familiar
Windows UI.

Install the Dev Containers extension
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Open VS Code.
2. Press ``Ctrl+Shift+X`` to open the Extensions panel.
3. Search for ``Dev Containers`` (publisher: Microsoft).
4. Click **Install**.

Alternatively, install from the command line:

.. code-block:: powershell

   code --install-extension ms-vscode-remote.remote-containers

Opening the repository in a Dev Container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The OpenLake repository ships a ``devcontainer.json`` configuration in the
``.devcontainer/`` directory. This file tells VS Code which Docker image to
use, which extensions to install inside the container, and which ports to
forward to the Windows host.

**From VS Code:**

1. Press ``Ctrl+Shift+P`` to open the Command Palette.
2. Type ``Dev Containers: Open Folder in Container`` and press ``Enter``.
3. Navigate to the location where you cloned OpenLake **inside WSL2**
   (e.g. ``\\wsl.localhost\Ubuntu\home\yourname\openlake``).
4. VS Code reopens, builds (or pulls) the container image, and installs
   the configured extensions inside the container.

The status bar at the bottom-left of VS Code changes to::

   >< Dev Container: OpenLake Dev

This confirms the editor is connected to the container and that all tools —
including ``rust-analyzer`` and ``cargo`` — are running on Linux.

**From the WSL2 terminal (fastest path):**

.. code-block:: bash

   # Inside WSL2, from the openlake directory
   code .

VS Code detects ``devcontainer.json`` and prompts you to reopen in a
container. Click **Reopen in Container**.

Working inside the container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once connected, everything works as it would in a native Linux environment:

- The integrated terminal (``Ctrl+` ``) opens a shell **inside the
  container**, not on Windows. Run ``cargo build``, ``cargo test``,
  and ``git`` commands directly here.
- File edits in the VS Code editor are written into the Linux file system
  inside the container.
- IntelliSense, go-to-definition, and inline diagnostics use the
  ``rust-analyzer`` extension running inside the container, so they resolve
  the correct Linux paths, crate targets, and ``openlaked`` binary.
- Port forwarding is handled automatically. If ``openlaked`` starts a local
  server on port ``8080`` inside the container, VS Code makes it reachable at
  ``localhost:8080`` on Windows without any extra configuration.

Rebuilding the container
~~~~~~~~~~~~~~~~~~~~~~~~~

If you update ``devcontainer.json`` or the base ``Dockerfile``, rebuild via
the Command Palette:

.. code-block:: none

   Dev Containers: Rebuild Container

----

Common Windows Setup Issues and Fixes
---------------------------------------

Every issue listed here has been reported by real contributors. If you hit
something not covered here, please open an issue — your pain is someone else's
future fix.

1. ``cargo``: command not found
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptom:**

.. code-block:: bash

   $ cargo build
   bash: cargo: command not found

**Cause:** The Rust environment has not been sourced in the current shell
session. This is most common in new terminal tabs or after a container restart.

**Fix:**

.. code-block:: bash

   source "$HOME/.cargo/env"

To make this automatic, confirm the following line is in ``~/.bashrc``
(or ``~/.zshrc`` if you use Zsh):

.. code-block:: bash

   source "$HOME/.cargo/env"

Then reload the shell without closing the terminal:

.. code-block:: bash

   exec bash

2. PATH issues — tools installed but not found
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptom:** A tool you just installed (e.g. ``rustup``, a Cargo sub-command)
is not found even though installation reported success.

**Cause:** The binary was written to ``~/.cargo/bin`` or ``~/.local/bin``,
neither of which is in ``PATH`` for non-login shells inside Docker containers.

**Fix:** Inspect and extend the current PATH:

.. code-block:: bash

   echo $PATH
   export PATH="$HOME/.cargo/bin:$PATH"

Add the export to ``~/.bashrc`` to make it permanent across sessions.

3. Disk space errors during build
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptom:**

.. code-block:: none

   error: failed to write to disk: No space left on device

**Cause:** Docker Desktop allocates a fixed virtual disk to the WSL2 backend.
The default is 64 GB, which fills up quickly once Rust starts accumulating
build artefacts across multiple projects.

**Fix:**

1. In Docker Desktop go to **Settings → Resources → Advanced** and increase
   the **Disk image size** to 100 GB or more.
2. Clear the Cargo build cache if the disk is already full:

   .. code-block:: bash

      cargo clean               # removes the target/ directory
      rm -rf ~/.cargo/registry/cache

3. For finer-grained cache management, use ``cargo-cache``:

   .. code-block:: bash

      cargo install cargo-cache
      cargo cache --autoclean

4. ``rustup`` installation fails or hangs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptom:** The ``curl | sh`` command hangs indefinitely, or exits with a
TLS handshake or certificate error.

**Causes and fixes:**

- **Corporate proxy:** Export proxy variables before running the installer:

  .. code-block:: bash

     export HTTPS_PROXY=http://proxy.example.com:3128
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

- **Outdated CA certificates inside the container:**

  .. code-block:: bash

     apt-get install -y ca-certificates
     update-ca-certificates

- **Interrupted or partial download:** Clear any leftover state and retry:

  .. code-block:: bash

     rm -rf ~/.rustup ~/.cargo
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

5. GNU toolchain vs. MSVC confusion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptom:**

.. code-block:: none

   error[E0463]: can't find crate for `std`
   = note: the `x86_64-pc-windows-msvc` target may not be installed

**Cause:** Rust was installed on the **Windows host** and the Windows
``PATH`` is leaking into the WSL2 shell or container. The Windows Rust
installation defaults to the ``x86_64-pc-windows-msvc`` target, which cannot
compile Linux binaries or produce the ``openlaked`` daemon.

**Fix:**

1. Confirm you are running inside Linux, not Windows:

   .. code-block:: bash

      uname -a
      # Expected: Linux ... x86_64 GNU/Linux

2. Check which ``rustc`` is active:

   .. code-block:: bash

      which rustc
      # Should be: /root/.cargo/bin/rustc  (or ~/.cargo/bin/rustc)
      # Must NOT be: /mnt/c/Users/...

3. If the Windows ``rustc`` is winning, disable Windows PATH inheritance in
   WSL2 by editing ``/etc/wsl.conf`` inside your Ubuntu distro:

   .. code-block:: ini

      [interop]
      appendWindowsPath = false

   Then restart WSL2 from PowerShell:

   .. code-block:: powershell

      wsl --shutdown

   Reopen your Ubuntu terminal and verify with ``which rustc`` again.

6. Line ending issues (``\r\n`` vs. ``\n``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptom:** Shell scripts fail with ``/bin/bash^M: bad interpreter``, or
``cargo fmt -- --check`` reports changes on every file immediately after a
clean checkout.

**Cause:** Git checked out files with Windows line endings (``CRLF``) because
``core.autocrlf=true`` was set on the Windows Git client, or the files were
copied from a Windows path into WSL2.

**Fix:** Disable auto line-ending conversion inside WSL2 or the container,
then force a clean re-checkout:

.. code-block:: bash

   # Inside the repository
   git config core.autocrlf false

   # Re-checkout all files with correct line endings
   git rm --cached -r .
   git reset --hard

OpenLake ships a ``.gitattributes`` that enforces ``LF`` for all tracked text
files. As long as you clone inside WSL2 with ``core.autocrlf=false``, you
should not encounter this issue on a fresh clone.

7. Windows file system slowness (``/mnt/c/``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptom:** ``cargo build`` takes 10+ minutes even for small incremental
changes. Filesystem operations in the ``target/`` directory feel sluggish.

**Cause:** The repository lives on the Windows NTFS file system, accessible
from WSL2 at ``/mnt/c/``. Every file operation crosses the WSL2 boundary,
which adds significant overhead. Rust's incremental compilation is especially
sensitive to this because it generates thousands of small files.

**Fix:** Move the repository to the WSL2 home directory. From WSL2 Ubuntu:

.. code-block:: bash

   cd ~
   git clone https://github.com/openlake-project/openlake.git
   cd openlake

The path ``~/openlake`` (``/home/yourname/openlake``) lives entirely on the
WSL2 virtual disk and delivers near-native Linux I/O performance.

8. Docker memory or CPU limits causing OOM kills
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptom:**

.. code-block:: none

   Killed
   error: could not compile `openlake`

Cargo worker processes were terminated by the Linux OOM killer because Docker
Desktop did not allocate enough memory to the WSL2 VM.

**Fix:**

1. Open Docker Desktop → **Settings → Resources → Advanced**.
2. Set **Memory** to at least 4 GB (8 GB recommended for a full cold build).
3. Set **CPUs** to at least half of your physical core count.
4. Click **Apply & Restart**.

If you are on a lower-spec machine and cannot spare 4 GB, cap Cargo's
parallelism to reduce peak memory usage:

.. code-block:: bash

   cargo build -j 2

----

Recommended Contributor Workflow
---------------------------------

Getting your setup working is step one. Contributing cleanly is step two.
Here is the full loop that keeps your history readable and your PRs easy to
review.

.. tip::

   Before starting any work, make sure your environment is in a known-good
   state: container running, ``cargo build`` passes, ``cargo test`` is green.
   Debugging a feature and a broken environment at the same time is not fun.

Step 1 — Fork and clone
~~~~~~~~~~~~~~~~~~~~~~~~~

Fork the repository on GitHub, then clone **your fork** (not the upstream)
inside WSL2:

.. code-block:: bash

   git clone https://github.com/YOUR_USERNAME/openlake.git
   cd openlake

Step 2 — Add the upstream remote
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This lets you pull in changes from the main project at any time:

.. code-block:: bash

   git remote add upstream https://github.com/openlake-project/openlake.git

   # Verify both remotes are registered
   git remote -v

Expected output::

   origin    https://github.com/YOUR_USERNAME/openlake.git (fetch)
   origin    https://github.com/YOUR_USERNAME/openlake.git (push)
   upstream  https://github.com/openlake-project/openlake.git (fetch)
   upstream  https://github.com/openlake-project/openlake.git (push)

Step 3 — Create a feature branch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Never commit directly to ``main``. One logical change per branch keeps
reviews focused and rebasing clean:

.. code-block:: bash

   # Sync local main with upstream before branching
   git fetch upstream
   git checkout main
   git rebase upstream/main

   # Create your branch — be descriptive
   git checkout -b feature/wal-flush-interval

Step 4 — Do the work, commit often
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Commit in small, logical units. Each commit should leave the tree in a
buildable state. Follow the `Conventional Commits
<https://www.conventionalcommits.org>`_ format:

.. code-block:: none

   feat(storage): add configurable WAL flush interval
   fix(cluster): prevent split-brain on network partition timeout
   test(index): add boundary condition tests for BTree leaf merge
   docs(setup): clarify WSL2 PATH isolation steps

Keep the subject line under 72 characters. Add a body when the *why* is
not obvious from the diff.

Step 5 — Run the pre-push checklist
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CI will catch these, but catching them locally first saves a pipeline cycle
and the subsequent embarrassment:

.. code-block:: bash

   # 1. Format — no style drift
   cargo fmt

   # 2. Lint — warnings are errors in CI
   cargo clippy -- -D warnings

   # 3. Tests — all must pass
   cargo test

   # 4. Check the release binary builds cleanly
   cargo build --release && ./target/release/openlaked --version

Save yourself some keystrokes with a shell alias:

.. code-block:: bash

   alias prepr='cargo fmt && cargo clippy -- -D warnings && cargo test'

Step 6 — Rebase before opening a pull request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Always rebase onto the latest upstream ``main`` before pushing. This keeps
the commit graph linear and makes the reviewer's job easier:

.. code-block:: bash

   git fetch upstream
   git rebase upstream/main

Resolve any conflicts interactively (``git rebase --continue`` after each),
then push to your fork:

.. code-block:: bash

   git push origin feature/wal-flush-interval --force-with-lease

Use ``--force-with-lease`` rather than ``--force``. It refuses to overwrite
commits on the remote that you have not seen locally — a useful safety net
if you ever share a branch with another contributor.

Step 7 — Rebuilding after a long break
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you leave Docker stopped for several days and come back to the codebase,
run this sequence to get back to a known-good state quickly:

.. code-block:: bash

   # Pull the latest Dev Container base image
   docker pull ghcr.io/openlake-project/openlake-devcontainer:latest

   # In VS Code: Command Palette → Dev Containers: Rebuild Container

   # Sync your branch with upstream
   git fetch upstream
   git rebase upstream/main

   # Confirm everything still builds and tests pass
   cargo build
   cargo test

 Avoid committing unrelated formatting changes generated by workspace-wide formatting runs.
----

Getting Help
------------

Stuck? These are the right places to ask:

- **GitHub Discussions** — questions, ideas, general contributor chat:
  https://github.com/openlake-project/openlake/discussions
- **Issue tracker** — bug reports and confirmed problems:
  https://github.com/openlake-project/openlake/issues
- **Contributing guide** — code style, PR process, review etiquette:
  ``CONTRIBUTING.md`` in the repository root
- **Rust Book** — if you are new to Rust:
  https://doc.rust-lang.org/book/

When reporting a setup problem, paste the output of the following diagnostic
block so maintainers can reproduce your environment exactly:

.. code-block:: bash

   # Run inside WSL2 or the container
   uname -a
   rustc --version
   cargo --version
   docker version

.. code-block:: powershell

   # Run in PowerShell on the Windows host
   wsl --list --verbose
   docker version

----

.. rubric:: Document Information

:Version: 1.1
:Maintained by: OpenLake Contributors
:License: CC BY 4.0

.. note::

   Spotted an error or a step that did not work for you? Open a PR against
   this file — contributor docs are code too.

