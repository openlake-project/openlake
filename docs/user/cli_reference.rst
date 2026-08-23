CLI Reference
=============

.. contents:: On this page
   :depth: 2

Overview
--------

The OpenLake CLI provides commands for managing clusters, inspecting topology,
running benchmarks, and viewing system information.

General command format:

.. code-block:: bash

   openlake <COMMAND> <SUBCOMMAND> [OPTIONS]

For detailed help on any command:

.. code-block:: bash

   openlake --help
   openlake <COMMAND> --help

Cluster Commands
----------------

The ``cluster`` command group provides functionality for inspecting and managing
OpenLake clusters.

cluster status
^^^^^^^^^^^^^^

Checks the availability of cluster nodes defined in a configuration file.

Syntax:

.. code-block:: bash

   openlake cluster status --config <FILE>

Options:

.. list-table::
   :header-rows: 1

   * - Option
     - Description
   * - ``--config``
     - Path to cluster TOML configuration file
   * - ``--probe-timeout-secs``
     - Timeout for node probes (default: 2 seconds)

Example:

.. code-block:: bash

   openlake cluster status \
     --config cluster.toml

Example Output:

.. code-block:: text

   [node   0] up    10.0.0.10:9000
   [node   1] up    10.0.0.11:9000

   openlake cluster status: 2 / 2 nodes alive

Behavior
~~~~~~~~

- Loads cluster configuration.
- Attempts TCP connectivity to each configured node.
- Reports node availability.
- Summarizes cluster health.

cluster topology
^^^^^^^^^^^^^^^^

Displays the configured cluster layout.

Syntax:

.. code-block:: bash

   openlake cluster topology --config <FILE>

Options:

.. list-table::
   :header-rows: 1

   * - Option
     - Description
   * - ``--config``
     - OpenLake configuration file
   * - ``--probe``
     - Probe nodes and display live state
   * - ``--probe-timeout-secs``
     - Probe timeout in seconds

Examples:

.. code-block:: bash

   openlake cluster topology \
     --config cluster.toml

.. code-block:: bash

   openlake cluster topology \
     --config cluster.toml \
     --probe

Example Output:

.. code-block:: text

   node    disks    rpc address
   ----    -----    -----------
      0        4    10.0.0.10:9000
      1        4    10.0.0.11:9000

Behavior
~~~~~~~~

- Reads cluster configuration.
- Displays node layout.
- Optionally performs liveness probes.
- Reports disk counts and node status.

cluster up
^^^^^^^^^^

Starts an OpenLake cluster using a configuration file.

.. note::

   The ``cluster up`` command is primarily intended for local single-node
   development and testing workflows. It should not be considered a
   production deployment mechanism for multi-node clusters.

Syntax:

.. code-block:: bash

   openlake cluster up --config <FILE>

Options:

.. list-table::
   :header-rows: 1

   * - Option
     - Description
   * - ``--config``
     - Path to OpenLake node configuration

Example:

.. code-block:: bash

   openlake cluster up \
     --config openlake.toml

Behavior
~~~~~~~~

- Launches the ``openlaked`` process.
- Passes the specified configuration file.
- Streams process output to the terminal.

Benchmark Commands
------------------

The ``bench`` command group is used for performance testing.

bench target
^^^^^^^^^^^^

Starts a benchmark listener.

Syntax:

.. code-block:: bash

   openlake bench target [OPTIONS]

Options:

.. list-table::
   :header-rows: 1

   * - Option
     - Description
   * - ``--mode``
     - auto, rdma, or tls
   * - ``--bind``
     - Bind address
   * - ``--buf-size``
     - Buffer size
   * - ``--config``
     - Optional configuration file

Example:

.. code-block:: bash

   openlake bench target \
     --bind 0.0.0.0:9090

bench client
^^^^^^^^^^^^

Generates benchmark traffic against a running target.

Syntax:

.. code-block:: bash

   openlake bench client [OPTIONS]

Key Options:

.. list-table::
   :header-rows: 1

   * - Option
     - Description
   * - ``--target``
     - Target endpoint
   * - ``--op``
     - read or write
   * - ``--threads``
     - Number of worker threads
   * - ``--duration-secs``
     - Benchmark duration
   * - ``--warmup-secs``
     - Warmup period

Example:

.. code-block:: bash

   openlake bench client \
     --target 10.0.0.10:9090 \
     --op read \
     --duration-secs 30

Disk Commands
-------------

disk info
^^^^^^^^^

Displays disk-related information.

Syntax:

.. code-block:: bash

   openlake disk info

Current Status
~~~~~~~~~~~~~~

This command currently provides a placeholder implementation and may be expanded in future releases.

Version Command
---------------

version
^^^^^^^

Displays the OpenLake CLI version.

Syntax:

.. code-block:: bash

   openlake version

Example Output:

.. code-block:: text

   OpenLake CLI Version 0.x.x

Exit Codes
----------

OpenLake commands return standard process exit codes.

- ``0`` indicates success.
- Non-zero values indicate an error condition.

See Also
---------

- Cluster Operations
- Deployment Guides
- Architecture Documentation