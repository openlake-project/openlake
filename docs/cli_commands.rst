CLI Commands
============

OpenLake provides a command-line interface for cluster management.

Available commands include:

* cluster status
* cluster up
* cluster down

Example:

.. code-block:: bash

   openlake cluster status --config cluster.toml

The CLI is implemented in Rust and organized under the ``cli/src/commands`` directory.