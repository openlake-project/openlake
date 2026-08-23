==================
Cluster Operations
==================

Overview
========

This guide describes operational workflows for starting a local OpenLake
cluster, inspecting cluster topology, checking node health, and
troubleshooting common issues.

Starting a Cluster
==================

OpenLake provides the `cluster up` command for starting a cluster from
a configuration file.

.. note::

   The ``cluster up`` command is intended primarily for local single-node
   development and testing workflows.

.. code-block:: bash

   openlake cluster up --config openlake.toml

Checking Cluster Status
=======================

The `cluster status` command checks whether configured nodes are
reachable.

.. code-block:: bash

    openlake cluster status --config openlake.toml

Example output:

.. code-block:: text

   [node   0] up    127.0.0.1:9000
   [node   1] DOWN  127.0.0.1:9001

openlake cluster status: 1 / 2 nodes alive

Viewing Cluster Topology
========================

The `cluster topology` command displays the cluster layout declared
in the configuration file.

.. code-block:: bash

    openlake cluster topology --config openlake.toml

The output includes:

* Node identifiers
* Disk counts
* RPC addresses

Monitoring Node Health
======================

The topology command can optionally probe nodes and report liveness.

When `--probe` is specified, OpenLake attempts to contact each
configured node and reports whether the node is currently reachable.

.. code-block:: bash

    openlake cluster topology 
    --config openlake.toml 
    --probe

This adds a status column indicating whether each node is reachable.

Troubleshooting
===============

No Nodes Configured
-------------------

If the configuration file declares zero nodes, OpenLake reports that no
cluster was detected.

Verify that the configuration file contains valid node definitions.

Nodes Reported as DOWN
----------------------

A node may appear as DOWN if:

* The node process is not running.
* The configured address is incorrect.
* Network connectivity is unavailable.

Verify the node configuration and ensure the node process is running.

Cluster Startup Failures
------------------------

If `cluster up` fails to start:

* Verify the configuration file path.
* Check the OpenLake daemon logs.
* Confirm required ports are available.

Operational Workflow
====================

Typical development workflow:

#. Start the cluster.
#. Verify cluster status.
#. Inspect topology.
#. Probe node health when troubleshooting connectivity issues.
