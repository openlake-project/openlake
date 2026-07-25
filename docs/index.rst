=======================
OpenLake Documentation
=======================

Welcome to the OpenLake documentation.

OpenLake is a distributed object storage system designed for modern data
processing and AI workloads.

Use the sections below to find developer guides, integration examples,
operational documentation, and CLI reference material.

Developer Guides
================

These guides help contributors set up a development environment and
understand core OpenLake features.

* To get started with local OpenLake development on Windows, see
  :doc:`developer/environment_setup`.

* Learn how OpenLake can be used as a KV cache backend for inference
  engines in :doc:`developer/kv_offload`.

.. toctree::
   :maxdepth: 1

   Developer Environment Setup <developer/environment_setup>
   KV Offload for Inference Engines <developer/kv_offload>

User Guides
===========

Learn how to integrate OpenLake with popular data processing frameworks.

* To use Apache Spark with OpenLake through its S3-compatible API, follow
  :doc:`examples/spark_openlake`.

* To configure Apache Flink checkpointing with OpenLake, see
  :doc:`user/flink-openlake`.

.. toctree::
   :maxdepth: 1

   Spark Integration <examples/spark_openlake>
   Flink Integration <user/flink-openlake>

Operations
==========

Operational guides for managing and troubleshooting OpenLake clusters.

* Learn how to start a cluster, inspect topology, monitor node health,
  and troubleshoot common issues in :doc:`cluster_operations`.

.. toctree::
   :maxdepth: 1

   Cluster Operations <cluster_operations>

Reference
=========

Reference documentation for the OpenLake command-line interface.

* Browse available cluster management and inspection commands in
  :doc:`cli_reference`.

.. toctree::
   :maxdepth: 1

   CLI Reference <cli_reference>
