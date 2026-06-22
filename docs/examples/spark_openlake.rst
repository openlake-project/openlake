===================
Spark with OpenLake
===================

Overview
========

This guide demonstrates how Apache Spark can write data to and read data
from an OpenLake cluster using the S3-compatible API.

The example uses a multi-node OpenLake deployment configured with a
4+2 erasure coding layout and validates end-to-end Spark integration.

Cluster Configuration
=====================

The example assumes an OpenLake cluster with:

* 6 storage disks
* 4 data shards
* 2 parity shards
* Multiple OpenLake nodes
* S3 endpoint exposed to Spark

Example cluster topology:

.. code-block:: text

   node0   2 disks
   node1   2 disks
   node2   2 disks

   Erasure Coding: 4 data + 2 parity

Verifying Cluster Health
========================

Before running Spark jobs, verify that all nodes are healthy.

.. code-block:: bash

   openlake cluster status --config cluster.toml

Example output:

.. code-block:: text

   [node   0] up    10.0.0.10:9100 (2 disks)
   [node   1] up    10.0.0.11:9100 (2 disks)
   [node   2] up    10.0.0.12:9100 (2 disks)

   openlake cluster status: 3 / 3 nodes alive

Inspecting Cluster Topology
===========================

View the configured cluster layout.

.. code-block:: bash

   openlake cluster topology \
     --config cluster.toml \
     --probe

Example output:

.. code-block:: text

   node    disks    state    rpc address
   ----    -----    -----    -----------
      0        2    up       10.0.0.10:9100
      1        2    up       10.0.0.11:9100
      2        2    up       10.0.0.12:9100

Creating a Bucket
=================

Create a bucket using an S3-compatible client.

.. code-block:: bash

   aws --endpoint-url http://10.0.0.10:9000 \
       s3 mb s3://spark-demo

Spark Configuration
===================

Configure Spark to use OpenLake as its object store.

.. code-block:: properties

   spark.hadoop.fs.s3a.endpoint=http://10.0.0.10:9000
   spark.hadoop.fs.s3a.access.key=openlakeadmin
   spark.hadoop.fs.s3a.secret.key=openlakesecret
   spark.hadoop.fs.s3a.path.style.access=true
   spark.hadoop.fs.s3a.connection.ssl.enabled=false

Writing Data
============

Example Spark job that writes Parquet data to OpenLake.

.. code-block:: python

   data = [
       (1, "alice"),
       (2, "bob"),
       (3, "charlie")
   ]

   df = spark.createDataFrame(
       data,
       ["id", "name"]
   )

   df.write.mode("overwrite").parquet(
       "s3a://spark-demo/users"
   )

Reading Data
============

Read the same dataset back from OpenLake.

.. code-block:: python

   df = spark.read.parquet(
       "s3a://spark-demo/users"
   )

   df.show()

Expected output:

.. code-block:: text

   +---+-------+
   | id| name  |
   +---+-------+
   | 1 | alice |
   | 2 | bob   |
   | 3 | charlie |
   +---+-------+

Validating the Workflow
=======================

A successful validation consists of:

#. Spark writes data to OpenLake.
#. OpenLake distributes object data across the cluster.
#. Erasure coding protects data using a 4+2 layout.
#. Spark reads the same dataset back successfully.
#. Returned records match the original dataset.

This demonstrates that OpenLake can serve as a storage backend for
distributed Spark workloads.

Checksum Validation
===================

OpenLake validates uploads using the
``x-amz-checksum-blake3`` checksum.

Clients that support BLAKE3 checksums can verify object integrity during
uploads and downloads.

Benchmarking with Warp
======================

Warp can be used to validate object uploads and benchmark the OpenLake
deployment.

Example:

.. code-block:: bash

   warp put \
     --host 10.0.0.10:9000 \
     --access-key openlakeadmin \
     --secret-key openlakesecret

Warp reports throughput, latency, request rates, and upload success
statistics for the cluster.