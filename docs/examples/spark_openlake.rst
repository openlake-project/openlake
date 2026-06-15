===================
Spark with OpenLake
===================

Overview
========

This guide demonstrates how Apache Spark can write data to and read data
from OpenLake using its S3-compatible API.

The workflow validates that OpenLake can be used as a storage backend
for Spark jobs while preserving normal S3A-based access patterns.

Prerequisites
=============

Before running Spark jobs:

* An OpenLake cluster is running.
* A bucket has been created.
* Spark is configured with the Hadoop S3A connector.
* Valid OpenLake access credentials are available.

Verifying OpenLake
==================

Confirm that the cluster is healthy before running Spark jobs.

.. code-block:: bash

   openlake cluster status --config node0.toml

Example output:

.. code-block:: text

   [node   0] up    127.0.0.1:9100 (2 disks)

   openlake cluster status: 1 / 1 nodes alive

Creating a Bucket
=================

Create a bucket using an S3-compatible client.

.. code-block:: bash

   aws --endpoint-url http://127.0.0.1:9000 s3 mb s3://demo

Spark Configuration
===================

Configure Spark to use OpenLake as the S3 endpoint.

.. code-block:: properties

   spark.hadoop.fs.s3a.endpoint=http://127.0.0.1:9000
   spark.hadoop.fs.s3a.access.key=openlakeadmin
   spark.hadoop.fs.s3a.secret.key=openlakesecret
   spark.hadoop.fs.s3a.path.style.access=true
   spark.hadoop.fs.s3a.connection.ssl.enabled=false

Writing Data
============

Example Spark job that writes data to OpenLake.

.. code-block:: python

   data = [
       (1, "alice"),
       (2, "bob"),
       (3, "charlie"),
   ]

   df = spark.createDataFrame(data, ["id", "name"])

   df.write.mode("overwrite").parquet(
       "s3a://demo/sample-data"
   )

Reading Data
============

Read the same dataset back from OpenLake.

.. code-block:: python

   df = spark.read.parquet(
       "s3a://demo/sample-data"
   )

   df.show()

Expected output:

.. code-block:: text

   +---+-------+
   | id|   name|
   +---+-------+
   |  1|  alice|
   |  2|    bob|
   |  3|charlie|
   +---+-------+

Validating the Workflow
=======================

A successful workflow consists of:

#. Writing data from Spark to OpenLake.
#. Reading the same data back from OpenLake.
#. Verifying that the expected records are returned.

This demonstrates end-to-end interoperability between Spark and
OpenLake through the S3-compatible interface.

Checksum Validation
===================

OpenLake validates object uploads using the
``x-amz-checksum-blake3`` checksum.

Clients that support BLAKE3 checksums can use them to verify object
integrity during uploads.

Benchmarking with Warp
======================

Warp can be used to benchmark uploads and validate client interaction
with OpenLake.

Example:

.. code-block:: bash

   warp put \
     --host 127.0.0.1:9000 \
     --access-key openlakeadmin \
     --secret-key openlakesecret

The benchmark reports throughput, latency, and upload success rates,
which can be used when evaluating OpenLake deployments.