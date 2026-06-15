=====================
Spark with OpenLake
=====================

Overview
========

This guide demonstrates how Apache Spark can read and write data
using OpenLake through its S3-compatible API.

Prerequisites
=============

Before running Spark jobs:

* OpenLake cluster is running.
* An S3 bucket exists.
* Access key and secret key are configured.
* Spark is configured with the Hadoop S3A connector.

Verify OpenLake
===============

Check cluster status:

.. code-block:: bash

   openlake cluster status --config node0.toml

Example output:

.. code-block:: text

   [node   0] up    127.0.0.1:9100 (2 disks)

Creating a Bucket
=================

Create a bucket using a compatible S3 client:

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

Example Spark code:

.. code-block:: python

   df.write.mode("overwrite").parquet(
       "s3a://demo/sample-data"
   )

Reading Data
============

Example Spark code:

.. code-block:: python

   df = spark.read.parquet(
       "s3a://demo/sample-data"
   )

   df.show()

Checksum Requirements
=====================

OpenLake validates uploads using the
``x-amz-checksum-blake3`` checksum.

Clients that automatically send unsupported checksum
algorithms may be rejected.

Compatible clients such as Warp can be used for
validation and benchmarking.

Benchmarking with Warp
======================

Example benchmark:

.. code-block:: bash

   ./warp put \
     --host 127.0.0.1:9000 \
     --access-key openlakeadmin \
     --secret-key openlakesecret

This can be used to verify upload behavior and benchmark
OpenLake deployments.
