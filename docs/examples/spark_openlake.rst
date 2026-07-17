===================
Spark with OpenLake
===================

Overview
========

This guide shows how to use Apache Spark with OpenLake through its
S3-compatible API.

By the end of this guide, you will:

* start a single-node OpenLake server for development,
* create an S3 bucket using a signed ``curl`` request,
* configure Spark to use OpenLake as its object store,
* write a Parquet dataset from Spark, and
* read the dataset back to verify the integration.

The steps in this guide were validated using a single-node OpenLake
deployment for development, running on Linux with Spark 3.5.5 in Docker.

Prerequisites
=============

Before starting, make sure you have:

* OpenLake built from source.
* Docker installed and running.
* Rust installed.
* ``curl`` with AWS SigV4 support.
* A local OpenLake configuration file named ``node0.toml``.

This guide assumes that you have completed the environment setup
described in :doc:`../developer/environment_setup`.

Before You Begin
================

This guide uses a single-node OpenLake deployment intended for local
development. It is not a production or multi-node cluster setup. Spark
connects to the OpenLake S3 endpoint through the Hadoop S3A connector.

The example writes a small Parquet dataset to a bucket named
``test-bucket`` and then reads it back to verify the configuration.

Start the OpenLake Server
=========================

After building OpenLake, start the server using your local configuration
file.

In this guide, the local OpenLake configuration is stored in
``node0.toml``.

.. code-block:: bash

   RUST_LOG=info ./target/release/openlaked --config node0.toml

If the server starts successfully, it will bind the S3 endpoint and
initialize the local deployment. Leave this terminal running while you
complete the remaining steps in this guide.

The following screenshot shows the OpenLake server after it has started
successfully.

.. image:: ../images/spark_openlake_server.png
   :alt: OpenLake server startup
   :align: center

Create a Bucket
===============

Spark writes data into an S3 bucket. Before starting the Spark session,
create a bucket that will store the example dataset.

Before creating the bucket, verify that the OpenLake S3 endpoint is
reachable:

.. code-block:: bash

   curl --max-time 10 \
     --silent \
     --show-error \
     --output /tmp/openlake-endpoint-response.xml \
     --write-out "HTTP status: %{http_code}\n" \
     http://127.0.0.1:9000/

   cat /tmp/openlake-endpoint-response.xml

A running server returns ``HTTP status: 403`` with an ``AccessDenied``
response because the request is not signed.

Create the bucket using a signed S3 request:

.. code-block:: bash

   curl --max-time 20 \
     --silent \
     --show-error \
     --output /tmp/openlake-create-bucket-response.xml \
     --write-out "HTTP status: %{http_code}\n" \
     --aws-sigv4 "aws:amz:us-east-1:s3" \
     --user "openlakeadmin:openlakesecret" \
     --request PUT \
     http://127.0.0.1:9000/test-bucket

A successful request returns ``HTTP status: 200``.

Start a PySpark Session
=======================

This example runs PySpark inside the official Apache Spark Docker image.
The Hadoop S3A connector is loaded when the session starts so that Spark
can communicate with the OpenLake S3-compatible endpoint.

Run the following command:

.. code-block:: bash

   docker run -it --rm \
     --name spark-openlake \
     -v /tmp:/tmp \
     apache/spark:3.5.5 \
     /opt/spark/bin/pyspark \
     --conf spark.jars.ivy=/tmp/.ivy2 \
     --packages org.apache.hadoop:hadoop-aws:3.3.4 \
     --conf spark.hadoop.fs.s3a.endpoint=http://host.docker.internal:9000 \
     --conf spark.hadoop.fs.s3a.access.key=openlakeadmin \
     --conf spark.hadoop.fs.s3a.secret.key=openlakesecret \
     --conf spark.hadoop.fs.s3a.path.style.access=true \
     --conf spark.hadoop.fs.s3a.connection.ssl.enabled=false \
     --conf spark.hadoop.fs.s3a.aws.credentials.provider=org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider

The first run may take a few minutes while Spark downloads the Hadoop
AWS dependencies.

When startup completes, Spark creates a ``SparkSession`` named
``spark``. The terminal then displays the Python prompt:

.. code-block:: text

   SparkSession available as 'spark'.
   >>>

Create and Inspect the DataFrame
================================

At the PySpark prompt, create a small DataFrame that contains three
rows.

.. code-block:: python

   df = spark.createDataFrame(
       [
           (1, "Alice"),
           (2, "Bob"),
           (3, "Charlie"),
       ],
       ["id", "name"],
   )

Display the DataFrame before writing it:

.. code-block:: python

   df.show()

The output should look like this:

.. code-block:: text

   +---+-------+
   | id|   name|
   +---+-------+
   |  1|  Alice|
   |  2|    Bob|
   |  3|Charlie|
   +---+-------+

Write the DataFrame to OpenLake
===============================

Write the DataFrame to the ``test-bucket`` bucket in Parquet format.

.. code-block:: python

   df.coalesce(1).write.mode("overwrite").parquet(
       "s3a://test-bucket/users"
   )

The command returns to the PySpark prompt after the write operation
completes successfully.

Read the Data Back
==================

To verify that the dataset was written successfully, read it back from
OpenLake using Spark.

.. code-block:: python

   read_df = spark.read.parquet("s3a://test-bucket/users")
   read_df.show()

The output should look similar to the following:

.. code-block:: text

   +---+-------+
   | id|   name|
   +---+-------+
   |  1|  Alice|
   |  2|    Bob|
   |  3|Charlie|
   +---+-------+

The following screenshot shows the dataset read successfully from
OpenLake.

.. image:: ../images/spark_openlake_read_output.png
   :alt: Reading a Parquet dataset from OpenLake using Spark
   :align: center

Troubleshooting
===============

If you encounter issues while following this guide, check the following:

* Verify that the OpenLake server is still running before starting
  PySpark.

* If bucket creation fails, verify that the OpenLake S3 endpoint is
  reachable with the unsigned ``curl`` request, then rerun the signed
  bucket-creation request.

* If the first ``docker run`` command takes a long time, Spark may be
  downloading the required Hadoop AWS dependencies. This only happens
  during the initial startup.

* Ensure that the endpoint configured for ``spark.hadoop.fs.s3a.endpoint``
  matches the OpenLake S3 endpoint.

Next Steps
==========

You have successfully configured Apache Spark to use OpenLake as an
S3-compatible storage backend.

You can now experiment with larger datasets, different Spark data
sources, or integrate OpenLake into your own Spark applications.
