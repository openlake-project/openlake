# OpenLake Integration with Milvus

.. contents:: On this page
:depth: 2

This guide describes how to configure Milvus to use OpenLake as its
S3-compatible object storage backend instead of MinIO.

It covers building and running OpenLake locally, configuring Milvus to
connect to OpenLake, verifying the integration, and building an HNSW
index to validate the object storage workflow.

## Prerequisites

Before starting, ensure the following requirements are met:

* Ubuntu 24.04 (or a compatible Linux environment)
* Docker installed and running
* Rust toolchain installed
* Python 3.12 with `pymilvus` installed
* OpenLake repository cloned locally
* Milvus v2.6.x

## Overview

This guide walks through the following steps:

1. Build OpenLake.
2. Configure and start an OpenLake node.
3. Configure Milvus to use OpenLake instead of MinIO.
4. Verify the connection between Milvus and OpenLake.
5. Create a collection and build an HNSW index.
6. Validate the integration using a benchmark.

## Step 1: Build OpenLake

From the OpenLake repository root, build the project:

.. code-block:: bash

cargo build

After the build completes successfully, the `openlaked` binary is
available at:

.. code-block:: text

target/debug/openlaked

## Step 2: Configure OpenLake

Configure a single-node OpenLake instance before starting the server.

A minimal configuration should define:

* Data directories
* S3 endpoint
* RPC endpoint
* Credentials
* Cluster node information

Start the OpenLake server using your configuration file:

.. code-block:: bash

./target/debug/openlaked --config node0.toml

Verify that the server starts successfully.

Expected log messages include:

.. code-block:: text

runtime serving
cluster bootstrap complete
s3 listener bound
rpc listener bound

.. note::

Update the storage paths in `node0.toml` to match your local
environment.

## Step 3: Configure Milvus

Milvus uses MinIO as its default object storage backend.

To configure Milvus to use OpenLake instead:

1. Disable or remove the MinIO service from the Docker Compose file.
2. Configure the standalone Milvus service to connect to OpenLake.

Example environment variables:

.. code-block:: yaml

MINIO_ADDRESS: 172.17.0.1:9000
MINIO_ACCESS_KEY_ID: openlakeaccesskey
MINIO_SECRET_ACCESS_KEY: openlakesecretkey

Replace `172.17.0.1` with the appropriate address if OpenLake is
reachable through a different network interface.

## Step 4: Start Milvus

Start the Milvus services:

.. code-block:: bash

docker compose up -d

Verify that the Milvus health endpoint is available:

.. code-block:: bash

curl http://localhost:9091/healthz

Expected output:

.. code-block:: text

OK

## Step 5: Verify the Integration

Confirm that both OpenLake and Milvus are running correctly.

Check the OpenLake server logs:

.. code-block:: bash

./target/debug/openlaked --config node0.toml

Check the Milvus logs:

.. code-block:: bash

docker logs milvus-standalone

Milvus should initialize successfully without reporting S3 object storage
errors.

## Step 6: Build an HNSW Index

Create a collection with the following parameters:

* Vector dimension: 128
* Dataset size: 2,000 vectors

Insert the vectors into the collection.

Flush the collection before checking statistics or building an index.

.. note::

Calling `flush()` ensures that all inserted entities are persisted
before index creation.

Create an HNSW index and wait until the operation completes.

## Step 7: Benchmark Results

The following benchmark was performed using the environment described in
this guide.

.. list-table::
:header-rows: 1

* * Metric
  * Result
* * Dataset Size
  * 2,000 vectors
* * Vector Dimension
  * 128
* * Index Type
  * HNSW
* * Row Count
  * 2,000
* * Index Build Time
  * Approximately 2.42 seconds

## Troubleshooting

**Row count is zero after inserting data**

Cause

The inserted entities have not yet been flushed.

Solution

Flush the collection before checking collection statistics or building
the index.

**Milvus reports `ListObjects` is not implemented**

Cause

Earlier OpenLake versions did not support the object listing behavior
required during Milvus initialization.

Solution

Update OpenLake to the latest version and rebuild the project.

.. code-block:: bash

git pull origin main
cargo build

**Port 9000 is already in use**

Cause

Another S3-compatible storage service (for example MinIO) is already
using the port.

Solution

Stop the conflicting service or configure OpenLake to use another
available port.

## Notes

* Start OpenLake before starting Milvus.
* Verify that the configured access key and secret key match in both
  OpenLake and Milvus.
* Ensure that the OpenLake S3 endpoint is reachable from the Milvus
  container.
* Adjust the endpoint address if your Docker networking configuration
  differs from this guide.

## Future Improvements

Possible future enhancements include:

* Benchmark larger datasets.
* Compare OpenLake and MinIO performance.
* Evaluate concurrent indexing workloads.
* Add automated integration tests.
