================================
Docker 4+2 OpenLake Cluster Guide
================================

Overview
========

This guide explains how to run a three-node OpenLake cluster in Docker
using a 4+2 erasure-coding layout.

The cluster uses:

* three OpenLake nodes,
* two data directories per node,
* six drives in total,
* four data shards, and
* two parity shards.

The guide covers three deployment modes:

* TCP without TLS,
* TCP with TLS, and
* RDMA.

The TCP modes were validated using Docker Desktop with WSL. The RDMA
image build was validated separately, but running the RDMA cluster
requires a native Linux host with RDMA-capable hardware and access to
``/dev/infiniband``.

Prerequisites
=============

Before starting, make sure you have:

* Docker installed and running.
* Git.
* OpenSSL.
* The OpenLake repository cloned locally.
* Enough free disk space to build the OpenLake Docker images.
* A Linux or WSL environment for running the commands.

For RDMA mode, you also need:

* an RDMA-capable network interface,
* the required RDMA kernel drivers,
* access to ``/dev/infiniband``, and
* a native Linux Docker host that can pass the RDMA devices into the
  containers.

This guide assumes that you have completed the environment setup
described in :doc:`../developer/environment_setup`.

Cluster Layout
==============

The examples use the following topology:

.. code-block:: text

   openlake-node0
     172.30.0.10
     2 data directories

   openlake-node1
     172.30.0.11
     2 data directories

   openlake-node2
     172.30.0.12
     2 data directories

   Total drives: 6
   Erasure coding: 4 data + 2 parity

The OpenLake configuration uses:

.. code-block:: toml

   set_drive_count = 6
   default_parity_count = 2

Build the Docker Images
=======================

Build the standard OpenLake image for the TCP modes:

.. code-block:: bash

   docker build \
     -f docker/openlaked.Dockerfile \
     -t openlake:local \
     .

Build the RDMA-enabled image separately:

.. code-block:: bash

   docker build \
     --build-arg RDMA=1 \
     -f docker/openlaked.Dockerfile \
     -t openlake:rdma \
     .

The RDMA image includes the OpenLake RDMA feature and the required
runtime libraries. Running it still requires an RDMA-capable Linux host.

Create the Docker Network
=========================

Create an isolated bridge network for the three OpenLake nodes:

.. code-block:: bash

   docker network create \
     --driver bridge \
     --subnet 172.30.0.0/24 \
     --gateway 172.30.0.1 \
     openlake-4plus2

Verify the network configuration:

.. code-block:: bash

   docker network inspect openlake-4plus2 \
     --format '{{.Name}} {{json .IPAM.Config}}'

Example output:

.. code-block:: text

   openlake-4plus2 [{"Subnet":"172.30.0.0/24","Gateway":"172.30.0.1"}]

TCP Without TLS
===============

This mode uses the HTTP/2 TCP transport for inter-node communication
without TLS. Use it only on an isolated, trusted development network.

Prepare the Data Directories
----------------------------

Create one configuration directory and two data directories for each
node:

.. code-block:: bash

   rm -rf /tmp/openlake-4plus2

   mkdir -p \
     /tmp/openlake-4plus2/configs \
     /tmp/openlake-4plus2/node0/d0 \
     /tmp/openlake-4plus2/node0/d1 \
     /tmp/openlake-4plus2/node1/d0 \
     /tmp/openlake-4plus2/node1/d1 \
     /tmp/openlake-4plus2/node2/d0 \
     /tmp/openlake-4plus2/node2/d1

The OpenLake container runs as a non-root user. For this local example,
allow the container user to write to the data directories:

.. code-block:: bash

   chmod -R 777 /tmp/openlake-4plus2/node0
   chmod -R 777 /tmp/openlake-4plus2/node1
   chmod -R 777 /tmp/openlake-4plus2/node2

.. note::

   The permissive directory mode is intended only for this temporary
   local example. Use appropriate ownership and permissions for
   persistent deployments.

Create the Node Configuration
-----------------------------

Create the configuration for node 0:

.. code-block:: bash

   cat > /tmp/openlake-4plus2/configs/node0.toml <<'CONFIG'
   self_id = 0

   data_dirs = [
     "/var/lib/openlake/d0",
     "/var/lib/openlake/d1"
   ]

   s3_addr = "0.0.0.0:9000"
   s3_port = 9000
   rpc_addr = "0.0.0.0:9100"

   set_drive_count = 6
   default_parity_count = 2
   region = "us-east-1"
   transport = "h2"

   [[credentials]]
   access_key = "openlakeadmin"
   secret_key = "openlakesecret"

   [[nodes]]
   id = 0
   rpc_addr = "172.30.0.10:9100"
   disk_count = 2

   [[nodes]]
   id = 1
   rpc_addr = "172.30.0.11:9100"
   disk_count = 2

   [[nodes]]
   id = 2
   rpc_addr = "172.30.0.12:9100"
   disk_count = 2
   CONFIG

Create the remaining configurations from the node 0 file:

.. code-block:: bash

   sed 's/self_id = 0/self_id = 1/' \
     /tmp/openlake-4plus2/configs/node0.toml \
     > /tmp/openlake-4plus2/configs/node1.toml

   sed 's/self_id = 0/self_id = 2/' \
     /tmp/openlake-4plus2/configs/node0.toml \
     > /tmp/openlake-4plus2/configs/node2.toml

Start the Cluster
-----------------

Start all three nodes within the cluster bootstrap timeout.

Start node 0:

.. code-block:: bash

   docker run -d \
     --name openlake-node0 \
     --security-opt seccomp=unconfined \
     --network openlake-4plus2 \
     --ip 172.30.0.10 \
     -p 9000:9000 \
     -v /tmp/openlake-4plus2/configs/node0.toml:/etc/openlake/openlake.toml:ro \
     -v /tmp/openlake-4plus2/node0/d0:/var/lib/openlake/d0 \
     -v /tmp/openlake-4plus2/node0/d1:/var/lib/openlake/d1 \
     openlake:local

Start node 1:

.. code-block:: bash

   docker run -d \
     --name openlake-node1 \
     --security-opt seccomp=unconfined \
     --network openlake-4plus2 \
     --ip 172.30.0.11 \
     -p 9001:9000 \
     -v /tmp/openlake-4plus2/configs/node1.toml:/etc/openlake/openlake.toml:ro \
     -v /tmp/openlake-4plus2/node1/d0:/var/lib/openlake/d0 \
     -v /tmp/openlake-4plus2/node1/d1:/var/lib/openlake/d1 \
     openlake:local

Start node 2:

.. code-block:: bash

   docker run -d \
     --name openlake-node2 \
     --security-opt seccomp=unconfined \
     --network openlake-4plus2 \
     --ip 172.30.0.12 \
     -p 9002:9000 \
     -v /tmp/openlake-4plus2/configs/node2.toml:/etc/openlake/openlake.toml:ro \
     -v /tmp/openlake-4plus2/node2/d0:/var/lib/openlake/d0 \
     -v /tmp/openlake-4plus2/node2/d1:/var/lib/openlake/d1 \
     openlake:local

The ``seccomp=unconfined`` option is required in environments where
Docker's default seccomp profile blocks the ``io_uring`` system calls
used by the OpenLake runtime.

Verify the Cluster
------------------

Check that all three containers are running:

.. code-block:: bash

   docker ps --filter "name=openlake-node" \
     --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

Check that every node completed cluster bootstrap:

.. code-block:: bash

   for node in 0 1 2; do
     echo "=== openlake-node${node} ==="
     docker logs openlake-node${node} 2>&1 \
       | grep "cluster bootstrap complete"
   done

All three nodes should report the same deployment ID.

Send an unsigned request to confirm that the S3 endpoint is available:

.. code-block:: bash

   curl --max-time 10 -v http://127.0.0.1:9000/

A running endpoint returns ``403 Forbidden`` with an ``AccessDenied``
error because the request does not include an authorization header.

Validate Cross-Node Object Access
---------------------------------

Create a bucket through node 0:

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

Create and upload a test object through node 0:

.. code-block:: bash

   echo "hello from openlake 4+2" > /tmp/openlake-test.txt

   curl --max-time 20 \
     --silent \
     --show-error \
     --output /tmp/openlake-put-response.xml \
     --write-out "HTTP status: %{http_code}\n" \
     --aws-sigv4 "aws:amz:us-east-1:s3" \
     --user "openlakeadmin:openlakesecret" \
     --request PUT \
     --header "Content-Length: $(stat -c%s /tmp/openlake-test.txt)" \
     --data-binary @/tmp/openlake-test.txt \
     http://127.0.0.1:9000/test-bucket/hello.txt

A successful upload returns ``HTTP status: 200``.

Download the same object through node 2:

.. code-block:: bash

   curl --max-time 20 \
     --silent \
     --show-error \
     --aws-sigv4 "aws:amz:us-east-1:s3" \
     --user "openlakeadmin:openlakesecret" \
     --output /tmp/openlake-test-downloaded.txt \
     http://127.0.0.1:9002/test-bucket/hello.txt

   cat /tmp/openlake-test-downloaded.txt

Expected content:

.. code-block:: text

   hello from openlake 4+2

Reading the object through node 2 confirms that data written through
node 0 is replicated correctly and can be accessed from another node in
the same OpenLake cluster.

TCP With TLS
============

This mode encrypts both the client-facing S3 endpoint and inter-node RPC
traffic. The example uses a local certificate authority and one
certificate for each OpenLake node.

Stop the Previous Cluster
-------------------------

Remove the containers from the plaintext example before reusing their
names, addresses, and host ports:

.. code-block:: bash

   docker rm -f openlake-node0 openlake-node1 openlake-node2

Prepare the TLS Workspace
-------------------------

Create fresh configuration, certificate, and data directories:

.. code-block:: bash

   rm -rf /tmp/openlake-4plus2-tls

   mkdir -p \
     /tmp/openlake-4plus2-tls/configs \
     /tmp/openlake-4plus2-tls/certs \
     /tmp/openlake-4plus2-tls/node0/d0 \
     /tmp/openlake-4plus2-tls/node0/d1 \
     /tmp/openlake-4plus2-tls/node1/d0 \
     /tmp/openlake-4plus2-tls/node1/d1 \
     /tmp/openlake-4plus2-tls/node2/d0 \
     /tmp/openlake-4plus2-tls/node2/d1

The OpenLake image runs as a non-root user. For this temporary local
example, allow the container user to write to the data directories:

.. code-block:: bash

   chmod -R 777 /tmp/openlake-4plus2-tls/node0
   chmod -R 777 /tmp/openlake-4plus2-tls/node1
   chmod -R 777 /tmp/openlake-4plus2-tls/node2

.. note::

   The permissive directory mode is intended only for this temporary
   local example. Use appropriate ownership and permissions for
   persistent deployments.

Generate the Cluster CA
-----------------------

Create a private certificate authority for the local cluster:

.. code-block:: bash

   cd /tmp/openlake-4plus2-tls/certs

   openssl genrsa -out ca.key 4096

   openssl req -x509 -new -nodes \
     -key ca.key \
     -sha256 \
     -days 3650 \
     -subj "/CN=OpenLake Local Cluster CA" \
     -out ca.crt

Generate Node Certificates
--------------------------

Generate one certificate and private key for each OpenLake node. Each
certificate includes both the container IP address and ``127.0.0.1`` as
Subject Alternative Names, allowing connections from inside the Docker
network and from the host.

.. code-block:: bash

   cd /tmp/openlake-4plus2-tls/certs

   for node in 0 1 2; do
     ip="172.30.0.1$((node))"

     cat > openlake-node${node}.cnf <<EOF
   [req]
   distinguished_name=req_distinguished_name
   req_extensions=req_ext
   prompt=no

   [req_distinguished_name]
   CN=openlake-node${node}

   [req_ext]
   subjectAltName=@alt_names

   [alt_names]
   DNS.1=openlake-node${node}
   DNS.2=localhost
   IP.1=${ip}
   IP.2=127.0.0.1
   EOF

     openssl genrsa -out openlake-node${node}.key 2048

     openssl req -new \
       -key openlake-node${node}.key \
       -out openlake-node${node}.csr \
       -config openlake-node${node}.cnf

     openssl x509 \
       -req \
       -in openlake-node${node}.csr \
       -CA ca.crt \
       -CAkey ca.key \
       -CAcreateserial \
       -out openlake-node${node}.crt \
       -days 825 \
       -sha256 \
       -extensions req_ext \
       -extfile openlake-node${node}.cnf
   done

   chmod 644 \
     ca.crt \
     openlake-node*.crt \
     openlake-node*.key

Create the Configuration Files
------------------------------

Create one configuration file for each node. Each node shares the same
cluster topology while using its own ``self_id`` and TLS certificate.

The configuration uses:

* ``s3_addr`` for the HTTPS S3 listener.
* ``rpc_addr`` for the inter-node RPC listener.
* ``rpc_tls.client_ca`` so each node can verify peer certificates.

Create the configuration for node 0:

.. code-block:: bash

   cat > /tmp/openlake-4plus2-tls/configs/node0.toml <<'CONFIG'
   self_id = 0
   region = "us-east-1"

   s3_addr = "0.0.0.0:9000"
   rpc_addr = "0.0.0.0:9001"

   data_dirs = [
     "/var/lib/openlake/d0",
     "/var/lib/openlake/d1",
   ]

   set_drive_count = 6
   default_parity_count = 2

   transport = "h2"

   [[credentials]]
   access_key = "openlakeadmin"
   secret_key = "openlakesecret"

   [[nodes]]
   id = 0
   rpc_addr = "172.30.0.10:9001"
   disk_count = 2

   [[nodes]]
   id = 1
   rpc_addr = "172.30.0.11:9001"
   disk_count = 2

   [[nodes]]
   id = 2
   rpc_addr = "172.30.0.12:9001"
   disk_count = 2

   [s3_tls]
   cert_path = "/etc/openlake/certs/openlake-node0.crt"
   key_path = "/etc/openlake/certs/openlake-node0.key"

   [rpc_tls]
   cert_path = "/etc/openlake/certs/openlake-node0.crt"
   key_path = "/etc/openlake/certs/openlake-node0.key"
   client_ca = "/etc/openlake/certs/ca.crt"
   CONFIG

Create the node 1 configuration by changing the node ID and certificate
filenames:

.. code-block:: bash

   sed \
     -e 's/self_id = 0/self_id = 1/' \
     -e 's/openlake-node0/openlake-node1/g' \
     /tmp/openlake-4plus2-tls/configs/node0.toml \
     > /tmp/openlake-4plus2-tls/configs/node1.toml

Create the node 2 configuration:

.. code-block:: bash

   sed \
     -e 's/self_id = 0/self_id = 2/' \
     -e 's/openlake-node0/openlake-node2/g' \
     /tmp/openlake-4plus2-tls/configs/node0.toml \
     > /tmp/openlake-4plus2-tls/configs/node2.toml

Start the TLS Cluster
---------------------

Start the three OpenLake containers with the TLS configuration and
certificate directory mounted read-only.

Start node 0:

.. code-block:: bash

   docker run -d \
     --name openlake-node0 \
     --security-opt seccomp=unconfined \
     --network openlake-4plus2 \
     --ip 172.30.0.10 \
     -p 9000:9000 \
     -v /tmp/openlake-4plus2-tls/configs/node0.toml:/etc/openlake/openlake.toml:ro \
     -v /tmp/openlake-4plus2-tls/certs:/etc/openlake/certs:ro \
     -v /tmp/openlake-4plus2-tls/node0/d0:/var/lib/openlake/d0 \
     -v /tmp/openlake-4plus2-tls/node0/d1:/var/lib/openlake/d1 \
     openlake:local

Start node 1:

.. code-block:: bash

   docker run -d \
     --name openlake-node1 \
     --security-opt seccomp=unconfined \
     --network openlake-4plus2 \
     --ip 172.30.0.11 \
     -p 9001:9000 \
     -v /tmp/openlake-4plus2-tls/configs/node1.toml:/etc/openlake/openlake.toml:ro \
     -v /tmp/openlake-4plus2-tls/certs:/etc/openlake/certs:ro \
     -v /tmp/openlake-4plus2-tls/node1/d0:/var/lib/openlake/d0 \
     -v /tmp/openlake-4plus2-tls/node1/d1:/var/lib/openlake/d1 \
     openlake:local

Start node 2:

.. code-block:: bash

   docker run -d \
     --name openlake-node2 \
     --security-opt seccomp=unconfined \
     --network openlake-4plus2 \
     --ip 172.30.0.12 \
     -p 9002:9000 \
     -v /tmp/openlake-4plus2-tls/configs/node2.toml:/etc/openlake/openlake.toml:ro \
     -v /tmp/openlake-4plus2-tls/certs:/etc/openlake/certs:ro \
     -v /tmp/openlake-4plus2-tls/node2/d0:/var/lib/openlake/d0 \
     -v /tmp/openlake-4plus2-tls/node2/d1:/var/lib/openlake/d1 \
     openlake:local

Check that all containers remain running:

.. code-block:: bash

   docker ps -a --filter "name=openlake-node" \
     --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

Check the startup logs:

.. code-block:: bash

   for node in 0 1 2; do
     echo "=== openlake-node${node} ==="
     docker logs openlake-node${node} 2>&1 | tail -50
   done

Each node should report ``cluster bootstrap complete`` with the same
deployment ID.

Verify TLS
----------

Verify that the S3 endpoint presents a certificate signed by the local
cluster CA:

.. code-block:: bash

   curl --verbose \
     --cacert /tmp/openlake-4plus2-tls/certs/ca.crt \
     https://127.0.0.1:9000/ \
     --output /tmp/openlake-tls-response.txt

Show the response body:

.. code-block:: bash

   cat /tmp/openlake-tls-response.txt

The TLS handshake should succeed and curl should report that the SSL
certificate was verified. The S3 request itself returns
``AccessDenied`` because it does not include an Authorization header.

Verify S3 Operations Over TLS
-----------------------------

Create a bucket through node 0:

.. code-block:: bash

   curl \
     --cacert /tmp/openlake-4plus2-tls/certs/ca.crt \
     --aws-sigv4 "aws:amz:us-east-1:s3" \
     --user openlakeadmin:openlakesecret \
     --request PUT \
     https://127.0.0.1:9000/tls-test-bucket \
     --write-out '\nHTTP %{http_code}\n'

The command should return ``HTTP 200``.

Create a small test object:

.. code-block:: bash

   printf 'hello from openlake TLS 4+2\n' \
     > /tmp/openlake-4plus2-tls-object.txt

Upload the object through node 0:

.. code-block:: bash

   curl \
     --cacert /tmp/openlake-4plus2-tls/certs/ca.crt \
     --aws-sigv4 "aws:amz:us-east-1:s3" \
     --user openlakeadmin:openlakesecret \
     --request PUT \
     --header "Content-Length: $(wc -c < /tmp/openlake-4plus2-tls-object.txt)" \
     --data-binary @/tmp/openlake-4plus2-tls-object.txt \
     https://127.0.0.1:9000/tls-test-bucket/hello.txt \
     --write-out '\nHTTP %{http_code}\n'

The upload should return ``HTTP 200``.

Read the same object through node 2:

.. code-block:: bash

   curl \
     --cacert /tmp/openlake-4plus2-tls/certs/ca.crt \
     --aws-sigv4 "aws:amz:us-east-1:s3" \
     --user openlakeadmin:openlakesecret \
     https://127.0.0.1:9002/tls-test-bucket/hello.txt \
     --write-out '\nHTTP %{http_code}\n'

The response should contain:

.. code-block:: text

   hello from openlake TLS 4+2

   HTTP 200

Reading through a different node verifies that the object is available
across the cluster while both the S3 and inter-node RPC paths use TLS.

RDMA
====

RDMA provides low-latency, high-throughput communication between
OpenLake nodes. Unlike the TCP examples above, RDMA requires a native
Linux host with RDMA-capable hardware. Docker Desktop and WSL do not
expose RDMA devices, so the configuration below is derived from the
project's implementation and was not validated with an end-to-end RDMA
deployment.

Prerequisites
-------------

Before using RDMA, ensure that:

* OpenLake is built with the ``rdma`` Cargo feature.
* The host has RDMA-capable hardware.
* ``/dev/infiniband`` is available on the host.
* The RDMA device name matches your system (for example,
  ``mlx5_ib0``).

RDMA Configuration
------------------

Set the transport mode to ``rdma`` and add the required RDMA
configuration:

.. code-block:: toml

   transport = "rdma"

   [rdma]
   self_node_id = 0
   dev_name = "mlx5_ib0"
   dc_key = 0x0BADBEEFC0FFEE

   [rdma.qos]
   traffic_class = 0
   service_level = 0

Each node must use a unique ``self_node_id`` (0, 1, or 2).

Docker Runtime Requirements
---------------------------

When starting RDMA-enabled containers, provide access to the RDMA
device and required capabilities:

.. code-block:: bash

   docker run \
     --device /dev/infiniband \
     --cap-add IPC_LOCK \
     --cap-add NET_RAW \
     ...

These requirements match the Kubernetes Helm deployment, which mounts
``/dev/infiniband`` into the container and grants the same Linux
capabilities.

.. note::

   This guide documents the required configuration for RDMA
   deployments. End-to-end validation requires a native Linux host
   with RDMA-capable hardware and was therefore not performed in the
   Docker Desktop and WSL environment used for this guide.
