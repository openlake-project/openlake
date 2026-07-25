===============================
KV Offload for Inference Engines
===============================

Overview
========

OpenLake can be used as an external Key-Value (KV) cache backend for
LLM inference workloads. Instead of storing KV cache entries entirely
inside the inference engine process, OpenLake manages KV metadata,
allocates cache slots, and provides lookup operations for previously
computed KV entries.

OpenLake supports two deployment modes:

* **Local KV offload**, where the inference engine communicates with a
  KV service running on the same machine.
* **Cross-node KV offload**, where KV cache is shared across machines
  using RDMA for low-latency communication.

By the end of this guide, you will understand:

* the KV offload architecture,
* the difference between local and RDMA-backed deployments,
* how OpenLake manages KV cache slots, and
* when to use each deployment model.

Prerequisites
=============

Before using OpenLake as a KV offload backend, ensure that you have:

* Built OpenLake successfully.
* Completed the development environment setup described in
  :doc:`environment_setup`.
* A working OpenLake configuration.
* RDMA-capable hardware if you plan to use cross-node KV offload.

KV Offload Architecture
=======================

OpenLake separates KV metadata management from inference execution.

Instead of allowing the inference engine to directly manage KV cache
allocation, OpenLake exposes a KV service responsible for:

* reserving cache slots,
* committing newly generated KV entries,
* looking up existing KV entries,
* releasing unused cache slots, and
* resetting the KV cache when required.

Depending on the deployment mode, KV cache storage is backed by either
shared memory or RDMA-accessible memory.
Local KV Offload
================

Local KV offload is intended for deployments where the inference engine
and OpenLake execute on the same host.

In this mode, OpenLake stores KV cache data in shared memory and exposes
a KV service over RPC. The inference engine communicates with the KV
service to allocate cache slots, publish newly generated entries, look
up previously computed entries, and release slots that are no longer
needed.

Using shared memory avoids unnecessary data copies while allowing the
inference engine and OpenLake to operate as separate processes.

KV Cache Lifecycle
==================

A typical KV cache request follows this sequence:

1. **Reserve**

   The inference engine requests one or more available cache slots.

2. **Commit**

   After generating KV cache data, the inference engine commits the
   associated key hashes and slot mappings.

3. **Lookup**

   Future requests search for matching key hashes. If a matching entry
   exists, OpenLake returns the corresponding slot identifier.

4. **Release**

   When cached data is no longer required, the associated slots are
   released and become available for future allocations.

5. **Reset**

   The complete KV cache can be cleared when required by the runtime or
   during testing.

Cache Management
================

OpenLake tracks KV cache entries using a slot-based allocation model.

Each slot represents a fixed-size cache region. The KV service manages
slot allocation, lookup, and reclamation without requiring the inference
engine to implement its own cache management logic.

When capacity becomes constrained, OpenLake reclaims expired
reservations and recycles available slots for future requests.
Cross-Node KV Offload
=====================

For distributed inference deployments, OpenLake supports KV offload over
RDMA. In this configuration, KV cache metadata remains centrally managed
while remote systems access cache slots using RDMA-capable networking.

Compared to a local shared-memory deployment, RDMA enables multiple
nodes to participate in KV cache operations while minimizing CPU
overhead and reducing data movement across the network.

During startup, the KV service initializes an RDMA-backed slab,
registers the memory region, and publishes the metadata required by
remote clients to access the registered memory.

The published metadata includes:

* the base address of the registered memory region,
* the RDMA remote key (RKey), and
* the configured KV slot size.

Inference runtimes use this information to perform KV cache operations
without relying on shared memory.

RDMA Request Flow
=================

When RDMA mode is enabled, KV operations are exchanged using the RDMA
transport instead of the local shared-memory control path.

Supported operations include:

* Reserve
* Commit
* Lookup
* Release
* Reset

Each request is processed by the KV engine before the corresponding
response is returned to the requesting runtime.

Choosing a Deployment Mode
==========================

Choose **Local KV Offload** when:

* the inference engine and OpenLake execute on the same machine,
* shared memory is available, and
* a simple development or evaluation environment is sufficient.

Choose **Cross-Node KV Offload** when:

* inference workloads span multiple machines,
* RDMA networking is available, and
* low-latency remote KV cache access is required.

Next Steps
==========

After understanding the KV offload architecture, you can integrate
OpenLake into your inference workflow and select the deployment model
that best matches your environment.