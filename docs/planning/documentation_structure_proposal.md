# OpenLake Documentation Structure Proposal

## Overview

This document reviews the current documentation layout across the OpenLake repository and proposes a user-oriented documentation structure for the upcoming Mintlify documentation site.

The objective is to consolidate project documentation under the `docs/` directory and organize it into a single hierarchy that is easy to navigate for users, operators, and contributors.

---

## Current Documentation Inventory

| Current Location | Description | Audience |
|------------------|-------------|----------|
| README.md | Project overview and quick start | Everyone |
| CONTRIBUTING.md | Contribution guide | Contributors |
| docs/developer/environment_setup.rst | Windows developer setup | Contributors |
| docs/examples/spark_openlake.rst | Spark integration guide | Users |
| docs/user/flink-openlake.rst | Flink integration guide | Users |
| docs/cluster_operations.rst | Cluster management | Operators |
| docs/cli_reference.rst | CLI reference | Users |
| benchmarks/README.md | Benchmark information | Developers |
| cli/Benchmark/_CPU/README.md | CPU benchmark notes | Developers |

Vendor documentation under `vendor/` is intentionally excluded since it belongs to third-party dependencies.

---

## Current Challenges

The current documentation has several structural issues:

- Documentation is distributed across multiple directories.
- Repository layout influences documentation organization.
- User documentation and contributor documentation are mixed together.
- Integration guides are separated into different folders.
- Images are stored in multiple locations.
- There is no single navigation hierarchy.

---

## Proposed Documentation Structure

```
docs/
│
├── Introduction
│   ├── Overview
│   ├── Architecture
│   └── FAQ
│
├── Getting Started
│   ├── Installation
│   ├── Quickstart
│   └── Local Cluster
│
├── Guides
│   ├── Integrations
│   │   ├── Spark
│   │   └── Flink
│   ├── Docker Deployment
│   └── Kubernetes (future)
│
├── Operations
│   ├── Cluster Operations
│   ├── Monitoring
│   └── Troubleshooting
│
├── Reference
│   ├── CLI Reference
│   ├── Configuration
│   └── API Reference
│
└── Development
    ├── Environment Setup
    ├── Contributing
    ├── Benchmarks
    └── Coding Standards
```

---

## Proposed Migration

| Current File | Proposed Section |
|--------------|------------------|
| README.md | Introduction + Getting Started |
| CONTRIBUTING.md | Development |
| docs/developer/environment_setup.rst | Development |
| docs/examples/spark_openlake.rst | Guides → Integrations |
| docs/user/flink-openlake.rst | Guides → Integrations |
| docs/cluster_operations.rst | Operations |
| docs/cli_reference.rst | Reference |
| benchmarks/README.md | Development |
| cli/Benchmark/_CPU/README.md | Development |
| docs/examples/docker_4plus2_cluster.rst *(after merge)* | Guides → Docker Deployment |

---

## Future Documentation

Potential future documentation includes:

- Kubernetes deployment
- RDMA deployment
- Performance tuning
- Security
- API reference
- Configuration reference
- Upgrade guide

---

## Next Steps

1. Review the proposed structure.
2. Finalize the documentation hierarchy.
3. Migrate existing RST documentation into the new structure.
4. Convert documentation to Mintlify format.
5. Add navigation and cross-linking.
