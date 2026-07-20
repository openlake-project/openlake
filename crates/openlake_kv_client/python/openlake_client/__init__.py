from openlake_client._native import Client, __version__

__all__ = ["Client", "__version__"]


def register():
    from vllm.distributed.kv_transfer.kv_connector.v1.base import KVConnectorFactory

    KVConnectorFactory.register_connector(
        "OpenLakeConnector",
        "openlake_client.openlake_connector",
        "OpenLakeConnector",
    )
