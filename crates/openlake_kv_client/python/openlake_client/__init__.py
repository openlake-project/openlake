from openlake_client._native import Client, __version__, cuda_compression_available

__all__ = ["Client", "__version__", "cuda_compression_available"]

if cuda_compression_available():
    from openlake_client._native import (
        cuda_compress,
        cuda_compressed_size,
        cuda_decompress,
    )

    __all__ += ["cuda_compress", "cuda_compressed_size", "cuda_decompress"]
