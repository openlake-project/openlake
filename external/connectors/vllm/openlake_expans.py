# SPDX-License-Identifier: Apache-2.0

import ctypes
from pathlib import Path

import torch


def _array(kind, values):
    values = tuple(values)
    return (kind * len(values))(*values)


def _configure_abi(library):
    void_pointer = ctypes.c_void_p
    library.openlake_expans_create.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(void_pointer),
    ]
    library.openlake_expans_create.restype = ctypes.c_int
    library.openlake_expans_destroy.argtypes = [void_pointer]
    library.openlake_expans_destroy.restype = None
    library.openlake_expans_last_error.argtypes = [void_pointer]
    library.openlake_expans_last_error.restype = ctypes.c_char_p
    library.openlake_expans_encode.argtypes = [
        void_pointer,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint64,
    ]
    library.openlake_expans_encode.restype = ctypes.c_int
    library.openlake_expans_decode.argtypes = [
        void_pointer,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint64,
    ]
    library.openlake_expans_decode.restype = ctypes.c_int


class ExpansCodec:
    def __init__(self, *, raw_block_bytes, record_bytes, segment_bytes,
                 max_batch_blocks, client):
        self.raw_block_bytes = int(raw_block_bytes)
        self.record_bytes = int(record_bytes)
        self.segment_bytes = tuple(int(value) for value in segment_bytes)
        self.max_batch_blocks = int(max_batch_blocks)
        self.client = client
        self._library = ctypes.CDLL(
            str(Path(__file__).with_name("libopenlake_expans.so"))
        )
        _configure_abi(self._library)

    def new_lane(self):
        return _ExpansLane(self)


class _ExpansLane:
    def __init__(self, codec):
        self.record_bytes = codec.record_bytes
        self.max_batch_blocks = codec.max_batch_blocks
        self._library = codec._library
        self._handle = ctypes.c_void_p()
        segment_bytes = _array(ctypes.c_uint32, codec.segment_bytes)
        status = self._library.openlake_expans_create(
            codec.raw_block_bytes,
            self.record_bytes,
            segment_bytes,
            len(codec.segment_bytes),
            self.max_batch_blocks,
            ctypes.byref(self._handle),
        )
        self._check(status)
        self._records = torch.empty(
            self.max_batch_blocks * self.record_bytes,
            dtype=torch.uint8,
            device="cuda",
        )
        codec.client.register_memory(
            self._records.data_ptr(), self._records.numel()
        )

    def __del__(self):
        handle = getattr(self, "_handle", None)
        library = getattr(self, "_library", None)
        if handle is not None and handle.value and library is not None:
            library.openlake_expans_destroy(handle)
            handle.value = None

    def _check(self, status):
        if status == 0:
            return
        message = self._library.openlake_expans_last_error(self._handle)
        detail = message.decode() if message else f"status {status}"
        raise RuntimeError(f"ExpANS CUDA codec failed: {detail}")

    def _addresses(self, count):
        if not 0 <= count <= self.max_batch_blocks:
            raise ValueError(
                f"ExpANS batch has {count} blocks; capacity is "
                f"{self.max_batch_blocks}"
            )
        base = self._records.data_ptr()
        return tuple(base + i * self.record_bytes for i in range(count))

    @staticmethod
    def _flatten(scatters):
        addresses = []
        sizes = []
        offsets = [0]
        for scatter in scatters:
            addresses.extend(int(address) for address, _ in scatter)
            sizes.extend(int(size) for _, size in scatter)
            offsets.append(len(addresses))
        return addresses, sizes, offsets

    @staticmethod
    def _stream():
        return int(torch.cuda.current_stream().cuda_stream)

    def encode(self, scatters):
        count = len(scatters)
        output_addresses = self._addresses(count)
        addresses, sizes, offsets = self._flatten(scatters)
        host_fits = (ctypes.c_uint8 * count)()
        status = self._library.openlake_expans_encode(
            self._handle,
            _array(ctypes.c_uint64, addresses),
            _array(ctypes.c_uint32, sizes),
            _array(ctypes.c_uint32, offsets),
            count,
            self._records.data_ptr(),
            host_fits,
            self._stream(),
        )
        self._check(status)
        return (
            output_addresses,
            tuple(bool(host_fits[i]) for i in range(count)),
        )

    def reserve(self, count):
        return self._addresses(count)

    def decode(self, record_indexes, destinations):
        if len(record_indexes) != len(destinations):
            raise ValueError("ExpANS record and destination counts differ")
        addresses, sizes, offsets = self._flatten(destinations)
        status = self._library.openlake_expans_decode(
            self._handle,
            self._records.data_ptr(),
            _array(ctypes.c_uint32, record_indexes),
            len(record_indexes),
            _array(ctypes.c_uint64, addresses),
            _array(ctypes.c_uint32, sizes),
            _array(ctypes.c_uint32, offsets),
            self._stream(),
        )
        self._check(status)
