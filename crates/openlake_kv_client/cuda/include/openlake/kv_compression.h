#pragma once

#include <cuda_runtime_api.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPENLAKE_KV_COMPRESSION_MAGIC UINT32_C(0x434b4c4f)

#define OPENLAKE_KV_COMPRESSION_VERSION UINT16_C(1)

#define OPENLAKE_KV_COMPRESSION_HEADER_BYTES UINT16_C(128)

typedef enum openlake_kv_dtype {
    OPENLAKE_KV_DTYPE_FP16 = 1,
    OPENLAKE_KV_DTYPE_BF16 = 2,
} openlake_kv_dtype;

typedef struct openlake_kv_compressed_header {
    uint32_t magic;
    uint16_t version;
    uint16_t header_bytes;
    uint32_t source_dtype;
    uint32_t group_size;
    uint64_t element_count;
    uint64_t group_count;
    uint64_t scales_offset;
    uint64_t payload_offset;
    uint64_t total_bytes;
    uint64_t uncompressed_bytes;
    uint64_t reserved[8];
} openlake_kv_compressed_header;

size_t openlake_kv_compressed_size(size_t element_count, uint32_t group_size);

cudaError_t openlake_kv_compress_fp16_async(
    const void* input,
    size_t element_count,
    uint32_t group_size,
    void* output,
    size_t output_bytes,
    cudaStream_t stream);

cudaError_t openlake_kv_compress_bf16_async(
    const void* input,
    size_t element_count,
    uint32_t group_size,
    void* output,
    size_t output_bytes,
    cudaStream_t stream);

cudaError_t openlake_kv_decompress_fp16_async(
    const void* input,
    size_t input_bytes,
    size_t element_count,
    uint32_t group_size,
    void* output,
    cudaStream_t stream);

cudaError_t openlake_kv_decompress_bf16_async(
    const void* input,
    size_t input_bytes,
    size_t element_count,
    uint32_t group_size,
    void* output,
    cudaStream_t stream);

#ifdef __cplusplus
}
#endif
