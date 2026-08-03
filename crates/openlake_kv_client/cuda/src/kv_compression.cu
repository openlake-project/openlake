#include "openlake/kv_compression.h"

#include <cuda_bf16.h>
#include <cuda_fp16.h>
#include <cuda_runtime.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace {

constexpr uint32_t kThreadsPerBlock = 256;
constexpr uint32_t kMinimumGroupSize = 16;
constexpr uint32_t kMaximumGroupSize = 4096;
constexpr uint32_t kGroupSizeAlignment = 16;
constexpr size_t kRegionAlignment = 16;
constexpr int kInt8Maximum = 127;

static_assert(sizeof(openlake_kv_compressed_header) ==
                  OPENLAKE_KV_COMPRESSION_HEADER_BYTES,
              "the on-device compression header must remain 128 bytes");
static_assert(std::is_standard_layout_v<openlake_kv_compressed_header>,
              "the public compression header must have a C-compatible layout");

struct BufferLayout {
    size_t group_count;
    size_t scales_offset;
    size_t payload_offset;
    size_t total_bytes;
};

bool checked_add(size_t left, size_t right, size_t* result) {
    if (left > std::numeric_limits<size_t>::max() - right) {
        return false;
    }
    *result = left + right;
    return true;
}

bool checked_multiply(size_t left, size_t right, size_t* result) {
    if (left != 0 && right > std::numeric_limits<size_t>::max() / left) {
        return false;
    }
    *result = left * right;
    return true;
}

bool align_up(size_t value, size_t alignment, size_t* result) {
    const size_t remainder = value % alignment;
    if (remainder == 0) {
        *result = value;
        return true;
    }
    return checked_add(value, alignment - remainder, result);
}

bool group_size_is_valid(uint32_t group_size) {
    return group_size >= kMinimumGroupSize &&
           group_size <= kMaximumGroupSize &&
           group_size % kGroupSizeAlignment == 0;
}

bool calculate_layout(
    size_t element_count,
    uint32_t group_size,
    BufferLayout* layout) {
    if (layout == nullptr || element_count == 0 ||
        !group_size_is_valid(group_size)) {
        return false;
    }

    const size_t group_count =
        element_count / group_size +
        static_cast<size_t>(element_count % group_size != 0);
    if (group_count == 0 ||
        group_count > std::numeric_limits<uint32_t>::max()) {
        return false;
    }

    size_t scale_bytes = 0;
    if (!checked_multiply(group_count, sizeof(float), &scale_bytes)) {
        return false;
    }

    size_t scales_end = 0;
    if (!checked_add(
            OPENLAKE_KV_COMPRESSION_HEADER_BYTES,
            scale_bytes,
            &scales_end)) {
        return false;
    }

    size_t payload_offset = 0;
    if (!align_up(scales_end, kRegionAlignment, &payload_offset)) {
        return false;
    }

    size_t total_bytes = 0;
    if (!checked_add(payload_offset, element_count, &total_bytes)) {
        return false;
    }

    layout->group_count = group_count;
    layout->scales_offset = OPENLAKE_KV_COMPRESSION_HEADER_BYTES;
    layout->payload_offset = payload_offset;
    layout->total_bytes = total_bytes;
    return true;
}

template <typename Scalar>
__device__ float scalar_to_float(Scalar value);

template <>
__device__ float scalar_to_float<__half>(__half value) {
    return __half2float(value);
}

template <>
__device__ float scalar_to_float<__nv_bfloat16>(__nv_bfloat16 value) {
    return __bfloat162float(value);
}

template <typename Scalar>
__device__ Scalar float_to_scalar(float value);

template <>
__device__ __half float_to_scalar<__half>(float value) {
    return __float2half_rn(value);
}

template <>
__device__ __nv_bfloat16 float_to_scalar<__nv_bfloat16>(float value) {
    return __float2bfloat16_rn(value);
}

__device__ float warp_reduce_max(float value) {
    constexpr unsigned int kFullWarpMask = 0xffffffffu;
    for (int offset = warpSize / 2; offset > 0; offset /= 2) {
        value = fmaxf(
            value,
            __shfl_down_sync(kFullWarpMask, value, offset));
    }
    return value;
}

__device__ float block_reduce_max(float value) {
    __shared__ float warp_maxima[32];

    const unsigned int lane = threadIdx.x % warpSize;
    const unsigned int warp = threadIdx.x / warpSize;
    const unsigned int warp_count =
        (blockDim.x + warpSize - 1) / warpSize;

    value = warp_reduce_max(value);
    if (lane == 0) {
        warp_maxima[warp] = value;
    }
    __syncthreads();

    float block_maximum = 0.0f;
    if (warp == 0) {
        block_maximum = lane < warp_count ? warp_maxima[lane] : 0.0f;
        block_maximum = warp_reduce_max(block_maximum);
        if (lane == 0) {
            warp_maxima[0] = block_maximum;
        }
    }
    __syncthreads();
    return warp_maxima[0];
}

__global__ void write_header_kernel(
    openlake_kv_compressed_header* header,
    uint32_t source_dtype,
    uint32_t group_size,
    uint64_t element_count,
    uint64_t group_count,
    uint64_t scales_offset,
    uint64_t payload_offset,
    uint64_t total_bytes,
    uint64_t uncompressed_bytes) {
    if (blockIdx.x != 0 || threadIdx.x != 0) {
        return;
    }

    header->magic = OPENLAKE_KV_COMPRESSION_MAGIC;
    header->version = OPENLAKE_KV_COMPRESSION_VERSION;
    header->header_bytes = OPENLAKE_KV_COMPRESSION_HEADER_BYTES;
    header->source_dtype = source_dtype;
    header->group_size = group_size;
    header->element_count = element_count;
    header->group_count = group_count;
    header->scales_offset = scales_offset;
    header->payload_offset = payload_offset;
    header->total_bytes = total_bytes;
    header->uncompressed_bytes = uncompressed_bytes;

#pragma unroll
    for (int index = 0; index < 8; ++index) {
        header->reserved[index] = 0;
    }
}

template <typename Scalar>
__global__ void compress_groups_kernel(
    const Scalar* input,
    size_t element_count,
    uint32_t group_size,
    float* scales,
    int8_t* payload) {
    const size_t group = blockIdx.x;
    const size_t first = group * static_cast<size_t>(group_size);
    if (first >= element_count) {
        return;
    }

    const size_t group_elements =
        min(static_cast<size_t>(group_size), element_count - first);
    float thread_absmax = 0.0f;

    for (size_t local = threadIdx.x;
         local < group_elements;
         local += blockDim.x) {
        const float value = scalar_to_float(input[first + local]);
        const float magnitude = isfinite(value) ? fabsf(value) : 0.0f;
        thread_absmax = fmaxf(thread_absmax, magnitude);
    }

    const float absolute_maximum = block_reduce_max(thread_absmax);
    __shared__ float group_scale;
    __shared__ float inverse_scale;

    if (threadIdx.x == 0) {
        group_scale = absolute_maximum > 0.0f
            ? absolute_maximum / static_cast<float>(kInt8Maximum)
            : 0.0f;
        inverse_scale = absolute_maximum > 0.0f
            ? static_cast<float>(kInt8Maximum) / absolute_maximum
            : 0.0f;
        scales[group] = group_scale;
    }
    __syncthreads();

    for (size_t local = threadIdx.x;
         local < group_elements;
         local += blockDim.x) {
        float value = scalar_to_float(input[first + local]);
        if (!isfinite(value) || group_scale == 0.0f) {
            payload[first + local] = 0;
            continue;
        }

        int quantized = __float2int_rn(value * inverse_scale);
        quantized = max(-kInt8Maximum, min(kInt8Maximum, quantized));
        payload[first + local] = static_cast<int8_t>(quantized);
    }
}

__device__ bool header_matches(
    const openlake_kv_compressed_header* header,
    uint32_t expected_dtype,
    size_t expected_elements,
    uint32_t expected_group_size,
    size_t expected_groups,
    size_t expected_scales_offset,
    size_t expected_payload_offset,
    size_t expected_total_bytes) {
    return header->magic == OPENLAKE_KV_COMPRESSION_MAGIC &&
           header->version == OPENLAKE_KV_COMPRESSION_VERSION &&
           header->header_bytes == OPENLAKE_KV_COMPRESSION_HEADER_BYTES &&
           header->source_dtype == expected_dtype &&
           header->group_size == expected_group_size &&
           header->element_count == expected_elements &&
           header->group_count == expected_groups &&
           header->scales_offset == expected_scales_offset &&
           header->payload_offset == expected_payload_offset &&
           header->total_bytes == expected_total_bytes;
}

template <typename Scalar>
__global__ void decompress_groups_kernel(
    const uint8_t* input,
    size_t element_count,
    uint32_t group_size,
    uint32_t expected_dtype,
    size_t group_count,
    size_t scales_offset,
    size_t payload_offset,
    size_t total_bytes,
    Scalar* output) {
    const auto* header =
        reinterpret_cast<const openlake_kv_compressed_header*>(input);
    __shared__ int valid_header;
    if (threadIdx.x == 0) {
        valid_header = header_matches(
            header,
            expected_dtype,
            element_count,
            group_size,
            group_count,
            scales_offset,
            payload_offset,
            total_bytes)
            ? 1
            : 0;
    }
    __syncthreads();
    if (valid_header == 0) {
        return;
    }

    const size_t group = blockIdx.x;
    const size_t first = group * static_cast<size_t>(group_size);
    if (first >= element_count) {
        return;
    }

    const auto* scales =
        reinterpret_cast<const float*>(input + scales_offset);
    const auto* payload =
        reinterpret_cast<const int8_t*>(input + payload_offset);
    const float scale = scales[group];
    const size_t group_elements =
        min(static_cast<size_t>(group_size), element_count - first);

    for (size_t local = threadIdx.x;
         local < group_elements;
         local += blockDim.x) {
        const float restored =
            static_cast<float>(payload[first + local]) * scale;
        output[first + local] = float_to_scalar<Scalar>(restored);
    }
}

cudaError_t validate_launch_arguments(
    const void* input,
    size_t element_count,
    uint32_t group_size,
    const void* output,
    size_t available_bytes,
    BufferLayout* layout) {
    if (input == nullptr || output == nullptr ||
        !calculate_layout(element_count, group_size, layout)) {
        return cudaErrorInvalidValue;
    }
    if (available_bytes < layout->total_bytes) {
        return cudaErrorInvalidValue;
    }
    return cudaSuccess;
}

template <typename Scalar>
cudaError_t launch_compression(
    const void* input,
    size_t element_count,
    uint32_t group_size,
    void* output,
    size_t output_bytes,
    openlake_kv_dtype source_dtype,
    cudaStream_t stream) {
    BufferLayout layout{};
    cudaError_t error = validate_launch_arguments(
        input,
        element_count,
        group_size,
        output,
        output_bytes,
        &layout);
    if (error != cudaSuccess) {
        return error;
    }

    auto* output_bytes_pointer = static_cast<uint8_t*>(output);
    auto* header =
        reinterpret_cast<openlake_kv_compressed_header*>(output_bytes_pointer);
    auto* scales = reinterpret_cast<float*>(
        output_bytes_pointer + layout.scales_offset);
    auto* payload = reinterpret_cast<int8_t*>(
        output_bytes_pointer + layout.payload_offset);

    write_header_kernel<<<1, 1, 0, stream>>>(
        header,
        static_cast<uint32_t>(source_dtype),
        group_size,
        element_count,
        layout.group_count,
        layout.scales_offset,
        layout.payload_offset,
        layout.total_bytes,
        element_count * sizeof(Scalar));
    error = cudaGetLastError();
    if (error != cudaSuccess) {
        return error;
    }

    compress_groups_kernel<Scalar>
        <<<static_cast<uint32_t>(layout.group_count),
           kThreadsPerBlock,
           0,
           stream>>>(
            static_cast<const Scalar*>(input),
            element_count,
            group_size,
            scales,
            payload);
    return cudaGetLastError();
}

template <typename Scalar>
cudaError_t launch_decompression(
    const void* input,
    size_t input_bytes,
    size_t element_count,
    uint32_t group_size,
    void* output,
    openlake_kv_dtype output_dtype,
    cudaStream_t stream) {
    BufferLayout layout{};
    cudaError_t error = validate_launch_arguments(
        input,
        element_count,
        group_size,
        output,
        input_bytes,
        &layout);
    if (error != cudaSuccess) {
        return error;
    }

    decompress_groups_kernel<Scalar>
        <<<static_cast<uint32_t>(layout.group_count),
           kThreadsPerBlock,
           0,
           stream>>>(
            static_cast<const uint8_t*>(input),
            element_count,
            group_size,
            static_cast<uint32_t>(output_dtype),
            layout.group_count,
            layout.scales_offset,
            layout.payload_offset,
            layout.total_bytes,
            static_cast<Scalar*>(output));
    return cudaGetLastError();
}

}

extern "C" size_t openlake_kv_compressed_size(
    size_t element_count,
    uint32_t group_size) {
    BufferLayout layout{};
    return calculate_layout(element_count, group_size, &layout)
        ? layout.total_bytes
        : 0;
}

extern "C" cudaError_t openlake_kv_compress_fp16_async(
    const void* input,
    size_t element_count,
    uint32_t group_size,
    void* output,
    size_t output_bytes,
    cudaStream_t stream) {
    return launch_compression<__half>(
        input,
        element_count,
        group_size,
        output,
        output_bytes,
        OPENLAKE_KV_DTYPE_FP16,
        stream);
}

extern "C" cudaError_t openlake_kv_compress_bf16_async(
    const void* input,
    size_t element_count,
    uint32_t group_size,
    void* output,
    size_t output_bytes,
    cudaStream_t stream) {
    return launch_compression<__nv_bfloat16>(
        input,
        element_count,
        group_size,
        output,
        output_bytes,
        OPENLAKE_KV_DTYPE_BF16,
        stream);
}

extern "C" cudaError_t openlake_kv_decompress_fp16_async(
    const void* input,
    size_t input_bytes,
    size_t element_count,
    uint32_t group_size,
    void* output,
    cudaStream_t stream) {
    return launch_decompression<__half>(
        input,
        input_bytes,
        element_count,
        group_size,
        output,
        OPENLAKE_KV_DTYPE_FP16,
        stream);
}

extern "C" cudaError_t openlake_kv_decompress_bf16_async(
    const void* input,
    size_t input_bytes,
    size_t element_count,
    uint32_t group_size,
    void* output,
    cudaStream_t stream) {
    return launch_decompression<__nv_bfloat16>(
        input,
        input_bytes,
        element_count,
        group_size,
        output,
        OPENLAKE_KV_DTYPE_BF16,
        stream);
}
