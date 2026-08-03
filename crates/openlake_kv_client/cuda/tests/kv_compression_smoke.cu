#include "openlake/kv_compression.h"

#include <cuda_bf16.h>
#include <cuda_fp16.h>
#include <cuda_runtime.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

using CodecFunction = cudaError_t (*)(
    const void*,
    size_t,
    uint32_t,
    void*,
    size_t,
    cudaStream_t);

using DecodeFunction = cudaError_t (*)(
    const void*,
    size_t,
    size_t,
    uint32_t,
    void*,
    cudaStream_t);

bool check_cuda(cudaError_t status, const char* operation) {
    if (status == cudaSuccess) {
        return true;
    }
    std::fprintf(
        stderr,
        "%s failed: %s\n",
        operation,
        cudaGetErrorString(status));
    return false;
}

template <typename Scalar>
Scalar make_scalar(float value);

template <>
__half make_scalar<__half>(float value) {
    return __float2half(value);
}

template <>
__nv_bfloat16 make_scalar<__nv_bfloat16>(float value) {
    return __float2bfloat16(value);
}

template <typename Scalar>
float read_scalar(Scalar value);

template <>
float read_scalar<__half>(__half value) {
    return __half2float(value);
}

template <>
float read_scalar<__nv_bfloat16>(__nv_bfloat16 value) {
    return __bfloat162float(value);
}

bool validate_header(
    const openlake_kv_compressed_header& header,
    openlake_kv_dtype dtype,
    size_t element_count,
    uint32_t group_size,
    size_t compressed_bytes) {
    const size_t expected_groups =
        element_count / group_size + (element_count % group_size != 0);
    if (header.magic != OPENLAKE_KV_COMPRESSION_MAGIC ||
        header.version != OPENLAKE_KV_COMPRESSION_VERSION ||
        header.header_bytes != OPENLAKE_KV_COMPRESSION_HEADER_BYTES ||
        header.source_dtype != static_cast<uint32_t>(dtype) ||
        header.group_size != group_size ||
        header.element_count != element_count ||
        header.group_count != expected_groups ||
        header.scales_offset != OPENLAKE_KV_COMPRESSION_HEADER_BYTES ||
        header.payload_offset < header.scales_offset ||
        header.total_bytes != compressed_bytes ||
        header.uncompressed_bytes != element_count * sizeof(uint16_t)) {
        std::fprintf(stderr, "compressed header validation failed\n");
        return false;
    }
    return true;
}

template <typename Scalar>
bool round_trip(
    const char* label,
    openlake_kv_dtype dtype,
    CodecFunction encode,
    DecodeFunction decode) {
    constexpr size_t kElementCount = 4109;
    constexpr uint32_t kGroupSize = 128;
    const size_t compressed_bytes =
        openlake_kv_compressed_size(kElementCount, kGroupSize);
    if (compressed_bytes == 0) {
        std::fprintf(stderr, "%s returned a zero compressed size\n", label);
        return false;
    }

    std::vector<Scalar> source(kElementCount);
    for (size_t index = 0; index < source.size(); ++index) {
        const float value = index < kGroupSize
            ? 0.0f
            : 3.75f * std::sin(static_cast<float>(index) * 0.037f) +
                  0.125f * std::cos(static_cast<float>(index) * 0.011f);
        source[index] = make_scalar<Scalar>(value);
    }

    Scalar* device_source = nullptr;
    Scalar* device_restored = nullptr;
    void* device_compressed = nullptr;
    cudaStream_t stream = nullptr;
    bool ok = true;

    ok &= check_cuda(
        cudaMalloc(&device_source, source.size() * sizeof(Scalar)),
        "cudaMalloc source");
    ok &= check_cuda(
        cudaMalloc(&device_restored, source.size() * sizeof(Scalar)),
        "cudaMalloc restored");
    ok &= check_cuda(
        cudaMalloc(&device_compressed, compressed_bytes),
        "cudaMalloc compressed");
    ok &= check_cuda(cudaStreamCreate(&stream), "cudaStreamCreate");
    if (!ok) {
        cudaFree(device_source);
        cudaFree(device_restored);
        cudaFree(device_compressed);
        if (stream != nullptr) {
            cudaStreamDestroy(stream);
        }
        return false;
    }

    ok &= check_cuda(
        cudaMemcpyAsync(
            device_source,
            source.data(),
            source.size() * sizeof(Scalar),
            cudaMemcpyHostToDevice,
            stream),
        "copy source to device");
    ok &= check_cuda(
        encode(
            device_source,
            source.size(),
            kGroupSize,
            device_compressed,
            compressed_bytes,
            stream),
        "launch compression");
    ok &= check_cuda(
        cudaMemsetAsync(
            device_restored,
            0xff,
            source.size() * sizeof(Scalar),
            stream),
        "initialize restored buffer");
    ok &= check_cuda(
        decode(
            device_compressed,
            compressed_bytes,
            source.size(),
            kGroupSize,
            device_restored,
            stream),
        "launch decompression");

    openlake_kv_compressed_header header{};
    std::vector<Scalar> restored(source.size());
    ok &= check_cuda(
        cudaMemcpyAsync(
            &header,
            device_compressed,
            sizeof(header),
            cudaMemcpyDeviceToHost,
            stream),
        "copy compressed header");
    ok &= check_cuda(
        cudaMemcpyAsync(
            restored.data(),
            device_restored,
            restored.size() * sizeof(Scalar),
            cudaMemcpyDeviceToHost,
            stream),
        "copy restored values");
    ok &= check_cuda(cudaStreamSynchronize(stream), "cudaStreamSynchronize");

    if (ok) {
        ok &= validate_header(
            header,
            dtype,
            source.size(),
            kGroupSize,
            compressed_bytes);
    }

    float maximum_error = 0.0f;
    double total_error = 0.0;
    if (ok) {
        for (size_t index = 0; index < source.size(); ++index) {
            const float error = std::fabs(
                read_scalar(source[index]) - read_scalar(restored[index]));
            maximum_error = std::max(maximum_error, error);
            total_error += error;
            if (index < kGroupSize && read_scalar(restored[index]) != 0.0f) {
                std::fprintf(stderr, "%s zero-group round trip failed\n", label);
                ok = false;
                break;
            }
        }
    }

    constexpr float kMaximumAllowedError = 0.05f;
    if (ok && maximum_error > kMaximumAllowedError) {
        std::fprintf(
            stderr,
            "%s maximum error %.6f exceeded %.6f\n",
            label,
            maximum_error,
            kMaximumAllowedError);
        ok = false;
    }

    const double mean_error = total_error / source.size();
    const double ratio =
        static_cast<double>(source.size() * sizeof(Scalar)) /
        static_cast<double>(compressed_bytes);
    std::printf(
        "%s: elements=%zu compressed=%zu bytes ratio=%.3fx "
        "max_error=%.6f mean_error=%.6f\n",
        label,
        source.size(),
        compressed_bytes,
        ratio,
        maximum_error,
        mean_error);

    check_cuda(cudaStreamDestroy(stream), "cudaStreamDestroy");
    check_cuda(cudaFree(device_source), "cudaFree source");
    check_cuda(cudaFree(device_restored), "cudaFree restored");
    check_cuda(cudaFree(device_compressed), "cudaFree compressed");
    return ok;
}

}

int main() {
    int device_count = 0;
    if (!check_cuda(cudaGetDeviceCount(&device_count), "cudaGetDeviceCount") ||
        device_count == 0) {
        std::fprintf(stderr, "no CUDA device is available\n");
        return EXIT_FAILURE;
    }
    if (!check_cuda(cudaSetDevice(0), "cudaSetDevice")) {
        return EXIT_FAILURE;
    }

    if (openlake_kv_compressed_size(4096, 7) != 0 ||
        openlake_kv_compressed_size(0, 128) != 0) {
        std::fprintf(stderr, "invalid compression layouts were accepted\n");
        return EXIT_FAILURE;
    }

    const bool fp16_ok = round_trip<__half>(
        "fp16",
        OPENLAKE_KV_DTYPE_FP16,
        openlake_kv_compress_fp16_async,
        openlake_kv_decompress_fp16_async);
    const bool bf16_ok = round_trip<__nv_bfloat16>(
        "bf16",
        OPENLAKE_KV_DTYPE_BF16,
        openlake_kv_compress_bf16_async,
        openlake_kv_decompress_bf16_async);

    return fp16_ok && bf16_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
