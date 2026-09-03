#include "openlake/expans_codec.h"

#include <cuda_runtime.h>

#include <cstdint>
#include <iostream>
#include <vector>

namespace {

constexpr uint32_t kRawBytes = 999424;
constexpr uint32_t kRecordBytes = 770048;

bool cuda_ok(cudaError_t status, const char* operation) {
  if (status == cudaSuccess) return true;
  std::cerr << operation << ": " << cudaGetErrorString(status) << '\n';
  return false;
}

bool codec_ok(int status, openlake_expans_codec* codec, const char* operation) {
  if (status == 0) return true;
  std::cerr << operation << ": " << openlake_expans_last_error(codec) << '\n';
  return false;
}

}

int main() {
  std::vector<uint16_t> input(kRawBytes / sizeof(uint16_t));
  for (size_t i = 0; i < input.size(); ++i) {
    const uint16_t sign = static_cast<uint16_t>((i & 1U) << 15);
    const uint16_t exponent = static_cast<uint16_t>((125U + i % 4U) << 7);
    const uint16_t fraction = static_cast<uint16_t>((i * 29U) & 0x7fU);
    input[i] = sign | exponent | fraction;
  }
  std::vector<uint16_t> output(input.size());

  uint8_t* device_input = nullptr;
  uint8_t* device_output = nullptr;
  uint8_t* device_record = nullptr;
  cudaStream_t stream = nullptr;
  openlake_expans_codec* codec = nullptr;
  bool success =
      cuda_ok(cudaMalloc(&device_input, kRawBytes), "allocate input") &&
      cuda_ok(cudaMalloc(&device_output, kRawBytes), "allocate output") &&
      cuda_ok(cudaMalloc(&device_record, kRecordBytes), "allocate record") &&
      cuda_ok(cudaStreamCreate(&stream), "create stream");
  if (!success) return 1;

  const uint32_t segment_bytes[] = {kRawBytes};
  success = codec_ok(
      openlake_expans_create(
          kRawBytes, kRecordBytes, segment_bytes, 1, 1, &codec),
      codec, "create codec");
  const uint64_t input_addresses[] = {
      reinterpret_cast<uint64_t>(device_input)};
  const uint32_t input_sizes[] = {kRawBytes};
  const uint32_t offsets[] = {0, 1};
  uint8_t fits = 0;
  if (success) {
    success = cuda_ok(
        cudaMemcpy(
            device_input, input.data(), kRawBytes, cudaMemcpyHostToDevice),
        "copy input");
  }
  if (success) {
    success = codec_ok(
        openlake_expans_encode(
            codec, input_addresses, input_sizes, offsets, 1,
            reinterpret_cast<uint64_t>(device_record), &fits,
            reinterpret_cast<uint64_t>(stream)),
        codec, "encode compressible block");
  }
  if (success && !fits) {
    std::cerr << "compressible block did not fit the 1.3x record\n";
    success = false;
  }

  const uint32_t record_indexes[] = {0};
  const uint64_t output_addresses[] = {
      reinterpret_cast<uint64_t>(device_output)};
  if (success) {
    success = codec_ok(
        openlake_expans_decode(
            codec, reinterpret_cast<uint64_t>(device_record), record_indexes,
            1, output_addresses, input_sizes, offsets,
            reinterpret_cast<uint64_t>(stream)),
        codec, "decode block");
  }
  if (success) {
    success = cuda_ok(
        cudaMemcpy(
            output.data(), device_output, kRawBytes, cudaMemcpyDeviceToHost),
        "copy output");
  }
  if (success && output != input) {
    std::cerr << "ExpANS round trip was not bit-exact\n";
    success = false;
  }

  for (size_t i = 0; i < input.size(); ++i) {
    input[i] = static_cast<uint16_t>(((i % 256U) << 7) | (i & 0x7fU));
  }
  if (success) {
    success = cuda_ok(
        cudaMemcpy(
            device_input, input.data(), kRawBytes, cudaMemcpyHostToDevice),
        "copy overflow input");
  }
  fits = 1;
  if (success) {
    success = codec_ok(
        openlake_expans_encode(
            codec, input_addresses, input_sizes, offsets, 1,
            reinterpret_cast<uint64_t>(device_record), &fits,
            reinterpret_cast<uint64_t>(stream)),
        codec, "encode overflow block");
  }
  if (success && fits) {
    std::cerr << "incompressible block unexpectedly fit the fixed record\n";
    success = false;
  }

  openlake_expans_destroy(codec);
  cudaStreamDestroy(stream);
  cudaFree(device_record);
  cudaFree(device_output);
  cudaFree(device_input);
  return success ? 0 : 1;
}
