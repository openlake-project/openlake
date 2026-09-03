#include "openlake/expans_codec.h"

#include <cuda_runtime.h>
#include <nvcomp/ans.h>

#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "expans_kernels.cuh"

namespace {

constexpr uint32_t kRecordMagic = 0x31505845U;
constexpr uint16_t kRecordVersion = 2;
constexpr uint32_t kRecordHeaderBytes = 64;
constexpr uint32_t kRecordAlignment = 16;
constexpr uint32_t kSignFractionOffset = kRecordHeaderBytes;
constexpr uint32_t kPhaseOffset = kSignFractionOffset + kSymbolsPerBlock;
constexpr uint32_t kFrameOffset =
    ((kPhaseOffset + kPhaseBytesPerBlock + kRecordAlignment - 1) /
     kRecordAlignment) * kRecordAlignment;

struct __align__(16) ExpansRecordHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t header_bytes;
  uint64_t layout_id;
  uint32_t raw_bytes;
  uint32_t actual_bytes;
  uint32_t sign_fraction_offset;
  uint32_t sign_fraction_bytes;
  uint32_t phase_offset;
  uint32_t phase_bytes;
  uint32_t frame_offset;
  uint32_t frame_bytes;
  uint32_t flags;
  uint32_t reserved[3];
};

static_assert(sizeof(ExpansRecordHeader) == kRecordHeaderBytes);

uint64_t layout_id(const uint32_t* segment_bytes, uint32_t segment_count) {
  uint64_t hash = 1469598103934665603ULL;
  auto add = [&](uint32_t value) {
    for (uint32_t byte = 0; byte < sizeof(value); ++byte) {
      hash ^= static_cast<uint8_t>(value >> (byte * 8));
      hash *= 1099511628211ULL;
    }
  };
  add(kRawBytesPerBlock);
  add(segment_count);
  for (uint32_t i = 0; i < segment_count; ++i) add(segment_bytes[i]);
  return hash;
}

__global__ void gather_segments(
    const uint64_t* addresses,
    const uint32_t* segment_offsets,
    uint32_t segment_count,
    uint8_t* output,
    uint32_t blocks) {
  const uint32_t index = blockIdx.x;
  if (index >= blocks * segment_count) return;
  const uint32_t block = index / segment_count;
  const uint32_t segment = index % segment_count;
  const auto* source = reinterpret_cast<const uint8_t*>(addresses[index]);
  uint8_t* destination = output +
      static_cast<size_t>(block) * kRawBytesPerBlock +
      segment_offsets[segment];
  const uint32_t bytes = segment_offsets[segment + 1] - segment_offsets[segment];
  for (uint32_t i = threadIdx.x; i < bytes; i += blockDim.x) {
    destination[i] = source[i];
  }
}

__global__ void residual_histogram(
    const uint16_t* input,
    const uint8_t* centers,
    uint32_t* histogram,
    size_t words) {
  const size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (index >= words) return;
  const uint32_t position = index % kSymbolsPerBlock;
  const uint8_t exponent = static_cast<uint8_t>((input[index] >> 7) & 0xffU);
  const uint8_t residual = static_cast<uint8_t>(
      static_cast<uint32_t>(exponent) + 127U - centers[position]);
  atomicAdd(histogram + residual, 1U);
}

__global__ void histogram_costs(
    const uint32_t* histogram,
    float* costs,
    uint32_t total) {
  const uint32_t symbol = threadIdx.x;
  if (symbol >= 256) return;
  costs[symbol] = -log2f(
      (static_cast<float>(histogram[symbol]) + 0.5f) /
      (static_cast<float>(total) + 128.0f));
}

__global__ void scatter_segments(
    const uint8_t* input,
    const uint64_t* addresses,
    const uint32_t* segment_offsets,
    uint32_t segment_count,
    uint32_t blocks) {
  const uint32_t index = blockIdx.x;
  if (index >= blocks * segment_count) return;
  const uint32_t block = index / segment_count;
  const uint32_t segment = index % segment_count;
  const uint8_t* source = input +
      static_cast<size_t>(block) * kRawBytesPerBlock +
      segment_offsets[segment];
  auto* destination = reinterpret_cast<uint8_t*>(addresses[index]);
  const uint32_t bytes = segment_offsets[segment + 1] - segment_offsets[segment];
  for (uint32_t i = threadIdx.x; i < bytes; i += blockDim.x) {
    destination[i] = source[i];
  }
}

__global__ void pack_records(
    uint8_t* records,
    uint32_t record_bytes,
    const uint8_t* sign_fraction,
    const uint8_t* phase_bitmaps,
    const uint8_t* frames,
    size_t frame_stride,
    const size_t* frame_sizes,
    uint8_t* fits,
    uint64_t expected_layout_id,
    uint32_t batches) {
  const uint32_t batch = blockIdx.x;
  if (batch >= batches) return;
  uint8_t* record = records + static_cast<size_t>(batch) * record_bytes;
  const size_t frame_bytes = frame_sizes[batch];
  const size_t actual_bytes = kFrameOffset + frame_bytes;
  const bool fit = frame_bytes != 0 && actual_bytes <= record_bytes;
  if (threadIdx.x == 0) fits[batch] = fit;
  if (!fit) return;

  const uint8_t* block_sign = sign_fraction +
      static_cast<size_t>(batch) * kSymbolsPerBlock;
  const uint8_t* block_phase = phase_bitmaps +
      static_cast<size_t>(batch) * kPhaseBytesPerBlock;
  const uint8_t* block_frame = frames +
      static_cast<size_t>(batch) * frame_stride;
  for (uint32_t i = threadIdx.x; i < kSymbolsPerBlock; i += blockDim.x) {
    record[kSignFractionOffset + i] = block_sign[i];
  }
  for (uint32_t i = threadIdx.x; i < kPhaseBytesPerBlock; i += blockDim.x) {
    record[kPhaseOffset + i] = block_phase[i];
  }
  for (size_t i = threadIdx.x; i < frame_bytes; i += blockDim.x) {
    record[kFrameOffset + i] = block_frame[i];
  }
  if (threadIdx.x == 0) {
    auto* header = reinterpret_cast<ExpansRecordHeader*>(record);
    *header = ExpansRecordHeader{
        kRecordMagic,
        kRecordVersion,
        kRecordHeaderBytes,
        expected_layout_id,
        kRawBytesPerBlock,
        static_cast<uint32_t>(actual_bytes),
        kSignFractionOffset,
        kSymbolsPerBlock,
        kPhaseOffset,
        kPhaseBytesPerBlock,
        kFrameOffset,
        static_cast<uint32_t>(frame_bytes),
        0,
        {0, 0, 0}};
  }
}

__global__ void unpack_records(
    const uint8_t* records,
    uint32_t record_bytes,
    const uint32_t* record_indexes,
    uint8_t* sign_fraction,
    uint8_t* phase_bitmaps,
    uint8_t* frames,
    size_t frame_stride,
    uint32_t batches) {
  const uint32_t batch = blockIdx.x;
  if (batch >= batches) return;
  const uint8_t* record = records +
      static_cast<size_t>(record_indexes[batch]) * record_bytes;
  const auto* header = reinterpret_cast<const ExpansRecordHeader*>(record);
  uint8_t* block_sign = sign_fraction +
      static_cast<size_t>(batch) * kSymbolsPerBlock;
  uint8_t* block_phase = phase_bitmaps +
      static_cast<size_t>(batch) * kPhaseBytesPerBlock;
  uint8_t* block_frame = frames +
      static_cast<size_t>(batch) * frame_stride;
  for (uint32_t i = threadIdx.x; i < kSymbolsPerBlock; i += blockDim.x) {
    block_sign[i] = record[header->sign_fraction_offset + i];
  }
  for (uint32_t i = threadIdx.x; i < kPhaseBytesPerBlock; i += blockDim.x) {
    block_phase[i] = record[header->phase_offset + i];
  }
  for (uint32_t i = threadIdx.x; i < header->frame_bytes; i += blockDim.x) {
    block_frame[i] = record[header->frame_offset + i];
  }
}

bool valid_layout(
    const uint32_t* sizes,
    const uint32_t* offsets,
    uint32_t blocks,
    const std::vector<uint32_t>& expected) {
  if (!sizes || !offsets || offsets[0] != 0) return false;
  for (uint32_t block = 0; block < blocks; ++block) {
    if (offsets[block + 1] - offsets[block] != expected.size()) return false;
    for (uint32_t segment = 0; segment < expected.size(); ++segment) {
      if (sizes[offsets[block] + segment] != expected[segment]) return false;
    }
  }
  return true;
}

}

struct openlake_expans_codec {
  uint32_t record_bytes = 0;
  uint32_t max_batch_blocks = 0;
  uint32_t segment_count = 0;
  size_t frame_stride = 0;
  size_t compress_temp_bytes = 0;
  size_t decompress_temp_bytes = 0;
  int device = 0;
  uint64_t layout = 0;
  nvcompBatchedANSCompressOpts_t compress_opts =
      nvcompBatchedANSCompressDefaultOpts;
  nvcompBatchedANSDecompressOpts_t decompress_opts =
      nvcompBatchedANSDecompressDefaultOpts;
  std::vector<uint32_t> segment_bytes;
  std::string error;
  uint8_t* input = nullptr;
  uint8_t* output = nullptr;
  uint8_t* centers = nullptr;
  uint8_t* phase_bitmaps = nullptr;
  uint8_t* sign_fraction = nullptr;
  uint8_t* residual = nullptr;
  uint8_t* frames = nullptr;
  void** residual_ptrs = nullptr;
  void** frame_ptrs = nullptr;
  size_t* raw_sizes = nullptr;
  size_t* frame_sizes = nullptr;
  size_t* decoded_sizes = nullptr;
  nvcompStatus_t* statuses = nullptr;
  void* compress_temp = nullptr;
  void* decompress_temp = nullptr;
  uint64_t* addresses = nullptr;
  uint32_t* segment_offsets = nullptr;
  uint32_t* record_indexes = nullptr;
  uint32_t* histogram = nullptr;
  float* phase_costs = nullptr;
  uint8_t* fits = nullptr;

  ~openlake_expans_codec() {
    cudaSetDevice(device);
    cudaFree(input);
    cudaFree(output);
    cudaFree(centers);
    cudaFree(phase_bitmaps);
    cudaFree(sign_fraction);
    cudaFree(residual);
    cudaFree(frames);
    cudaFree(residual_ptrs);
    cudaFree(frame_ptrs);
    cudaFree(raw_sizes);
    cudaFree(frame_sizes);
    cudaFree(decoded_sizes);
    cudaFree(statuses);
    cudaFree(compress_temp);
    cudaFree(decompress_temp);
    cudaFree(addresses);
    cudaFree(segment_offsets);
    cudaFree(record_indexes);
    cudaFree(histogram);
    cudaFree(phase_costs);
    cudaFree(fits);
  }
};

namespace {

int fail(openlake_expans_codec* codec, const std::string& message) {
  if (codec) codec->error = message;
  return 1;
}

int fail_cuda(openlake_expans_codec* codec, cudaError_t status, const char* op) {
  std::ostringstream message;
  message << op << ": " << cudaGetErrorString(status);
  return fail(codec, message.str());
}

int fail_nvcomp(
    openlake_expans_codec* codec, nvcompStatus_t status, const char* op) {
  std::ostringstream message;
  message << op << ": nvCOMP status " << static_cast<int>(status);
  return fail(codec, message.str());
}

#define EXPANS_ALLOC(member, count)                                            \
  do {                                                                         \
    const size_t bytes__ = static_cast<size_t>(count);                         \
    if (bytes__ != 0) {                                                        \
      cudaError_t status__ = cudaMalloc(&codec->member, bytes__);              \
      if (status__ != cudaSuccess) return fail_cuda(codec, status__, #member); \
    }                                                                          \
  } while (0)

bool valid_header(
    const ExpansRecordHeader& header,
    const openlake_expans_codec& codec) {
  return header.magic == kRecordMagic &&
      header.version == kRecordVersion &&
      header.header_bytes == kRecordHeaderBytes &&
      header.raw_bytes == kRawBytesPerBlock &&
      header.actual_bytes <= codec.record_bytes &&
      header.sign_fraction_offset == kSignFractionOffset &&
      header.sign_fraction_bytes == kSymbolsPerBlock &&
      header.phase_offset == kPhaseOffset &&
      header.phase_bytes == kPhaseBytesPerBlock &&
      header.frame_offset == kFrameOffset &&
      header.frame_bytes != 0 &&
      header.frame_bytes <= codec.frame_stride &&
      header.frame_offset + header.frame_bytes == header.actual_bytes &&
      header.layout_id == codec.layout;
}

}

extern "C" int openlake_expans_create(
    uint64_t raw_block_bytes,
    uint64_t record_bytes,
    const uint32_t* segment_bytes,
    uint32_t segment_count,
    uint32_t max_batch_blocks,
    openlake_expans_codec** output) {
  if (!output) return 1;
  *output = nullptr;
  auto codec = std::make_unique<openlake_expans_codec>();
  if (!segment_bytes || segment_count == 0 || max_batch_blocks == 0) {
    return fail(codec.get(), "invalid ExpANS creation arguments");
  }
  if (raw_block_bytes != kRawBytesPerBlock ||
      record_bytes <= kFrameOffset || record_bytes >= raw_block_bytes ||
      record_bytes > UINT32_MAX) {
    return fail(codec.get(), "unsupported ExpANS block or record size");
  }
  codec->record_bytes = static_cast<uint32_t>(record_bytes);
  codec->segment_count = segment_count;
  codec->max_batch_blocks = max_batch_blocks;
  codec->segment_bytes.assign(segment_bytes, segment_bytes + segment_count);
  uint64_t sum = 0;
  for (uint32_t bytes : codec->segment_bytes) sum += bytes;
  if (sum != raw_block_bytes) {
    return fail(codec.get(), "segment bytes do not form one ExpANS block");
  }
  codec->layout = layout_id(segment_bytes, segment_count);
  cudaError_t status = cudaGetDevice(&codec->device);
  if (status != cudaSuccess) return fail_cuda(codec.get(), status, "cudaGetDevice");
  codec->compress_opts.data_type = NVCOMP_TYPE_UCHAR;
  nvcompStatus_t nvcomp_status = nvcompBatchedANSCompressGetMaxOutputChunkSize(
      kSymbolsPerBlock, codec->compress_opts, &codec->frame_stride);
  if (nvcomp_status != nvcompSuccess) {
    return fail_nvcomp(
        codec.get(), nvcomp_status,
        "nvcompBatchedANSCompressGetMaxOutputChunkSize");
  }
  codec->frame_stride =
      (codec->frame_stride + kRecordAlignment - 1) & ~(kRecordAlignment - 1);
  const size_t blocks = max_batch_blocks;
  const size_t symbols = blocks * kSymbolsPerBlock;
  nvcomp_status = nvcompBatchedANSCompressGetTempSizeAsync(
      blocks, kSymbolsPerBlock, codec->compress_opts,
      &codec->compress_temp_bytes, symbols);
  if (nvcomp_status != nvcompSuccess) {
    return fail_nvcomp(
        codec.get(), nvcomp_status,
        "nvcompBatchedANSCompressGetTempSizeAsync");
  }
  nvcomp_status = nvcompBatchedANSDecompressGetTempSizeAsync(
      blocks, kSymbolsPerBlock, codec->decompress_opts,
      &codec->decompress_temp_bytes, symbols);
  if (nvcomp_status != nvcompSuccess) {
    return fail_nvcomp(
        codec.get(), nvcomp_status,
        "nvcompBatchedANSDecompressGetTempSizeAsync");
  }
  const size_t address_count = blocks * segment_count;
  EXPANS_ALLOC(input, blocks * kRawBytesPerBlock);
  EXPANS_ALLOC(output, blocks * kRawBytesPerBlock);
  EXPANS_ALLOC(centers, kSymbolsPerBlock);
  EXPANS_ALLOC(phase_bitmaps, blocks * kPhaseBytesPerBlock);
  EXPANS_ALLOC(sign_fraction, symbols);
  EXPANS_ALLOC(residual, symbols);
  EXPANS_ALLOC(frames, blocks * codec->frame_stride);
  EXPANS_ALLOC(residual_ptrs, blocks * sizeof(void*));
  EXPANS_ALLOC(frame_ptrs, blocks * sizeof(void*));
  EXPANS_ALLOC(raw_sizes, blocks * sizeof(size_t));
  EXPANS_ALLOC(frame_sizes, blocks * sizeof(size_t));
  EXPANS_ALLOC(decoded_sizes, blocks * sizeof(size_t));
  EXPANS_ALLOC(statuses, blocks * sizeof(nvcompStatus_t));
  EXPANS_ALLOC(compress_temp, codec->compress_temp_bytes);
  EXPANS_ALLOC(decompress_temp, codec->decompress_temp_bytes);
  EXPANS_ALLOC(addresses, address_count * sizeof(uint64_t));
  EXPANS_ALLOC(segment_offsets, (segment_count + 1) * sizeof(uint32_t));
  EXPANS_ALLOC(record_indexes, blocks * sizeof(uint32_t));
  EXPANS_ALLOC(histogram, 256 * sizeof(uint32_t));
  EXPANS_ALLOC(phase_costs, 256 * sizeof(float));
  EXPANS_ALLOC(fits, blocks);

  status = cudaMemset(codec->centers, 127, kSymbolsPerBlock);
  if (status != cudaSuccess) {
    return fail_cuda(codec.get(), status, "initialize centers");
  }
  std::vector<uint32_t> offsets(segment_count + 1, 0);
  for (uint32_t i = 0; i < segment_count; ++i) {
    offsets[i + 1] = offsets[i] + segment_bytes[i];
  }
  status = cudaMemcpy(
      codec->segment_offsets, offsets.data(), offsets.size() * sizeof(uint32_t),
      cudaMemcpyHostToDevice);
  if (status != cudaSuccess) {
    return fail_cuda(codec.get(), status, "copy segment layout");
  }
  std::vector<void*> residual_ptrs(blocks);
  std::vector<void*> frame_ptrs(blocks);
  std::vector<size_t> raw_sizes(blocks, kSymbolsPerBlock);
  for (size_t block = 0; block < blocks; ++block) {
    residual_ptrs[block] = codec->residual + block * kSymbolsPerBlock;
    frame_ptrs[block] = codec->frames + block * codec->frame_stride;
  }
  status = cudaMemcpy(
      codec->residual_ptrs, residual_ptrs.data(), blocks * sizeof(void*),
      cudaMemcpyHostToDevice);
  if (status != cudaSuccess) {
    return fail_cuda(codec.get(), status, "copy residual pointers");
  }
  status = cudaMemcpy(
      codec->frame_ptrs, frame_ptrs.data(), blocks * sizeof(void*),
      cudaMemcpyHostToDevice);
  if (status != cudaSuccess) {
    return fail_cuda(codec.get(), status, "copy frame pointers");
  }
  status = cudaMemcpy(
      codec->raw_sizes, raw_sizes.data(), blocks * sizeof(size_t),
      cudaMemcpyHostToDevice);
  if (status != cudaSuccess) {
    return fail_cuda(codec.get(), status, "copy raw sizes");
  }
  *output = codec.release();
  return 0;
}

extern "C" void openlake_expans_destroy(openlake_expans_codec* codec) {
  delete codec;
}

extern "C" const char* openlake_expans_last_error(openlake_expans_codec* codec) {
  return codec ? codec->error.c_str() : "invalid ExpANS codec";
}

extern "C" int openlake_expans_encode(
    openlake_expans_codec* codec,
    const uint64_t* input_addresses,
    const uint32_t* input_sizes,
    const uint32_t* block_segment_offsets,
    uint32_t block_count,
    uint64_t output_records,
    uint8_t* host_fits,
    uint64_t cuda_stream) {
  if (!codec || !input_addresses || !host_fits || output_records == 0 ||
      block_count == 0 || block_count > codec->max_batch_blocks ||
      !valid_layout(input_sizes, block_segment_offsets, block_count,
                    codec->segment_bytes)) {
    return fail(codec, "invalid ExpANS encode arguments or scatter layout");
  }
  cudaError_t status = cudaSetDevice(codec->device);
  if (status != cudaSuccess) return fail_cuda(codec, status, "cudaSetDevice");
  auto stream = reinterpret_cast<cudaStream_t>(cuda_stream);
  const size_t address_count =
      static_cast<size_t>(block_count) * codec->segment_count;
  status = cudaMemcpyAsync(
      codec->addresses, input_addresses, address_count * sizeof(uint64_t),
      cudaMemcpyHostToDevice, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "copy input addresses");
  gather_segments<<<address_count, 256, 0, stream>>>(
      codec->addresses, codec->segment_offsets, codec->segment_count,
      codec->input, block_count);
  status = cudaMemsetAsync(
      codec->phase_bitmaps, 0,
      static_cast<size_t>(block_count) * kPhaseBytesPerBlock, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "clear phase bitmap");
  const size_t words = static_cast<size_t>(block_count) * kSymbolsPerBlock;
  const int vectors = static_cast<int>(((words / 8) + 255) / 256);
  status = cudaMemsetAsync(codec->histogram, 0, 256 * sizeof(uint32_t), stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "clear histogram");
  status = cudaMemsetAsync(
      codec->frame_sizes, 0, block_count * sizeof(size_t), stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "clear frame sizes");
  const int histogram_blocks = static_cast<int>((words + 255) / 256);
  residual_histogram<<<histogram_blocks, 256, 0, stream>>>(
      reinterpret_cast<const uint16_t*>(codec->input), codec->centers,
      codec->histogram, words);
  histogram_costs<<<1, 256, 0, stream>>>(
      codec->histogram, codec->phase_costs, static_cast<uint32_t>(words));
  fit_group_direction_phases<<<block_count * kGroups, 1024, 0, stream>>>(
      reinterpret_cast<const uint16_t*>(codec->input), codec->centers,
      codec->phase_costs, codec->phase_bitmaps, block_count);
  split_bf16_position_phase<<<vectors, 256, 0, stream>>>(
      reinterpret_cast<const uint16_t*>(codec->input), codec->centers,
      codec->phase_bitmaps, codec->sign_fraction, codec->residual, words);
  nvcompStatus_t nvcomp_status = nvcompBatchedANSCompressAsync(
      const_cast<const void* const*>(codec->residual_ptrs), codec->raw_sizes,
      kSymbolsPerBlock, block_count, codec->compress_temp,
      codec->compress_temp_bytes, codec->frame_ptrs, codec->frame_sizes,
      codec->compress_opts, codec->statuses, stream);
  if (nvcomp_status != nvcompSuccess) {
    return fail_nvcomp(codec, nvcomp_status, "nvcompBatchedANSCompressAsync");
  }
  status = cudaMemsetAsync(
      reinterpret_cast<void*>(output_records), 0,
      static_cast<size_t>(block_count) * codec->record_bytes, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "clear output records");
  pack_records<<<block_count, 256, 0, stream>>>(
      reinterpret_cast<uint8_t*>(output_records), codec->record_bytes,
      codec->sign_fraction, codec->phase_bitmaps, codec->frames,
      codec->frame_stride, codec->frame_sizes, codec->fits, codec->layout,
      block_count);
  std::vector<nvcompStatus_t> statuses(block_count);
  status = cudaMemcpyAsync(
      host_fits, codec->fits, block_count, cudaMemcpyDeviceToHost, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "copy fit results");
  status = cudaMemcpyAsync(
      statuses.data(), codec->statuses,
      block_count * sizeof(nvcompStatus_t), cudaMemcpyDeviceToHost, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "copy nvCOMP statuses");
  status = cudaStreamSynchronize(stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "encode synchronize");
  for (nvcompStatus_t value : statuses) {
    if (value != nvcompSuccess) {
      return fail_nvcomp(codec, value, "nvCOMP encode operation");
    }
  }
  return 0;
}

extern "C" int openlake_expans_decode(
    openlake_expans_codec* codec,
    uint64_t input_records,
    const uint32_t* record_indexes,
    uint32_t record_count,
    const uint64_t* output_addresses,
    const uint32_t* output_sizes,
    const uint32_t* block_segment_offsets,
    uint64_t cuda_stream) {
  if (!codec || input_records == 0 || !record_indexes || !output_addresses ||
      record_count == 0 || record_count > codec->max_batch_blocks ||
      !valid_layout(output_sizes, block_segment_offsets, record_count,
                    codec->segment_bytes)) {
    return fail(codec, "invalid ExpANS decode arguments or scatter layout");
  }
  cudaError_t status = cudaSetDevice(codec->device);
  if (status != cudaSuccess) return fail_cuda(codec, status, "cudaSetDevice");
  auto stream = reinterpret_cast<cudaStream_t>(cuda_stream);
  std::vector<ExpansRecordHeader> headers(record_count);
  for (uint32_t i = 0; i < record_count; ++i) {
    if (record_indexes[i] >= codec->max_batch_blocks) {
      return fail(codec, "ExpANS record index exceeds lane capacity");
    }
    status = cudaMemcpyAsync(
        &headers[i],
        reinterpret_cast<const uint8_t*>(input_records) +
            static_cast<size_t>(record_indexes[i]) * codec->record_bytes,
        sizeof(ExpansRecordHeader), cudaMemcpyDeviceToHost, stream);
    if (status != cudaSuccess) return fail_cuda(codec, status, "copy record header");
  }
  status = cudaStreamSynchronize(stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "header synchronize");
  std::vector<size_t> frame_sizes(record_count);
  for (uint32_t i = 0; i < record_count; ++i) {
    if (!valid_header(headers[i], *codec)) {
      return fail(codec, "invalid or incompatible ExpANS record header");
    }
    frame_sizes[i] = headers[i].frame_bytes;
  }
  const size_t address_count =
      static_cast<size_t>(record_count) * codec->segment_count;
  status = cudaMemcpyAsync(
      codec->record_indexes, record_indexes, record_count * sizeof(uint32_t),
      cudaMemcpyHostToDevice, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "copy record indexes");
  status = cudaMemcpyAsync(
      codec->addresses, output_addresses, address_count * sizeof(uint64_t),
      cudaMemcpyHostToDevice, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "copy output addresses");
  status = cudaMemcpyAsync(
      codec->frame_sizes, frame_sizes.data(), record_count * sizeof(size_t),
      cudaMemcpyHostToDevice, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "copy frame sizes");
  unpack_records<<<record_count, 256, 0, stream>>>(
      reinterpret_cast<const uint8_t*>(input_records), codec->record_bytes,
      codec->record_indexes, codec->sign_fraction, codec->phase_bitmaps,
      codec->frames, codec->frame_stride, record_count);
  nvcompStatus_t nvcomp_status = nvcompBatchedANSDecompressAsync(
      const_cast<const void* const*>(codec->frame_ptrs), codec->frame_sizes,
      codec->raw_sizes, codec->decoded_sizes, record_count,
      codec->decompress_temp, codec->decompress_temp_bytes,
      codec->residual_ptrs, codec->decompress_opts, codec->statuses, stream);
  if (nvcomp_status != nvcompSuccess) {
    return fail_nvcomp(codec, nvcomp_status, "nvcompBatchedANSDecompressAsync");
  }
  const size_t words = static_cast<size_t>(record_count) * kSymbolsPerBlock;
  const int vectors = static_cast<int>(((words / 8) + 255) / 256);
  merge_bf16_position_phase<<<vectors, 256, 0, stream>>>(
      codec->residual, codec->sign_fraction, codec->centers,
      codec->phase_bitmaps, reinterpret_cast<uint16_t*>(codec->output), words);
  scatter_segments<<<address_count, 256, 0, stream>>>(
      codec->output, codec->addresses, codec->segment_offsets,
      codec->segment_count, record_count);
  std::vector<nvcompStatus_t> statuses(record_count);
  std::vector<size_t> decoded_sizes(record_count);
  status = cudaMemcpyAsync(
      statuses.data(), codec->statuses,
      record_count * sizeof(nvcompStatus_t), cudaMemcpyDeviceToHost, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "copy nvCOMP statuses");
  status = cudaMemcpyAsync(
      decoded_sizes.data(), codec->decoded_sizes,
      record_count * sizeof(size_t), cudaMemcpyDeviceToHost, stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "copy decoded sizes");
  status = cudaStreamSynchronize(stream);
  if (status != cudaSuccess) return fail_cuda(codec, status, "decode synchronize");
  for (uint32_t i = 0; i < record_count; ++i) {
    if (statuses[i] != nvcompSuccess) {
      return fail_nvcomp(codec, statuses[i], "nvCOMP decode operation");
    }
    if (decoded_sizes[i] != kSymbolsPerBlock) {
      return fail(codec, "nvCOMP decoded an incompatible ExpANS frame");
    }
  }
  return 0;
}
