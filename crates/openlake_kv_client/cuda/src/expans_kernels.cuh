#pragma once

#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>

namespace {

constexpr uint32_t kGroups = 122;
constexpr uint32_t kSymbolsPerGroup = 4096;
constexpr uint32_t kSymbolsPerBlock = kGroups * kSymbolsPerGroup;
constexpr uint32_t kRawBytesPerBlock = kSymbolsPerBlock * sizeof(uint16_t);
constexpr uint32_t kPhaseUnitValues = 128;
constexpr uint32_t kPhaseUnitsPerBlock =
    kSymbolsPerBlock / kPhaseUnitValues;
constexpr uint32_t kPhasePresenceBytes = kPhaseUnitsPerBlock / 8;
constexpr uint32_t kPhaseDirectionBytes =
    ((kGroups * 2 + 31) / 32) * sizeof(uint32_t);
constexpr uint32_t kPhaseBytesPerBlock =
    kPhasePresenceBytes + kPhaseDirectionBytes;

static_assert(kSymbolsPerBlock % kPhaseUnitValues == 0);

__device__ __forceinline__ int32_t phase_for_position(
    const uint8_t* bitmap, uint32_t position) {
  const uint32_t unit = position / kPhaseUnitValues;
  const uint32_t present = (bitmap[unit >> 3] >> (unit & 7U)) & 1U;
  if (!present) return 0;
  const uint32_t direction_bit = (position / kSymbolsPerGroup) * 2;
  const uint32_t code =
      (bitmap[kPhasePresenceBytes + (direction_bit >> 3)] >>
       (direction_bit & 7U)) & 3U;
  return code == 0 ? -2 : (code == 1 ? -1 : 1);
}

__device__ __forceinline__ float phase_warp_sum(float value) {
#pragma unroll
  for (int delta = 16; delta > 0; delta >>= 1) {
    value += __shfl_down_sync(0xffffffffU, value, delta);
  }
  return value;
}

__global__ __launch_bounds__(1024) void fit_group_direction_phases(
    const uint16_t* __restrict__ input,
    const uint8_t* __restrict__ centers,
    const float* __restrict__ costs,
    uint8_t* __restrict__ bitmaps,
    uint32_t batches) {
  const uint32_t block_group = blockIdx.x;
  if (block_group >= batches * kGroups) return;
  constexpr uint32_t units_per_group =
      kSymbolsPerGroup / kPhaseUnitValues;
  const uint32_t batch = block_group / kGroups;
  const uint32_t group = block_group % kGroups;
  const uint32_t warp = threadIdx.x >> 5;
  const uint32_t lane = threadIdx.x & 31;
  const uint32_t unit = group * units_per_group + warp;
  const uint32_t first = unit * kPhaseUnitValues;
  const size_t block_base = static_cast<size_t>(batch) * kSymbolsPerBlock;

  float local[4] = {0, 0, 0, 0};
  for (uint32_t i = lane; i < kPhaseUnitValues; i += 32) {
    const uint32_t position = first + i;
    const uint8_t exponent = static_cast<uint8_t>(
        (input[block_base + position] >> 7) & 0xffU);
    const uint8_t residual = static_cast<uint8_t>(
        static_cast<uint32_t>(exponent) + 127U - centers[position]);
    local[0] += costs[residual];
    local[1] += costs[static_cast<uint8_t>(residual + 2U)];
    local[2] += costs[static_cast<uint8_t>(residual + 1U)];
    local[3] += costs[static_cast<uint8_t>(residual - 1U)];
  }

  __shared__ float unit_costs[units_per_group][4];
#pragma unroll
  for (int candidate = 0; candidate < 4; ++candidate) {
    const float total = phase_warp_sum(local[candidate]);
    if (lane == 0) unit_costs[warp][candidate] = total;
  }
  __syncthreads();

  __shared__ uint32_t selected_candidate;
  if (warp == 0) {
    float group_cost[3];
#pragma unroll
    for (int candidate = 1; candidate < 4; ++candidate) {
      const float contribution =
          fminf(unit_costs[lane][0], unit_costs[lane][candidate]);
      group_cost[candidate - 1] = phase_warp_sum(contribution);
    }
    if (lane == 0) {
      uint32_t best = 1;
      if (group_cost[1] < group_cost[0]) best = 2;
      if (group_cost[2] < group_cost[best - 1]) best = 3;
      selected_candidate = best;
      uint8_t* bitmap = bitmaps +
          static_cast<size_t>(batch) * kPhaseBytesPerBlock;
      auto* directions = reinterpret_cast<uint32_t*>(
          bitmap + kPhasePresenceBytes);
      atomicOr(
          directions + ((group * 2) >> 5),
          (best - 1) << ((group * 2) & 31));
    }
  }
  __syncthreads();
  if (lane == 0 &&
      unit_costs[warp][selected_candidate] < unit_costs[warp][0]) {
    uint8_t* bitmap = bitmaps +
        static_cast<size_t>(batch) * kPhaseBytesPerBlock;
    auto* presence = reinterpret_cast<uint32_t*>(bitmap);
    atomicOr(presence + (unit >> 5), 1U << (unit & 31));
  }
}

__global__ void split_bf16_position_phase(
    const uint16_t* __restrict__ input,
    const uint8_t* __restrict__ centers,
    const uint8_t* __restrict__ phase_bitmaps,
    uint8_t* __restrict__ sign_fraction,
    uint8_t* __restrict__ residual,
    size_t words) {
  const size_t vector =
      static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  const size_t first = vector * 8;
  if (first >= words) return;
  const uint4 packed = *reinterpret_cast<const uint4*>(input + first);
  const uint32_t lanes[4] = {packed.x, packed.y, packed.z, packed.w};
  uint64_t packed_sm = 0;
  uint64_t packed_residual = 0;
#pragma unroll
  for (int lane = 0; lane < 4; ++lane) {
    const uint16_t values[2] = {
        static_cast<uint16_t>(lanes[lane]),
        static_cast<uint16_t>(lanes[lane] >> 16)};
#pragma unroll
    for (int half = 0; half < 2; ++half) {
      const size_t global = first + lane * 2 + half;
      const uint32_t batch = static_cast<uint32_t>(
          global / kSymbolsPerBlock);
      const uint32_t position = static_cast<uint32_t>(
          global % kSymbolsPerBlock);
      const uint8_t* bitmap = phase_bitmaps +
          static_cast<size_t>(batch) * kPhaseBytesPerBlock;
      const uint16_t value = values[half];
      const uint8_t exponent = static_cast<uint8_t>((value >> 7) & 0xffU);
      const uint8_t sm = static_cast<uint8_t>(
          ((value >> 8) & 0x80U) | (value & 0x7fU));
      const uint8_t centered = static_cast<uint8_t>(
          static_cast<uint32_t>(exponent) + 127U - centers[position]);
      const uint8_t transformed = static_cast<uint8_t>(
          centered - phase_for_position(bitmap, position));
      const int shift = lane * 16 + half * 8;
      packed_sm |= static_cast<uint64_t>(sm) << shift;
      packed_residual |= static_cast<uint64_t>(transformed) << shift;
    }
  }
  *reinterpret_cast<uint64_t*>(sign_fraction + first) = packed_sm;
  *reinterpret_cast<uint64_t*>(residual + first) = packed_residual;
}

__global__ void merge_bf16_position_phase(
    const uint8_t* __restrict__ residual,
    const uint8_t* __restrict__ sign_fraction,
    const uint8_t* __restrict__ centers,
    const uint8_t* __restrict__ phase_bitmaps,
    uint16_t* __restrict__ output,
    size_t words) {
  const size_t vector =
      static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  const size_t first = vector * 8;
  if (first >= words) return;
  const uint32_t batch = static_cast<uint32_t>(first / kSymbolsPerBlock);
  const uint32_t first_position = static_cast<uint32_t>(
      first % kSymbolsPerBlock);
  const uint8_t* bitmap = phase_bitmaps +
      static_cast<size_t>(batch) * kPhaseBytesPerBlock;
  const uint64_t packed_sm =
      *reinterpret_cast<const uint64_t*>(sign_fraction + first);
  const uint64_t packed_residual =
      *reinterpret_cast<const uint64_t*>(residual + first);
  uint32_t lanes[4];
#pragma unroll
  for (int lane = 0; lane < 4; ++lane) {
    uint32_t pair = 0;
#pragma unroll
    for (int half = 0; half < 2; ++half) {
      const int shift = lane * 16 + half * 8;
      const uint32_t position = first_position + lane * 2 + half;
      const uint8_t sm = static_cast<uint8_t>(packed_sm >> shift);
      const uint8_t transformed = static_cast<uint8_t>(
          packed_residual >> shift);
      const uint8_t exponent = static_cast<uint8_t>(
          static_cast<int32_t>(transformed) + centers[position] - 127 +
          phase_for_position(bitmap, position));
      const uint16_t value = static_cast<uint16_t>(
          ((sm & 0x80U) << 8) | (static_cast<uint16_t>(exponent) << 7) |
          (sm & 0x7fU));
      pair |= static_cast<uint32_t>(value) << (half * 16);
    }
    lanes[lane] = pair;
  }
  *reinterpret_cast<uint4*>(output + first) =
      make_uint4(lanes[0], lanes[1], lanes[2], lanes[3]);
}

}
