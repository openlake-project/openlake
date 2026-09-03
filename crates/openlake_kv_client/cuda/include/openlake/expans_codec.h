#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct openlake_expans_codec openlake_expans_codec;

int openlake_expans_create(
    uint64_t raw_block_bytes,
    uint64_t record_bytes,
    const uint32_t* segment_bytes,
    uint32_t segment_count,
    uint32_t max_batch_blocks,
    openlake_expans_codec** output);

void openlake_expans_destroy(openlake_expans_codec* codec);

const char* openlake_expans_last_error(openlake_expans_codec* codec);

int openlake_expans_encode(
    openlake_expans_codec* codec,
    const uint64_t* input_addresses,
    const uint32_t* input_sizes,
    const uint32_t* block_segment_offsets,
    uint32_t block_count,
    uint64_t output_records,
    uint8_t* host_fits,
    uint64_t cuda_stream);

int openlake_expans_decode(
    openlake_expans_codec* codec,
    uint64_t input_records,
    const uint32_t* record_indexes,
    uint32_t record_count,
    const uint64_t* output_addresses,
    const uint32_t* output_sizes,
    const uint32_t* block_segment_offsets,
    uint64_t cuda_stream);

#ifdef __cplusplus
}
#endif
