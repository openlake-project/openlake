//! Erasure coding for the object data path, on top of the
//! `reed-solomon-simd` crate.
//!
//! `reed-solomon-simd` accepts any `T: AsRef<[u8]>` for shard inputs
//! (no `Vec<u8>` requirement) and yields recovery / restored shards as
//! `&[u8]` borrowed from the encoder/decoder. This lets us:
//!   * Pass slices of pool-backed buffers / `Bytes` straight to the
//!     encoder — no `Vec<u8>↔PooledBuffer` conversion at the trait
//!     boundary (this killed `E` from the memcpy audit).
//!   * Pass slices of network-fetched shard buffers straight to the
//!     decoder — no `buf.clone()` into a `Vec<Option<Vec<u8>>>` slot
//!     for the legacy reconstruct API (killed `G`).
//!
//! The crate auto-detects SSSE3/AVX2/NEON at load and uses the FFT
//! algorithm — typically 5-15× faster than the byte-wise Galois field
//! reference impl, and faster than `reed-solomon-erasure` even with
//! its `simd-accel` C-bindings feature on most CPUs.
//!
//! Constraint: `shard_bytes` must be even (`% 2 == 0`). The engine's
//! per-shard sizing already aligns to KB so this is satisfied; we
//! still validate explicitly.

use std::io;

use bytes::Bytes;
use phenomenal_io::PooledBuffer;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

/// Shard size used for an object payload.
///
/// `block_size` is the byte length of one encoder "block". For a
/// single-block payload (which is what we use today — the engine
/// buffers the full object and encodes it as one block) this equals
/// the object size, padded up so that every data shard is the same
/// length.
pub fn shard_size(block_size: usize, data_shards: usize) -> usize {
    let raw = block_size.div_ceil(data_shards);
    // reed-solomon-simd requires `shard_bytes % 2 == 0`. Round up.
    raw + (raw & 1)
}

/// Reed-Solomon erasure coder.
///
/// `data_shards` of original data + `parity_shards` of parity. Total
/// disks per set = `data_shards + parity_shards`. Read quorum =
/// `data_shards`, write quorum (today, no healer) =
/// `data_shards + parity_shards`.
#[derive(Clone)]
pub struct Erasure {
    pub data_shards:   usize,
    pub parity_shards: usize,
}

impl Erasure {
    pub fn new(data_shards: usize, parity_shards: usize) -> io::Result<Self> {
        if data_shards == 0 || parity_shards == 0 {
            return Err(io::Error::other(format!(
                "EC requires data_shards>=1 and parity_shards>=1 (got {data_shards}+{parity_shards})"
            )));
        }
        Ok(Self { data_shards, parity_shards })
    }

    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Encode one full stripe (`data_shards * unit` bytes, already
    /// zero-padded) into `data_shards + parity_shards` shards. Returns
    /// the shards in slot order: D data shards first (zero-copy slices
    /// of `stripe`), then P parity shards (fresh pool-backed buffers
    /// frozen to `Bytes`).
    pub fn encode_stripe(&self, stripe: Bytes) -> io::Result<Vec<Bytes>> {
        let n = self.data_shards;
        let m = self.parity_shards;
        let total_len = stripe.len();
        if total_len == 0 || total_len % n != 0 {
            return Err(io::Error::other(format!(
                "encode_stripe: stripe len {total_len} not divisible by {n} data shards"
            )));
        }
        let unit = total_len / n;
        if unit % 2 != 0 {
            return Err(io::Error::other(format!(
                "encode_stripe: shard unit {unit} must be even"
            )));
        }

        let mut encoder = ReedSolomonEncoder::new(n, m, unit)
            .map_err(|e| io::Error::other(format!("RS encoder new: {e:?}")))?;

        // Slice each data shard out of `stripe` zero-copy and feed it
        // to the encoder. The encoder's `add_original_shard` does an
        // internal `copy_from_slice` into its own SIMD-aligned buffer
        // — that copy is fundamental to the FFT-based algorithm and
        // can't be avoided at the API boundary.
        let mut out: Vec<Bytes> = Vec::with_capacity(n + m);
        for i in 0..n {
            let shard = stripe.slice(i * unit..(i + 1) * unit);
            encoder.add_original_shard(&shard)
                .map_err(|e| io::Error::other(format!("RS add original {i}: {e:?}")))?;
            out.push(shard);
        }

        let result = encoder.encode()
            .map_err(|e| io::Error::other(format!("RS encode: {e:?}")))?;

        // Recovery shards come back as `&[u8]` borrowed from the
        // encoder. We materialize each into a fresh PooledBuffer so
        // the resulting `Bytes` outlives the encoder (the sink writes
        // are awaited concurrently below the encoder's lifetime). The
        // pool recycles each parity shard's allocation when the sink
        // drops the `Bytes` after writev completes.
        for i in 0..m {
            let parity = result.recovery(i).ok_or_else(|| {
                io::Error::other(format!("encode: recovery shard {i} missing"))
            })?;
            let mut pb = PooledBuffer::with_capacity(parity.len());
            pb.extend_from_slice(parity);
            out.push(pb.freeze());
        }

        Ok(out)
    }

    /// Decode one stripe from a vector of length
    /// `data_shards + parity_shards` where slots are `Some(shard)` for
    /// shards we read successfully and `None` for missing/failed
    /// disks. Returns `D` data shards in slot order — originals
    /// returned as zero-copy clones of the input `Bytes` where
    /// available, missing slots restored from parity (one fresh
    /// pool-backed buffer per missing shard).
    ///
    /// Caller composes the stripe payload by concatenating the
    /// returned shards, or serves them as separate frames from a
    /// `RopeByteStream`-style reader.
    pub fn decode_stripe(
        &self,
        shards: Vec<Option<Bytes>>,
        unit: usize,
    ) -> io::Result<Vec<Bytes>> {
        let n = self.data_shards;
        let m = self.parity_shards;
        if shards.len() != n + m {
            return Err(io::Error::other(format!(
                "decode_stripe: expected {} shard slots, got {}",
                n + m,
                shards.len()
            )));
        }
        if unit == 0 || unit % 2 != 0 {
            return Err(io::Error::other(format!(
                "decode_stripe: shard unit {unit} must be non-zero and even"
            )));
        }

        // Count what's present — fast-path the all-original case.
        let originals_present = shards[..n].iter().filter(|s| s.is_some()).count();
        if originals_present == n {
            // All D data shards available — no decoding needed.
            // Return them as zero-copy clones; ignore parity.
            return Ok(shards.into_iter().take(n)
                .map(|s| s.expect("checked is_some"))
                .collect());
        }

        let mut decoder = ReedSolomonDecoder::new(n, m, unit)
            .map_err(|e| io::Error::other(format!("RS decoder new: {e:?}")))?;

        // Feed every shard we have. The decoder enforces "at least D
        // total" internally and errors if we're below quorum.
        for (i, slot) in shards.iter().enumerate().take(n) {
            if let Some(s) = slot {
                if s.len() != unit {
                    return Err(io::Error::other(format!(
                        "decode_stripe: original shard {i} len {} != unit {unit}", s.len()
                    )));
                }
                decoder.add_original_shard(i, s)
                    .map_err(|e| io::Error::other(format!("RS add original {i}: {e:?}")))?;
            }
        }
        for (i, slot) in shards.iter().enumerate().skip(n) {
            if let Some(s) = slot {
                if s.len() != unit {
                    return Err(io::Error::other(format!(
                        "decode_stripe: recovery shard {i} len {} != unit {unit}", s.len()
                    )));
                }
                decoder.add_recovery_shard(i - n, s)
                    .map_err(|e| io::Error::other(format!("RS add recovery {i}: {e:?}")))?;
            }
        }

        let result = decoder.decode()
            .map_err(|e| io::Error::other(format!("RS decode: {e:?}")))?;

        // Build the D data shards. Originals we had are zero-copy
        // clones of the caller's `Bytes`; restored ones get copied
        // out of the decoder's internal buffer into a fresh
        // pool-backed allocation.
        let mut out: Vec<Bytes> = Vec::with_capacity(n);
        for i in 0..n {
            match &shards[i] {
                Some(orig) => out.push(orig.clone()),
                None => {
                    let restored = result.restored_original(i).ok_or_else(|| {
                        io::Error::other(format!("decode: shard {i} not restored"))
                    })?;
                    let mut pb = PooledBuffer::with_capacity(restored.len());
                    pb.extend_from_slice(restored);
                    out.push(pb.freeze());
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 31 + 7) % 251) as u8).collect()
    }

    /// Pad a payload up to D × unit bytes so the encoder sees a full stripe.
    fn pad_stripe(payload: Vec<u8>, data_shards: usize) -> (Bytes, usize) {
        let unit = shard_size(payload.len().max(2), data_shards);
        let total = unit * data_shards;
        let mut padded = payload;
        padded.resize(total, 0);
        (Bytes::from(padded), unit)
    }

    #[test]
    fn round_trip_no_loss() {
        let ec = Erasure::new(6, 2).unwrap();
        let data = random_payload(16384);
        let (stripe, unit) = pad_stripe(data.clone(), ec.data_shards);
        let shards = ec.encode_stripe(stripe).unwrap();
        let opts: Vec<Option<Bytes>> = shards.into_iter().map(Some).collect();
        let restored = ec.decode_stripe(opts, unit).unwrap();
        let mut concat: Vec<u8> = Vec::new();
        for s in &restored { concat.extend_from_slice(s); }
        concat.truncate(data.len());
        assert_eq!(concat, data);
    }

    #[test]
    fn round_trip_two_data_shards_lost() {
        let ec = Erasure::new(6, 2).unwrap();
        let data = random_payload(16384);
        let (stripe, unit) = pad_stripe(data.clone(), ec.data_shards);
        let shards = ec.encode_stripe(stripe).unwrap();
        let mut opts: Vec<Option<Bytes>> = shards.into_iter().map(Some).collect();
        opts[0] = None;
        opts[3] = None;
        let restored = ec.decode_stripe(opts, unit).unwrap();
        let mut concat: Vec<u8> = Vec::new();
        for s in &restored { concat.extend_from_slice(s); }
        concat.truncate(data.len());
        assert_eq!(concat, data);
    }

    #[test]
    fn fails_when_below_quorum() {
        let ec = Erasure::new(6, 2).unwrap();
        let data = b"hello world".to_vec();
        let (stripe, unit) = pad_stripe(data, ec.data_shards);
        let shards = ec.encode_stripe(stripe).unwrap();
        // Drop 3 shards — past the 2-parity budget.
        let mut opts: Vec<Option<Bytes>> = shards.into_iter().map(Some).collect();
        opts[0] = None;
        opts[1] = None;
        opts[2] = None;
        assert!(ec.decode_stripe(opts, unit).is_err());
    }

    #[test]
    fn empty_payload_round_trip() {
        // For an "empty" object the engine passes a zero-padded stripe;
        // verify the encoder/decoder accept it and round-trip cleanly.
        let ec = Erasure::new(3, 1).unwrap();
        let unit = 64usize;
        let stripe = Bytes::from(vec![0u8; unit * ec.data_shards]);
        let shards = ec.encode_stripe(stripe).unwrap();
        let opts: Vec<Option<Bytes>> = shards.into_iter().map(Some).collect();
        let restored = ec.decode_stripe(opts, unit).unwrap();
        for s in &restored { assert!(s.iter().all(|&b| b == 0)); }
    }
}
