//! Bucketed lock-free buffer pool. Port of iggy's
//! `core/common/src/alloc/memory_pool.rs`, simplified for our needs
//! (no IggyByteSize / human_repr deps; plain bytes + a small inline
//! formatter for the stats line).

use aligned_vec::{AVec, ConstAlign};
use crossbeam_queue::ArrayQueue;
use once_cell::sync::OnceCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{info, trace, warn};

/// Page-size alignment for every pool allocation. 4 KiB is the
/// universal Linux page size; matches `O_DIRECT` and `io_uring`
/// registered-buffer requirements, so the same pool can serve both
/// the network and the disk paths once those land.
pub const ALIGNMENT: usize = 4096;

/// All pool allocations are this concrete type. `aligned_vec::AVec`
/// is a `Vec<u8>`-shaped owned buffer that guarantees the data
/// pointer is aligned to the const-generic value.
pub type AlignedBuffer = AVec<u8, ConstAlign<4096>>;

/// Number of distinct bucket sizes maintained by the pool.
const NUM_BUCKETS: usize = 28;

/// Bucket sizes in ascending order. Powers-of-2 below 2 MiB and a
/// few intermediate sizes (768 KiB, 1.5 MiB) to fit common shard
/// stripe widths. Above 2 MiB the table follows powers of 2 to keep
/// alignment with hugepage boundaries on hosts where that's enabled
/// at the allocator layer.
const BUCKET_SIZES: [usize; NUM_BUCKETS] = [
    4 * 1024,
    8 * 1024,
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    768 * 1024,
    1024 * 1024,
    1536 * 1024,
    2 * 1024 * 1024,
    4 * 1024 * 1024,
    6 * 1024 * 1024,
    8 * 1024 * 1024,
    10 * 1024 * 1024,
    12 * 1024 * 1024,
    16 * 1024 * 1024,
    24 * 1024 * 1024,
    32 * 1024 * 1024,
    48 * 1024 * 1024,
    64 * 1024 * 1024,
    96 * 1024 * 1024,
    128 * 1024 * 1024,
    192 * 1024 * 1024,
    256 * 1024 * 1024,
    384 * 1024 * 1024,
    512 * 1024 * 1024,
];

/// Global pool instance. Initialized once at process startup via
/// [`init_pool`]; subsequent acquires/releases lock-free through the
/// `OnceCell` static-ref read.
static MEMORY_POOL: OnceCell<MemoryPool> = OnceCell::new();

/// Get the global pool. If [`init_pool`] has not been called, the
/// pool is lazily initialised with `MemoryPoolConfig::default()`.
/// Production startup calls `init_pool` explicitly with operator
/// config before any runtime spawns; tests, helpers, or one-shot
/// CLIs that touch `PooledBuffer` without an explicit init still
/// get a working pool (with default sizing).
pub fn memory_pool() -> &'static MemoryPool {
    MEMORY_POOL.get_or_init(|| MemoryPool::new(&MemoryPoolConfig::default()))
}

/// Initialize the global pool with the given configuration. The
/// first caller wins — subsequent calls (and any lazy initialisation
/// via [`memory_pool`]) are no-ops. Production startup calls this in
/// `main()` before any runtime spawns.
pub fn init_pool(config: &MemoryPoolConfig) {
    let _ = MEMORY_POOL.get_or_init(|| MemoryPool::new(config));
}

/// Pool runtime configuration. Operators tune `size` and
/// `bucket_capacity` via TOML; `enabled = false` disables pool
/// participation entirely (every acquire goes straight to the
/// allocator), useful for diff-testing pool effects.
#[derive(Debug, Clone)]
pub struct MemoryPoolConfig {
    /// Master switch. When `false`, `acquire_buffer` always allocates
    /// fresh and `release_buffer` always drops — pool semantics are
    /// fully bypassed. Stats counters do not move.
    pub enabled: bool,
    /// Hard cap (bytes) on the total memory the pool will hold across
    /// all buckets. Allocations that would push past this go through
    /// the system allocator instead, tracked as `external_allocations`.
    pub size_bytes: usize,
    /// Maximum number of free buffers held in any one bucket. Returns
    /// past this are dropped (deallocated) and counted as
    /// `dropped_returns`. Bounds steady-state pool size at
    /// `bucket_capacity * sum(BUCKET_SIZES)`.
    pub bucket_capacity: usize,
}

impl Default for MemoryPoolConfig {
    fn default() -> Self {
        Self {
            enabled:         true,
            size_bytes:      4 * 1024 * 1024 * 1024, // 4 GiB
            bucket_capacity: 8 * 1024,
        }
    }
}

/// The pool itself. Each bucket holds an MPMC queue of free
/// [`AlignedBuffer`]s ready for reuse, plus per-bucket atomic
/// counters for in-use / total-allocated / total-returned. Cross-bucket
/// counters track external (un-pooled) allocations and pathological
/// events (resizes, dropped returns).
///
/// All counters are released atomic increments — they are observed
/// only by the periodic logger and never gate any hot-path decision.
pub struct MemoryPool {
    is_enabled:   bool,
    memory_limit: usize,

    /// Free-buffer queue per bucket. Lock-free MPMC; uncontended
    /// pop/push is ~1 atomic CAS each. The `ArrayQueue`'s own bound
    /// is what enforces the configured `bucket_capacity` — we do not
    /// keep a separate copy of the value because every later check
    /// goes through `buckets[i].push()` which fails when full.
    buckets:        [Arc<ArrayQueue<AlignedBuffer>>; NUM_BUCKETS],

    /// Number of buffers currently checked out per bucket.
    in_use:         [AtomicUsize; NUM_BUCKETS],

    /// Lifetime allocations per bucket (only counts pool allocations,
    /// not external).
    allocations:    [AtomicUsize; NUM_BUCKETS],

    /// Lifetime returns per bucket.
    returned:       [AtomicUsize; NUM_BUCKETS],

    external_allocations:   AtomicUsize,
    external_deallocations: AtomicUsize,
    resize_events:          AtomicUsize,
    dropped_returns:        AtomicUsize,
    capacity_warning:       AtomicBool,
}

impl MemoryPool {
    fn new(cfg: &MemoryPoolConfig) -> Self {
        let buckets = std::array::from_fn(|_| Arc::new(ArrayQueue::new(cfg.bucket_capacity)));
        let in_use = std::array::from_fn(|_| AtomicUsize::new(0));
        let allocations = std::array::from_fn(|_| AtomicUsize::new(0));
        let returned = std::array::from_fn(|_| AtomicUsize::new(0));

        if cfg.enabled {
            info!(
                num_buckets    = NUM_BUCKETS,
                memory_limit   = cfg.size_bytes,
                bucket_capacity = cfg.bucket_capacity,
                "MemoryPool initialised"
            );
        } else {
            info!("MemoryPool disabled (enabled=false in config)");
        }

        Self {
            is_enabled:             cfg.enabled,
            memory_limit:           cfg.size_bytes,
            buckets,
            in_use,
            allocations,
            returned,
            external_allocations:   AtomicUsize::new(0),
            external_deallocations: AtomicUsize::new(0),
            resize_events:          AtomicUsize::new(0),
            dropped_returns:        AtomicUsize::new(0),
            capacity_warning:       AtomicBool::new(false),
        }
    }

    /// Wire the global pool. Call once at process startup, before any
    /// `PooledBuffer::with_capacity` call.
    pub fn init_pool(config: &MemoryPoolConfig) {
        init_pool(config)
    }

    /// Acquire a buffer of *at least* `capacity` bytes. The returned
    /// buffer's actual capacity is rounded up to the next bucket size
    /// (or to `capacity.next_multiple_of(ALIGNMENT)` if no bucket
    /// fits). The bool is `true` iff the buffer was tracked as a pool
    /// allocation — the caller (typically [`PooledBuffer`]) uses this
    /// to drive `release_buffer` later.
    pub fn acquire_buffer(&self, capacity: usize) -> (AlignedBuffer, bool) {
        if !self.is_enabled {
            return (allocate_aligned_buffer(capacity), false);
        }

        let current = self.pool_current_size();

        match self.best_fit(capacity) {
            Some(idx) => {
                let bucket_size = BUCKET_SIZES[idx];

                // Try to pop a free buffer from this bucket first.
                if let Some(mut buf) = self.buckets[idx].pop() {
                    buf.clear();

                    if buf.capacity() < capacity {
                        // Defensive: a bucket entry whose capacity
                        // somehow shrank (shouldn't happen — buffers
                        // are alloc'd to bucket size). Drop and
                        // reallocate.
                        warn!(
                            bucket_idx     = idx,
                            bucket_size    = bucket_size,
                            buf_capacity   = buf.capacity(),
                            requested      = capacity,
                            "pool buffer too small, reallocating",
                        );
                        drop(buf);
                        let new_buf = allocate_aligned_buffer(bucket_size);
                        self.allocations[idx].fetch_add(1, Ordering::Release);
                        self.in_use[idx].fetch_add(1, Ordering::Release);
                        return (new_buf, true);
                    }

                    self.in_use[idx].fetch_add(1, Ordering::Release);
                    return (buf, true);
                }

                // Bucket empty — allocate a fresh one if we have budget.
                if current + bucket_size > self.memory_limit {
                    self.capacity_warning.store(true, Ordering::Release);
                    trace!(
                        requested = bucket_size,
                        in_use    = current,
                        limit     = self.memory_limit,
                        "pool at limit, allocating externally",
                    );
                    self.external_allocations.fetch_add(1, Ordering::Release);
                    return (allocate_aligned_buffer(bucket_size), false);
                }

                self.allocations[idx].fetch_add(1, Ordering::Release);
                self.in_use[idx].fetch_add(1, Ordering::Release);
                (allocate_aligned_buffer(bucket_size), true)
            }
            None => {
                // Requested size exceeds the largest bucket. Allocate
                // outside the pool — these bypass return-to-pool
                // accounting on Drop.
                self.external_allocations.fetch_add(1, Ordering::Release);
                (allocate_aligned_buffer(capacity), false)
            }
        }
    }

    /// Return a buffer previously acquired via [`acquire_buffer`].
    /// Mismatch between `original_capacity` and the buffer's current
    /// capacity is recorded as a `resize_event` (the buffer grew or
    /// shrank between acquire and release — typically it grew via
    /// `extend_from_slice`).
    pub fn release_buffer(
        &self,
        buffer: AlignedBuffer,
        original_capacity: usize,
        was_pool_allocated: bool,
    ) {
        if !self.is_enabled {
            return;
        }

        let current_capacity = buffer.capacity();
        if current_capacity != original_capacity {
            self.resize_events.fetch_add(1, Ordering::Release);
        }

        // If the buffer started in the pool, decrement its original
        // bucket's in-use count. (The new bucket — if any — gets
        // re-incremented during `inc_bucket_alloc` on next acquire,
        // not here, so we don't double-count.)
        if was_pool_allocated {
            if let Some(orig_idx) = self.best_fit(original_capacity) {
                self.in_use[orig_idx].fetch_sub(1, Ordering::Release);
            }
        }

        match self.best_fit(current_capacity) {
            Some(idx) => {
                self.returned[idx].fetch_add(1, Ordering::Release);
                if self.buckets[idx].push(buffer).is_err() {
                    self.dropped_returns.fetch_add(1, Ordering::Release);
                    self.capacity_warning.store(true, Ordering::Release);
                    trace!(bucket_size = BUCKET_SIZES[idx], "pool bucket full, dropping return");
                }
            }
            None => {
                self.external_deallocations.fetch_add(1, Ordering::Release);
            }
        }
    }

    /// Smallest bucket index whose size is ≥ `capacity`, or `None` if
    /// `capacity` exceeds the largest bucket.
    #[inline]
    pub fn best_fit(&self, capacity: usize) -> Option<usize> {
        match BUCKET_SIZES.binary_search(&capacity) {
            Ok(idx) => Some(idx),
            Err(idx) if idx < NUM_BUCKETS => Some(idx),
            Err(_) => None,
        }
    }

    /// Emit a one-line stats summary. Cheap; safe to call from any
    /// task. Operators wire this on a periodic timer (e.g. once a
    /// minute on one runtime) for production observability.
    pub fn log_stats(&self) {
        if !self.is_enabled {
            return;
        }
        let current = self.pool_current_size();
        if current == 0 {
            return;
        }
        let allocated = self.pool_allocated_size();
        let util = (current as f64 / self.memory_limit as f64) * 100.0;

        info!(
            current_bytes    = current,
            allocated_bytes  = allocated,
            limit_bytes      = self.memory_limit,
            utilisation_pct  = format_args!("{util:.1}"),
            external_alloc   = self.external_allocations.load(Ordering::Acquire),
            external_dealloc = self.external_deallocations.load(Ordering::Acquire),
            dropped_returns  = self.dropped_returns.load(Ordering::Acquire),
            resize_events    = self.resize_events.load(Ordering::Acquire),
            "MemoryPool stats",
        );

        if self.capacity_warning.swap(false, Ordering::AcqRel) {
            warn!(
                "MemoryPool reached its size or per-bucket limit at least once \
                 since the last stats log — consider raising memory_pool.size \
                 or memory_pool.bucket_capacity"
            );
        }
    }

    fn pool_current_size(&self) -> usize {
        (0..NUM_BUCKETS)
            .map(|i| self.in_use[i].load(Ordering::Acquire) * BUCKET_SIZES[i])
            .sum()
    }

    fn pool_allocated_size(&self) -> usize {
        (0..NUM_BUCKETS)
            .map(|i| self.allocations[i].load(Ordering::Acquire) * BUCKET_SIZES[i])
            .sum()
    }
}

/// Allocate a fresh page-aligned buffer of at least `capacity` bytes.
/// Used both for pool-tracked allocations and for the external path.
fn allocate_aligned_buffer(capacity: usize) -> AlignedBuffer {
    let aligned_capacity = capacity.next_multiple_of(ALIGNMENT).max(ALIGNMENT);
    AlignedBuffer::with_capacity(ALIGNMENT, aligned_capacity)
}

/// Convenience for callers that hold an `AlignedBuffer` directly
/// and want to return it without going through `PooledBuffer`'s Drop.
pub trait AlignedBufferExt {
    fn return_to_pool(self, original_capacity: usize, was_pool_allocated: bool);
}

impl AlignedBufferExt for AlignedBuffer {
    fn return_to_pool(self, original_capacity: usize, was_pool_allocated: bool) {
        memory_pool().release_buffer(self, original_capacity, was_pool_allocated);
    }
}
