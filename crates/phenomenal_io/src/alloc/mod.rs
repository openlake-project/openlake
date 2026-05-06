//! Page-aligned bucketed buffer pool.
//!
//! Faithful port of iggy's `core/common/src/alloc/` design: a global
//! `MemoryPool` singleton holding 28 size-bucketed lock-free queues of
//! 4 KiB-aligned heap allocations, plus a `PooledBuffer` RAII wrapper
//! that returns buffers to the pool on drop. The wrapper implements
//! compio's `IoBuf`/`IoBufMut`/`SetLen` so it slots directly into our
//! `read_exact` / `read` / `write` paths without any glue.
//!
//! # Why a pool
//!
//! Hot paths (1 MiB stream-chunk pumps, control-frame body buffers,
//! per-shard EC scratch) allocate-and-drop the same shape repeatedly.
//! Going through the system allocator on every call costs:
//!
//!   * a syscall (mmap or brk for large allocations),
//!   * page faults on first touch,
//!   * memory fragmentation in long-running processes.
//!
//! A pool amortises all three: the same physical pages get reused
//! across thousands of requests; once warmed, the steady-state
//! allocation cost is one atomic queue pop.
//!
//! # Why 4 KiB alignment
//!
//! Page-aligned allocations are required by `O_DIRECT` (kernel-bypass
//! disk I/O) and by `io_uring` registered buffers. Neither is wired
//! today but both are realistic next steps; aligning at the pool
//! layer means we don't have to retrofit later. Wasted bytes on small
//! buffers are bounded by the bucket-size table (smallest bucket is
//! one page, so no waste at the small end).
//!
//! # Why global rather than per-runtime
//!
//! Each compio runtime in phenomenald is single-threaded and pinned
//! to one CPU, so a per-runtime pool would have zero contention but
//! also zero load-balancing — buffers freed on an idle runtime can't
//! help a busy peer. crossbeam's `ArrayQueue` is lock-free MPMC; on
//! uncontended ops it is a single CAS, dwarfed by the cost of the
//! page allocation it replaces. We pay a few atomics for cross-runtime
//! sharing, exactly as iggy does.

pub mod buffer;
pub mod memory_pool;

pub use buffer::PooledBuffer;
pub use memory_pool::{init_pool, memory_pool, MemoryPool, MemoryPoolConfig};
