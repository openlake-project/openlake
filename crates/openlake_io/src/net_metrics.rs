//! Inter-node operation metrics per `(transport, class)` cell, so the
//! RDMA-verbs plane and the h2/IPoIB plane are separable. Ops the RDMA
//! backend falls back on route through `RemoteBackend` and therefore
//! count as `h2`. Rendered by the server's metrics endpoint; honors
//! `OPENLAKE_METRICS=0`.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;

/// Latency histogram upper bounds, microseconds; last bucket is +Inf.
const LE_US: [u64; 8] = [50, 200, 1_000, 5_000, 20_000, 100_000, 500_000, 5_000_000];

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Transport {
    Rdma,
    H2,
}

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Class {
    Unary,
    ReadStream,
    WriteStream,
}

const TRANSPORT_NAMES: [&str; 2] = ["rdma", "h2"];
const CLASS_NAMES: [&str; 3] = ["unary", "read_stream", "write_stream"];

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("OPENLAKE_METRICS").map_or(true, |v| v != "0"))
}

#[derive(Default)]
struct Cell {
    ops: AtomicU64,
    errors: AtomicU64,
    bytes: AtomicU64,
    lat_us_sum: AtomicU64,
    lat_buckets: [AtomicU64; LE_US.len() + 1],
}

static REGISTRY: [[Cell; 3]; 2] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const Z: AtomicU64 = AtomicU64::new(0);
    #[allow(clippy::declare_interior_mutable_const)]
    const C: Cell = Cell {
        ops: Z,
        errors: Z,
        bytes: Z,
        lat_us_sum: Z,
        lat_buckets: [Z; 9],
    };
    #[allow(clippy::declare_interior_mutable_const)]
    const ROW: [Cell; 3] = [C; 3];
    [ROW; 2]
};

pub fn observe(t: Transport, c: Class, latency_us: u64, err: bool) {
    if !enabled() {
        return;
    }
    let cell = &REGISTRY[t as usize][c as usize];
    cell.ops.fetch_add(1, Relaxed);
    if err {
        cell.errors.fetch_add(1, Relaxed);
    }
    cell.lat_us_sum.fetch_add(latency_us, Relaxed);
    let idx = LE_US
        .iter()
        .position(|le| latency_us <= *le)
        .unwrap_or(LE_US.len());
    cell.lat_buckets[idx].fetch_add(1, Relaxed);
}

pub fn add_bytes(t: Transport, c: Class, n: u64) {
    if !enabled() || n == 0 {
        return;
    }
    REGISTRY[t as usize][c as usize].bytes.fetch_add(n, Relaxed);
}

pub fn render() -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(8 * 1024);
    out.push_str("# TYPE openlake_internode_ops_total counter\n");
    out.push_str("# TYPE openlake_internode_errors_total counter\n");
    out.push_str("# TYPE openlake_internode_bytes_total counter\n");
    out.push_str("# TYPE openlake_internode_latency_us histogram\n");
    for (ti, tname) in TRANSPORT_NAMES.iter().enumerate() {
        for (ci, cname) in CLASS_NAMES.iter().enumerate() {
            let cell = &REGISTRY[ti][ci];
            let ops = cell.ops.load(Relaxed);
            let bytes = cell.bytes.load(Relaxed);
            if ops == 0 && bytes == 0 {
                continue;
            }
            let lbl = format!("transport=\"{tname}\",class=\"{cname}\"");
            let _ = writeln!(out, "openlake_internode_ops_total{{{lbl}}} {ops}");
            let _ = writeln!(
                out,
                "openlake_internode_errors_total{{{lbl}}} {}",
                cell.errors.load(Relaxed)
            );
            let _ = writeln!(out, "openlake_internode_bytes_total{{{lbl}}} {bytes}");
            let mut cumulative = 0u64;
            for (b, le) in LE_US.iter().enumerate() {
                cumulative += cell.lat_buckets[b].load(Relaxed);
                let _ = writeln!(
                    out,
                    "openlake_internode_latency_us_bucket{{{lbl},le=\"{le}\"}} {cumulative}"
                );
            }
            cumulative += cell.lat_buckets[LE_US.len()].load(Relaxed);
            let _ = writeln!(
                out,
                "openlake_internode_latency_us_bucket{{{lbl},le=\"+Inf\"}} {cumulative}"
            );
            let _ = writeln!(
                out,
                "openlake_internode_latency_us_sum{{{lbl}}} {}",
                cell.lat_us_sum.load(Relaxed)
            );
            let _ = writeln!(
                out,
                "openlake_internode_latency_us_count{{{lbl}}} {cumulative}"
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_and_render() {
        observe(Transport::Rdma, Class::ReadStream, 180, false);
        add_bytes(Transport::Rdma, Class::ReadStream, 4 * 1024 * 1024);
        observe(Transport::H2, Class::Unary, 900, true);
        let text = render();
        assert!(text
            .contains("openlake_internode_bytes_total{transport=\"rdma\",class=\"read_stream\"}"));
        assert!(
            text.contains("openlake_internode_errors_total{transport=\"h2\",class=\"unary\"} 1")
        );
    }
}
