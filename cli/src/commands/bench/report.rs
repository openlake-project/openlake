use hdrhistogram::Histogram;

use super::mode::BenchMode;

#[allow(dead_code)]
pub struct Cell {
    pub block_bytes: u64,
    pub batch: u32,
    pub threads: u32,
    pub op: &'static str,
    pub iters: u64,
    pub bytes: u128,
    pub elapsed_us: u128,
    pub lat: Histogram<u64>,
}

pub struct Report {
    pub cells: Vec<Cell>,
}

#[allow(dead_code)]
pub struct ClientPreamble {
    pub target: String,
    pub mode: BenchMode,
    pub duration_secs: u64,
    pub warmup_secs: u64,
}

const RULE: &str =
    "----------------------------------------------------------------------------------------------------------------------------------------------------------------";

pub fn print_preamble(_p: &ClientPreamble) {}

#[allow(clippy::manual_is_multiple_of)]
fn fmt_block(n: u64) -> String {
    const K: u64 = 1u64 << 10;
    const M: u64 = 1u64 << 20;
    const G: u64 = 1u64 << 30;
    if n >= G && n % G == 0 {
        format!("{} GiB", n / G)
    } else if n >= M && n % M == 0 {
        format!("{} MiB", n / M)
    } else if n >= K && n % K == 0 {
        format!("{} KiB", n / K)
    } else {
        format!("{n} B")
    }
}

pub fn print_header() {
    println!(
        "{:<12}{:<8}{:<14}{:<14}{:<14}{:<14}{:<14}",
        "BlkSize",
        "Batch",
        "BW (GB/S)",
        "Avg Lat (us)",
        "Avg Tx (us)",
        "P99 Tx (us)",
        "P999 Tx (us)",
    );
    println!("{RULE}");
}

pub fn print_row(c: &Cell) {
    let secs = c.elapsed_us as f64 / 1e6;
    let num_ops = c.iters as f64;
    let total_data_b = c.block_bytes as f64 * c.batch as f64 * num_ops;
    let bw_gb_s = total_data_b / 1e9 / secs;
    let avg_lat_us = secs * 1e6 * c.threads as f64 / num_ops;
    let avg_tx_us = c.lat.mean();
    let p99_us = c.lat.value_at_quantile(0.99) as f64;
    let p999_us = c.lat.value_at_quantile(0.999) as f64;

    println!(
        "{:<12}{:<8}{:<14.6}{:<14.1}{:<14.1}{:<14.1}{:<14.1}",
        fmt_block(c.block_bytes),
        c.batch,
        bw_gb_s,
        avg_lat_us,
        avg_tx_us,
        p99_us,
        p999_us,
    );
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

pub fn print_table(rep: &Report) {
    print_header();
    for c in &rep.cells {
        print_row(c);
    }
}
