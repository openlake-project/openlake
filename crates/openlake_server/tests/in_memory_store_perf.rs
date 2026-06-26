use std::time::Instant;

use openlake_server::in_memory_store::InMemoryStore;

const SIZES: &[(usize, &str)] = &[
    (256, "256 B"),
    (4 * 1024, "4 KiB"),
    (64 * 1024, "64 KiB"),
    (1024 * 1024, "1 MiB"),
];

fn fill(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i & 0xff) as u8).collect()
}

#[test]
fn in_memory_store_perf_single_thread() {
    let store = InMemoryStore::new();
    println!();
    println!(
        "{:>10} {:>12} {:>14} {:>14} {:>14} {:>14}",
        "size", "ops", "put ns/op", "put MiB/s", "get ns/op", "get MiB/s"
    );
    for (size, label) in SIZES {
        let value = fill(*size);
        let ops: usize = match *size {
            s if s <= 4 * 1024 => 200_000,
            s if s <= 64 * 1024 => 50_000,
            _ => 5_000,
        };
        for i in 0..1000 {
            store.put(format!("warm-{i}"), &value);
        }

        let t0 = Instant::now();
        for i in 0..ops {
            store.put(format!("k-{i}"), &value);
        }
        let put_elapsed = t0.elapsed();

        let t0 = Instant::now();
        for i in 0..ops {
            let b = store.get(&format!("k-{i}")).unwrap();
            std::hint::black_box(b);
        }
        let get_elapsed = t0.elapsed();

        let put_ns = put_elapsed.as_nanos() as f64 / ops as f64;
        let get_ns = get_elapsed.as_nanos() as f64 / ops as f64;
        let put_mib = (*size as f64 * ops as f64) / put_elapsed.as_secs_f64() / (1024.0 * 1024.0);
        let get_mib = (*size as f64 * ops as f64) / get_elapsed.as_secs_f64() / (1024.0 * 1024.0);

        println!(
            "{:>10} {:>12} {:>14.1} {:>14.1} {:>14.1} {:>14.1}",
            label, ops, put_ns, put_mib, get_ns, get_mib
        );
    }
}

#[test]
fn in_memory_store_concurrent_get() {
    let store = InMemoryStore::new();
    let value = fill(4096);
    for i in 0..10_000 {
        store.put(format!("k-{i}"), &value);
    }
    println!();
    println!(
        "{:>10} {:>14} {:>16}",
        "threads", "get ns/op", "aggregate Mops/s"
    );
    for &threads in &[1usize, 2, 4, 8, 16] {
        let per_thread = 200_000usize;
        let mut handles = Vec::with_capacity(threads);
        let t0 = Instant::now();
        for _ in 0..threads {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..per_thread {
                    let k = format!("k-{}", i % 10_000);
                    let b = store.get(&k).unwrap();
                    std::hint::black_box(b);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let elapsed = t0.elapsed();
        let total_ops = (threads * per_thread) as f64;
        let ns_per_op = elapsed.as_nanos() as f64 / total_ops;
        let mops_sec = total_ops / elapsed.as_secs_f64() / 1_000_000.0;
        println!("{:>10} {:>14.1} {:>16.2}", threads, ns_per_op, mops_sec);
    }
}
