use anyhow::Result;
use clap::Args as ClapArgs;
use rand::Rng;

#[derive(ClapArgs)]
pub struct BenchArgs {
    #[arg(long)]
    pub mixed: bool,

    #[arg(long, default_value_t = 10000)]
    pub n: usize,

    #[arg(long, default_value_t = 4096)]
    pub size: usize,

    #[arg(long, default_value_t = 64)]
    pub concurrency: usize,
}

pub async fn run(args: BenchArgs) -> Result<()> {
    if !args.mixed {
        println!(
            "bench: n={}, size={}, concurrency={}",
            args.n,
            args.size,
            args.concurrency
        );
        return Ok(());
    }

    let mut puts = 0usize;
    let mut gets = 0usize;
    let mut deletes = 0usize;

    let mut rng = rand::thread_rng();

    for _ in 0..args.n {
        let r: u8 = rng.gen_range(0..100);

        match r {
            0..=59 => puts += 1,
            60..=89 => gets += 1,
            _ => deletes += 1,
        }
    }

    println!("Mixed workload benchmark");
    println!("Total operations : {}", args.n);
    println!("PUT (60%)        : {}", puts);
    println!("GET (30%)        : {}", gets);
    println!("DELETE (10%)     : {}", deletes);
    println!("Object size      : {} bytes", args.size);
    println!("Concurrency      : {}", args.concurrency);

    Ok(())
}