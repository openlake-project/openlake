use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::fmt::Write as _;
use std::path::PathBuf;

use openlake_server::config::Config;
use openlake_storage::NodeAddr;

#[derive(ClapArgs)]
pub struct TopologyArgs {
    /// openlake.toml. The same file openlaked reads.
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: TopologyArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("parse {}", args.config.display()))?;

    println!("openlake cluster topology: {}", args.config.display());
    println!();

    let (report, warnings) = render(&cfg.nodes);
    print!("{report}");

    for w in warnings {
        eprintln!("{w}");
    }
    Ok(())
}

fn render(nodes: &[NodeAddr]) -> (String, Vec<String>) {
    if nodes.is_empty() {
        return ("config declares zero nodes, nothing to lay out.\n".to_string(), Vec::new());
    }

    let mut sorted: Vec<&NodeAddr> = nodes.iter().collect();
    sorted.sort_unstable_by_key(|n| n.id);

    let mut out = String::new();
    out.push_str("  node    disks    rpc address\n");
    out.push_str("  ----    -----    -----------\n");
    for n in &sorted {
        let _ = writeln!(out, "  {:>4}    {:>5}    {}", n.id, n.disk_count, n.rpc_addr);
    }
    out.push('\n');

    let count = sorted.len();
    let total_disks: u32 = sorted.iter().map(|n| n.disk_count as u32).sum();
    let _ = writeln!(
        out,
        "{} node{} configured, {} disk{} total.",
        count,        if count == 1 { "" } else { "s" },
        total_disks,  if total_disks == 1 { "" } else { "s" },
    );

    let mut dup_ids: Vec<u16> = sorted
        .windows(2)
        .filter(|w| w[0].id == w[1].id)
        .map(|w| w[0].id)
        .collect();
    dup_ids.dedup();
    let warnings = dup_ids
        .into_iter()
        .map(|id| format!("warning: node id {id} declared more than once."))
        .collect();

    (out, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn node(id: u16, addr: &str, disk_count: u16) -> NodeAddr {
        NodeAddr {
            id,
            rpc_addr: addr.parse::<SocketAddr>().unwrap(),
            disk_count,
        }
    }

    #[test]
    fn empty_config_reports_no_nodes() {
        let (report, warnings) = render(&[]);
        assert!(report.contains("zero nodes"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn nodes_are_sorted_by_id() {
        let nodes = vec![
            node(2, "127.0.0.1:9002", 1),
            node(0, "127.0.0.1:9000", 1),
            node(1, "127.0.0.1:9001", 1),
        ];
        let (report, warnings) = render(&nodes);
        let p0 = report.find("127.0.0.1:9000").unwrap();
        let p1 = report.find("127.0.0.1:9001").unwrap();
        let p2 = report.find("127.0.0.1:9002").unwrap();
        assert!(p0 < p1 && p1 < p2, "nodes should be ordered by id");
        assert!(report.contains("3 nodes configured"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn single_node_uses_singular() {
        let (report, _) = render(&[node(0, "127.0.0.1:9000", 1)]);
        assert!(report.contains("1 node configured"));
        assert!(report.contains("1 disk total"));
    }

    #[test]
    fn duplicate_ids_are_flagged() {
        let nodes = vec![node(0, "127.0.0.1:9000", 1), node(0, "10.0.0.1:9000", 2)];
        let (_, warnings) = render(&nodes);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("node id 0 declared more than once."));
    }

    #[test]
    fn disk_count_appears_in_render() {
        let (report, _) = render(&[node(0, "127.0.0.1:9000", 4), node(1, "127.0.0.1:9001", 4)]);
        assert!(report.contains("8 disks total"));
    }
}
