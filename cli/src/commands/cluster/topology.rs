use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::config::{self, ClusterToml};

#[derive(ClapArgs)]
pub struct TopologyArgs {
    /// Cluster TOML.  One TOML describes exactly one cluster.
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: TopologyArgs) -> Result<()> {
    let cfg = config::load(&args.config).with_context(|| {
        format!("failed to load cluster config from {}", args.config.display())
    })?;

    println!("openlake cluster topology: {}", args.config.display());
    println!();

    let (report, warnings) = render(&cfg);
    print!("{report}");

    // Keep stdout a clean, pipeable report; diagnostics go to stderr.
    for w in warnings {
        eprintln!("{w}");
    }
    Ok(())
}

/// Render the declared cluster layout and any config warnings.
///
/// Unlike `cluster status`, this never touches the network: it reports the
/// static topology exactly as the TOML declares it, sorted by node id.  The
/// returned tuple is `(report, warnings)` — the report is the stdout table,
/// and `warnings` are diagnostics the caller should emit on stderr.
fn render(cfg: &ClusterToml) -> (String, Vec<String>) {
    if cfg.nodes.is_empty() {
        let report = "config declares zero nodes; nothing to lay out.\n".to_string();
        return (report, Vec::new());
    }

    let mut nodes: Vec<_> = cfg.nodes.iter().collect();
    nodes.sort_unstable_by_key(|n| n.id);

    let mut out = String::new();
    out.push_str("  node    rpc address\n");
    out.push_str("  ----    -----------\n");
    for n in &nodes {
        let _ = writeln!(out, "  {:>4}    {}", n.id, n.rpc_addr);
    }
    out.push('\n');

    let count = nodes.len();
    let _ = writeln!(
        out,
        "{} node{} configured.",
        count,
        if count == 1 { "" } else { "s" }
    );

    // A cluster TOML must map each id to exactly one node.  After sorting,
    // duplicates are adjacent, so a single pass surfaces them.
    let mut dup_ids: Vec<u32> = nodes
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
    use crate::config::NodeToml;
    use std::net::SocketAddr;

    fn node(id: u32, addr: &str) -> NodeToml {
        NodeToml {
            id,
            rpc_addr: addr.parse::<SocketAddr>().unwrap(),
        }
    }

    #[test]
    fn empty_config_reports_no_nodes() {
        let (report, warnings) = render(&ClusterToml { nodes: vec![] });
        assert!(report.contains("zero nodes"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn nodes_are_sorted_by_id() {
        let cfg = ClusterToml {
            nodes: vec![
                node(2, "127.0.0.1:9002"),
                node(0, "127.0.0.1:9000"),
                node(1, "127.0.0.1:9001"),
            ],
        };
        let (report, warnings) = render(&cfg);
        let p0 = report.find("127.0.0.1:9000").unwrap();
        let p1 = report.find("127.0.0.1:9001").unwrap();
        let p2 = report.find("127.0.0.1:9002").unwrap();
        assert!(p0 < p1 && p1 < p2, "nodes should be ordered by id");
        assert!(report.contains("3 nodes configured."));
        assert!(warnings.is_empty());
    }

    #[test]
    fn single_node_uses_singular() {
        let cfg = ClusterToml {
            nodes: vec![node(0, "127.0.0.1:9000")],
        };
        let (report, _) = render(&cfg);
        assert!(report.contains("1 node configured."));
    }

    #[test]
    fn duplicate_ids_are_flagged() {
        let cfg = ClusterToml {
            nodes: vec![node(0, "127.0.0.1:9000"), node(0, "10.0.0.1:9000")],
        };
        let (_, warnings) = render(&cfg);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("node id 0 declared more than once."));
    }
}
