mod cache;
mod scanner;
mod server;

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;

use crate::cache::DigestCache;
use crate::scanner::{ScanOptions, ScanResult};
use crate::server::ServeOptions;

/// Find duplicate files (by content hash) across one or more folders and review them in a browser UI.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Folders to scan recursively
    #[arg(required = true, num_args = 1..)]
    paths: Vec<String>,

    /// Port for the local review UI (0 picks a free one)
    #[arg(short, long, default_value_t = 7878)]
    port: u16,

    /// Ignore files smaller than this many bytes (empty files are skipped by default)
    #[arg(long, default_value_t = 1)]
    min_size: u64,

    /// Skip files or folders with this name (or trailing path) anywhere in the tree (repeatable),
    /// e.g. `--exclude target --exclude ios/Pods`. Always skipped: .git, .hg, .svn,
    /// node_modules, android/build
    #[arg(short, long, value_name = "NAME")]
    exclude: Vec<String>,

    /// Don't read or write the digest cache (forces every candidate file to be re-read)
    #[arg(long)]
    no_cache: bool,

    /// Don't open the browser automatically
    #[arg(long)]
    no_open: bool,

    /// Print the duplicate groups and exit instead of starting the UI
    #[arg(long)]
    list: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let roots: Vec<PathBuf> = server::resolve_roots(&cli.paths).map_err(anyhow::Error::msg)?;

    for root in &roots {
        eprintln!("Scanning {}", root.display());
    }
    configure_thread_pool();
    let started = Instant::now();
    let scan_options = ScanOptions {
        min_size: cli.min_size,
        exclude: cli.exclude,
        cache: if cli.no_cache {
            None
        } else {
            DigestCache::default_location()
        },
    };
    let scan = scanner::find_duplicates(&roots, &scan_options);
    print_summary(&scan, started);

    if cli.list {
        for group in &scan.groups {
            println!(
                "\n{} × {} ({})",
                group.files.len(),
                format_bytes(group.size),
                &group.hash[..16]
            );
            for file in &group.files {
                println!("  {}", file.path.display());
            }
        }
        return Ok(());
    }

    let options = ServeOptions {
        roots,
        scan: scan_options,
        port: cli.port,
        open_browser: !cli.no_open,
    };
    tokio::runtime::Runtime::new()?.block_on(server::serve(options, scan))
}

/// Scanning is I/O-bound: threads mostly wait on `stat`/`read`, so running ~3x more threads than
/// cores keeps the SSD queue full (measured ~15% faster than one thread per core).
/// `RAYON_NUM_THREADS` still overrides this.
fn configure_thread_pool() {
    if std::env::var_os("RAYON_NUM_THREADS").is_some() {
        return;
    }
    let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads((cores * 3).min(64))
        .build_global();
}

fn print_summary(scan: &ScanResult, started: Instant) {
    let duplicates: usize = scan.groups.iter().map(|g| g.files.len() - 1).sum();
    let wasted: u64 = scan.groups.iter().map(|g| g.wasted_bytes()).sum();
    eprintln!(
        "Scanned {} files ({}, read {} to compare) in {:.1?}: {} duplicate groups, {} redundant copies, {} reclaimable{}",
        scan.stats.files_seen,
        format_bytes(scan.stats.bytes_seen),
        format_bytes(scan.stats.bytes_read),
        started.elapsed(),
        scan.groups.len(),
        duplicates,
        format_bytes(wasted),
        match scan.stats.unreadable {
            0 => String::new(),
            n => format!(", {n} unreadable"),
        },
    );
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
