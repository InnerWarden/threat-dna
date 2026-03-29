#[cfg(not(target_os = "macos"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::sync::RwLock;
use tracing::info;

mod anomaly;
mod api;
mod attack_chain;
mod classifier;
mod fingerprint;
mod ingest;
mod sequence;
mod store;

use anomaly::AnomalyDetector;
use attack_chain::AttackChainTracker;
use store::DnaStore;

#[derive(Parser)]
#[command(
    name = "innerwarden-dna",
    about = "Behavioral threat fingerprinting — identifies attackers by behavior, not IP."
)]
struct Cli {
    /// Inner Warden data directory (where events/incidents JSONL live)
    #[arg(long, default_value = "/var/lib/innerwarden")]
    data_dir: PathBuf,

    /// Directory to store DNA fingerprints and state
    #[arg(long, default_value = "/var/lib/innerwarden/dna")]
    dna_dir: PathBuf,

    /// API bind address
    #[arg(long, default_value = "127.0.0.1:8791")]
    bind: String,

    /// Minimum sequence length to fingerprint (ignore trivial interactions)
    #[arg(long, default_value = "3")]
    min_sequence: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "innerwarden_dna=info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Ensure DNA directory exists
    std::fs::create_dir_all(&cli.dna_dir)?;

    info!(data_dir = %cli.data_dir.display(), dna_dir = %cli.dna_dir.display(), "starting Threat DNA daemon");

    let store = Arc::new(RwLock::new(DnaStore::load(&cli.dna_dir)?));
    let chain_tracker = Arc::new(RwLock::new(AttackChainTracker::load(&cli.dna_dir)));
    let anomaly_detector = Arc::new(RwLock::new(AnomalyDetector::load(&cli.dna_dir)));

    // Spawn ingestion loop — watches JSONL files for new events
    let ingest_store = store.clone();
    let data_dir = cli.data_dir.clone();
    let min_seq = cli.min_sequence;
    tokio::spawn(async move {
        ingest::run(data_dir, ingest_store, min_seq).await;
    });

    // Spawn attack chain tracker — watches incidents for kill chain progression
    let chain_data_dir = cli.data_dir.clone();
    let chain_tracker_handle = chain_tracker.clone();
    tokio::spawn(async move {
        attack_chain::run(chain_data_dir, chain_tracker_handle).await;
    });

    // Spawn anomaly detector — learns process profiles and detects deviations
    let anomaly_data_dir = cli.data_dir.clone();
    let anomaly_handle = anomaly_detector.clone();
    tokio::spawn(async move {
        anomaly::run(anomaly_data_dir, anomaly_handle).await;
    });

    // Spawn API server
    info!(bind = %cli.bind, "starting DNA API");
    api::serve(&cli.bind, store, chain_tracker, anomaly_detector).await?;

    Ok(())
}
