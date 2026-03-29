//! HTTP API for querying threat DNA.
//!
//! Endpoints:
//!   GET  /api/dna/status          — daemon status + stats
//!   GET  /api/dna/check?ip=X      — is this IP's behavior known?
//!   GET  /api/dna/threats         — top known threat DNA fingerprints
//!   GET  /api/dna/lookup?hash=X   — get DNA details by exact hash
//!   GET  /api/dna/similar?hash=X  — find similar DNA by fuzzy hash
//!   GET  /api/dna/chains          — active attack chains, sorted by score
//!   GET  /api/dna/chains?ip=X     — attack chain for a specific IP

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::HeaderValue;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::anomaly::{AnomalyAlert, ProfileSummary, SharedAnomalyDetector};
use crate::attack_chain::{AttackChain, SharedChainTracker};
use crate::fingerprint::{ThreatClass, ThreatDna};
use crate::store::DnaStore;

type SharedStore = Arc<RwLock<DnaStore>>;

/// Combined application state for all API endpoints.
#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub chain_tracker: SharedChainTracker,
    pub anomaly_detector: SharedAnomalyDetector,
}

pub async fn serve(
    bind: &str,
    store: SharedStore,
    chain_tracker: SharedChainTracker,
    anomaly_detector: SharedAnomalyDetector,
) -> anyhow::Result<()> {
    let state = AppState {
        store,
        chain_tracker,
        anomaly_detector,
    };

    let app = Router::new()
        .route("/api/dna/status", get(status))
        .route("/api/dna/check", get(check_ip))
        .route("/api/dna/threats", get(top_threats))
        .route("/api/dna/lookup", get(lookup))
        .route("/api/dna/similar", get(similar))
        .route("/api/dna/chains", get(chains))
        .route("/api/dna/anomalies", get(anomalies))
        .route("/api/dna/profiles", get(profiles))
        .layer(axum::middleware::from_fn(cors))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn cors(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert("access-control-allow-origin", HeaderValue::from_static("*"));
    resp
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    total_dna: usize,
    active_chains: usize,
    anomaly_profiles: usize,
    anomaly_alerts: usize,
    version: &'static str,
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    let store = state.store.read().await;
    let tracker = state.chain_tracker.read().await;
    let detector = state.anomaly_detector.read().await;
    Json(StatusResponse {
        status: "running",
        total_dna: store.len(),
        active_chains: tracker.len(),
        anomaly_profiles: detector.profile_count(),
        anomaly_alerts: detector.anomaly_count(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Deserialize)]
struct IpQuery {
    ip: String,
}

#[derive(Serialize)]
struct CheckResponse {
    ip: String,
    known: bool,
    matches: Vec<DnaSummary>,
}

#[derive(Serialize)]
struct DnaSummary {
    exact_hash: String,
    classification: Option<ThreatClass>,
    seen_count: u32,
    first_seen: String,
    last_seen: String,
    sequence_length: usize,
}

fn summarize(dna: &ThreatDna) -> DnaSummary {
    DnaSummary {
        exact_hash: dna.exact_hash[..12].to_string(),
        classification: dna.classification.clone(),
        seen_count: dna.seen_count,
        first_seen: dna.first_seen.to_rfc3339(),
        last_seen: dna.last_seen.to_rfc3339(),
        sequence_length: dna.length,
    }
}

async fn check_ip(
    State(state): State<AppState>,
    Query(query): Query<IpQuery>,
) -> Json<CheckResponse> {
    let store = state.store.read().await;
    let matches: Vec<DnaSummary> = store
        .all()
        .into_iter()
        .filter(|d| d.source_ip == query.ip)
        .map(summarize)
        .collect();

    Json(CheckResponse {
        ip: query.ip,
        known: !matches.is_empty(),
        matches,
    })
}

#[derive(Deserialize)]
struct LimitQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    20
}

async fn top_threats(
    State(state): State<AppState>,
    Query(query): Query<LimitQuery>,
) -> Json<Vec<DnaSummary>> {
    let store = state.store.read().await;
    let threats: Vec<DnaSummary> = store
        .top_threats(query.limit)
        .into_iter()
        .map(summarize)
        .collect();
    Json(threats)
}

#[derive(Deserialize)]
struct HashQuery {
    hash: String,
}

async fn lookup(
    State(state): State<AppState>,
    Query(query): Query<HashQuery>,
) -> Json<Option<ThreatDna>> {
    let store = state.store.read().await;
    // Support both full and prefix hash lookup
    let result = store.get(&query.hash).cloned().or_else(|| {
        store
            .all()
            .into_iter()
            .find(|d| d.exact_hash.starts_with(&query.hash))
            .cloned()
    });
    Json(result)
}

async fn similar(
    State(state): State<AppState>,
    Query(query): Query<HashQuery>,
) -> Json<Vec<DnaSummary>> {
    let store = state.store.read().await;
    // Find the DNA by hash first to get its fuzzy hash
    let fuzzy = store
        .get(&query.hash)
        .or_else(|| {
            store
                .all()
                .into_iter()
                .find(|d| d.exact_hash.starts_with(&query.hash))
        })
        .map(|d| d.fuzzy_hash.clone());

    let results = match fuzzy {
        Some(fh) => store.find_similar(&fh).into_iter().map(summarize).collect(),
        None => Vec::new(),
    };
    Json(results)
}

// ---------------------------------------------------------------------------
// Attack chain endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChainQuery {
    ip: Option<String>,
}

async fn chains(
    State(state): State<AppState>,
    Query(query): Query<ChainQuery>,
) -> Json<Vec<AttackChain>> {
    let tracker = state.chain_tracker.read().await;

    let result = if let Some(ip) = query.ip {
        // Return chain for specific IP
        match tracker.get_chain(&ip) {
            Some(chain) => vec![chain.clone()],
            None => Vec::new(),
        }
    } else {
        // Return all chains sorted by score
        tracker.all_chains_sorted().into_iter().cloned().collect()
    };

    Json(result)
}

// ---------------------------------------------------------------------------
// Anomaly detection endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AnomalyQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

async fn anomalies(
    State(state): State<AppState>,
    Query(query): Query<AnomalyQuery>,
) -> Json<Vec<AnomalyAlert>> {
    let detector = state.anomaly_detector.read().await;
    let alerts = detector.recent_anomalies(query.limit);
    Json(alerts.to_vec())
}

#[derive(Deserialize)]
struct ProfileQuery {
    comm: Option<String>,
}

async fn profiles(
    State(state): State<AppState>,
    Query(query): Query<ProfileQuery>,
) -> Json<serde_json::Value> {
    let detector = state.anomaly_detector.read().await;

    if let Some(comm) = query.comm {
        // Return specific profile details
        match detector.get_profile(&comm) {
            Some(profile) => Json(serde_json::to_value(profile).unwrap_or_default()),
            None => Json(serde_json::json!({"error": "profile not found"})),
        }
    } else {
        // Return summary of all profiles
        let summaries: Vec<ProfileSummary> = detector
            .all_profiles()
            .iter()
            .map(|p| ProfileSummary::from(*p))
            .collect();
        Json(serde_json::to_value(summaries).unwrap_or_default())
    }
}
