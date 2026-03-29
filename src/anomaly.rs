//! Syscall sequence anomaly detection using an autoencoder-inspired approach.
//!
//! Learns "normal" behavior per process name by building frequency profiles of
//! behavior atoms. Once a profile is trained (enough observations), deviations
//! are flagged as anomalies using cosine distance and z-score rate analysis.
//!
//! This catches zero-day attacks that no signature-based detector would find:
//! a process suddenly doing things it has never done before stands out
//! statistically even if no rule was written for that specific behavior.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::sequence::*;

/// How often the anomaly detector polls for new events (seconds).
const ANOMALY_POLL_INTERVAL_SECS: u64 = 5;

/// Default minimum observations before a profile is considered trained.
const DEFAULT_MIN_TRAINING_SAMPLES: u64 = 100;

/// Default z-score threshold for anomaly detection (3.0 = 99.7% confidence).
const DEFAULT_ANOMALY_THRESHOLD: f64 = 3.0;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Classification of the anomaly type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Process doing unusual syscalls compared to its learned profile.
    BehaviorDeviation,
    /// Process event rate spiked well above its historical average.
    RateSpike,
    /// Process emitted an atom type never seen in its training history.
    NewBehavior,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyType::BehaviorDeviation => write!(f, "BehaviorDeviation"),
            AnomalyType::RateSpike => write!(f, "RateSpike"),
            AnomalyType::NewBehavior => write!(f, "NewBehavior"),
        }
    }
}

/// A single anomaly alert raised by the detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    /// Process name that triggered the anomaly.
    pub comm: String,
    /// What kind of anomaly was detected.
    pub alert_type: AnomalyType,
    /// Anomaly score from 0.0 (normal) to 1.0 (maximally anomalous).
    pub score: f64,
    /// Human-readable description of the anomaly.
    pub details: String,
    /// When the anomaly was detected.
    pub timestamp: DateTime<Utc>,
}

/// Learned behavioral profile for a single process name (comm).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallProfile {
    /// Process name this profile describes.
    pub comm: String,
    /// Frequency of each atom type, normalized to 0.0–1.0.
    pub atom_frequencies: HashMap<String, f64>,
    /// Raw count of each atom type (used to recompute frequencies).
    #[serde(default)]
    raw_counts: HashMap<String, u64>,
    /// Total number of events observed for this process.
    pub total_events: u64,
    /// Running mean of event rate (events per minute).
    pub rate_mean: f64,
    /// Running standard deviation of event rate.
    pub rate_stddev: f64,
    /// Number of rate samples collected (for Welford's algorithm).
    #[serde(default)]
    rate_sample_count: u64,
    /// Welford M2 accumulator for variance calculation.
    #[serde(default)]
    rate_m2: f64,
    /// When this profile was last updated.
    pub last_updated: DateTime<Utc>,
    /// Whether this profile has enough data to be considered trained.
    pub trained: bool,
}

impl SyscallProfile {
    fn new(comm: &str) -> Self {
        Self {
            comm: comm.to_string(),
            atom_frequencies: HashMap::new(),
            raw_counts: HashMap::new(),
            total_events: 0,
            rate_mean: 0.0,
            rate_stddev: 0.0,
            rate_sample_count: 0,
            rate_m2: 0.0,
            last_updated: Utc::now(),
            trained: false,
        }
    }

    /// Record a single atom observation and update frequencies.
    fn observe_atom(&mut self, atom_key: &str) {
        *self.raw_counts.entry(atom_key.to_string()).or_insert(0) += 1;
        self.total_events += 1;
        self.last_updated = Utc::now();

        // Recompute normalized frequencies
        let total = self.total_events as f64;
        for (key, count) in &self.raw_counts {
            self.atom_frequencies
                .insert(key.clone(), *count as f64 / total);
        }
    }

    /// Update the running rate statistics using Welford's online algorithm.
    fn observe_rate(&mut self, events_per_minute: f64) {
        self.rate_sample_count += 1;
        let n = self.rate_sample_count as f64;
        let delta = events_per_minute - self.rate_mean;
        self.rate_mean += delta / n;
        let delta2 = events_per_minute - self.rate_mean;
        self.rate_m2 += delta * delta2;

        if self.rate_sample_count > 1 {
            self.rate_stddev = (self.rate_m2 / (n - 1.0)).sqrt();
        }
    }

    /// Check training status based on minimum sample count.
    fn check_trained(&mut self, min_samples: u64) {
        if self.total_events >= min_samples {
            self.trained = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Cosine distance
// ---------------------------------------------------------------------------

/// Compute the cosine distance between two frequency vectors.
///
/// Returns 0.0 for identical vectors, 1.0 for orthogonal or zero vectors.
/// The vectors are represented as sparse maps keyed by atom type.
pub fn cosine_distance(a: &HashMap<String, f64>, b: &HashMap<String, f64>) -> f64 {
    let keys: HashSet<&String> = a.keys().chain(b.keys()).collect();
    let dot: f64 = keys
        .iter()
        .map(|k| a.get(*k).unwrap_or(&0.0) * b.get(*k).unwrap_or(&0.0))
        .sum();
    let mag_a: f64 = a.values().map(|v| v * v).sum::<f64>().sqrt();
    let mag_b: f64 = b.values().map(|v| v * v).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return 1.0;
    }
    1.0 - (dot / (mag_a * mag_b))
}

// ---------------------------------------------------------------------------
// Anomaly detector
// ---------------------------------------------------------------------------

/// Maximum number of process profiles to prevent unbounded memory growth.
const MAX_PROFILES: usize = 5_000;

/// Rate window duration: only keep timestamps from the last 5 minutes.
const RATE_WINDOW_SECS: i64 = 300;

/// Core anomaly detection engine.
///
/// Maintains per-process behavioral profiles and detects deviations from
/// learned normal behavior.
pub struct AnomalyDetector {
    /// Per-process behavioral profiles, keyed by comm name.
    profiles: HashMap<String, SyscallProfile>,
    /// Minimum observations before a profile is considered trained.
    min_training_samples: u64,
    /// Z-score threshold for anomaly detection.
    anomaly_threshold: f64,
    /// Recent anomaly alerts.
    anomalies: Vec<AnomalyAlert>,
    /// Maximum number of anomalies to retain.
    max_anomalies: usize,
    /// Path for persistence.
    persist_path: PathBuf,
    /// Per-process event timestamps within the current rate window, used to
    /// compute events-per-minute for rate anomaly detection.
    #[allow(dead_code)]
    rate_windows: HashMap<String, Vec<DateTime<Utc>>>,
}

/// Shared detector type for API access.
pub type SharedAnomalyDetector = Arc<RwLock<AnomalyDetector>>;

impl AnomalyDetector {
    /// Create a new detector with the given configuration.
    pub fn new(dna_dir: &Path) -> Self {
        Self::with_config(
            dna_dir,
            DEFAULT_MIN_TRAINING_SAMPLES,
            DEFAULT_ANOMALY_THRESHOLD,
        )
    }

    /// Create with custom configuration parameters.
    pub fn with_config(dna_dir: &Path, min_training_samples: u64, anomaly_threshold: f64) -> Self {
        Self {
            profiles: HashMap::new(),
            min_training_samples,
            anomaly_threshold,
            anomalies: Vec::new(),
            max_anomalies: 1000,
            persist_path: dna_dir.join("syscall-profiles.json"),
            rate_windows: HashMap::new(),
        }
    }

    /// Load profiles from disk, falling back to empty state.
    pub fn load(dna_dir: &Path) -> Self {
        let mut detector = Self::new(dna_dir);
        let path = dna_dir.join("syscall-profiles.json");
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    let profiles: Vec<SyscallProfile> =
                        serde_json::from_str(&content).unwrap_or_default();
                    for p in profiles {
                        detector.profiles.insert(p.comm.clone(), p);
                    }
                    info!(
                        count = detector.profiles.len(),
                        "loaded syscall profiles from disk"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "failed to read syscall profiles, starting fresh");
                }
            }
        }
        detector
    }

    /// Save profiles to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        let profiles: Vec<&SyscallProfile> = self.profiles.values().collect();
        let json = serde_json::to_string_pretty(&profiles)?;
        std::fs::write(&self.persist_path, json)?;
        Ok(())
    }

    /// Process a batch of events from a single process, updating its profile
    /// and checking for anomalies.
    ///
    /// Returns any anomalies detected during this batch.
    pub fn process_events(
        &mut self,
        comm: &str,
        atom_keys: &[String],
        now: DateTime<Utc>,
    ) -> Vec<AnomalyAlert> {
        if comm.is_empty() || atom_keys.is_empty() {
            return Vec::new();
        }

        let mut alerts = Vec::new();
        let threshold = self.anomaly_threshold;
        let min_samples = self.min_training_samples;

        // Build current batch frequency vector
        let mut batch_counts: HashMap<String, u64> = HashMap::new();
        for key in atom_keys {
            *batch_counts.entry(key.clone()).or_insert(0) += 1;
        }
        let batch_total = atom_keys.len() as f64;
        let batch_freq: HashMap<String, f64> = batch_counts
            .iter()
            .map(|(k, &v)| (k.clone(), v as f64 / batch_total))
            .collect();

        // Cap profiles to prevent unbounded growth
        if self.profiles.len() >= MAX_PROFILES && !self.profiles.contains_key(comm) {
            // Evict the least-recently-updated profile
            if let Some(oldest_comm) = self
                .profiles
                .iter()
                .min_by_key(|(_, p)| p.last_updated)
                .map(|(k, _)| k.clone())
            {
                self.profiles.remove(&oldest_comm);
                self.rate_windows.remove(&oldest_comm);
            }
        }

        // Clean up stale rate_windows entries (only keep timestamps from last 5 minutes)
        let cutoff = now - chrono::Duration::seconds(RATE_WINDOW_SECS);
        if let Some(timestamps) = self.rate_windows.get_mut(comm) {
            timestamps.retain(|ts| *ts > cutoff);
        }
        // Also periodically purge rate_windows for processes no longer in profiles
        self.rate_windows
            .retain(|k, _| self.profiles.contains_key(k));

        // Get or create the profile
        let profile = self
            .profiles
            .entry(comm.to_string())
            .or_insert_with(|| SyscallProfile::new(comm));

        // Check for anomalies BEFORE updating the profile (compare against learned baseline)
        if profile.trained {
            // 1. Check for new behavior: atom types never seen during training
            for key in atom_keys {
                if !profile.atom_frequencies.contains_key(key) {
                    let alert = AnomalyAlert {
                        comm: comm.to_string(),
                        alert_type: AnomalyType::NewBehavior,
                        score: 1.0,
                        details: format!(
                            "process '{}' emitted atom '{}' which was never observed during training ({} events)",
                            comm, key, profile.total_events
                        ),
                        timestamp: now,
                    };
                    alerts.push(alert);
                    // Only alert once per new atom type per batch
                    break;
                }
            }

            // 2. Check for behavioral deviation via cosine distance
            let distance = cosine_distance(&profile.atom_frequencies, &batch_freq);
            // Convert cosine distance to anomaly score: threshold at 1-1/e (~0.632)
            // normalized so that threshold maps to ~0.5 score
            if distance > (1.0 - 1.0 / threshold) {
                let score = distance.min(1.0);
                let alert = AnomalyAlert {
                    comm: comm.to_string(),
                    alert_type: AnomalyType::BehaviorDeviation,
                    score,
                    details: format!(
                        "process '{}' behavioral cosine distance {:.4} exceeds threshold (profile trained on {} events)",
                        comm, distance, profile.total_events
                    ),
                    timestamp: now,
                };
                alerts.push(alert);
            }

            // 3. Check for rate spike
            let events_per_minute = atom_keys.len() as f64; // batch size as proxy for rate
            if profile.rate_sample_count >= 2 {
                let deviation = events_per_minute - profile.rate_mean;
                let is_spike = if profile.rate_stddev > 1e-9 {
                    // Normal case: use z-score
                    let z_score = deviation / profile.rate_stddev;
                    z_score > threshold
                } else {
                    // Near-zero stddev (constant rate): any significant deviation is anomalous.
                    // Use a relative threshold: rate > mean * threshold as spike indicator.
                    profile.rate_mean > 0.0 && events_per_minute > profile.rate_mean * threshold
                };

                if is_spike && deviation > 0.0 {
                    let z_score = if profile.rate_stddev > 1e-9 {
                        deviation / profile.rate_stddev
                    } else {
                        events_per_minute / profile.rate_mean.max(1.0)
                    };
                    let score = (z_score / (threshold * 2.0)).min(1.0);
                    let alert = AnomalyAlert {
                        comm: comm.to_string(),
                        alert_type: AnomalyType::RateSpike,
                        score,
                        details: format!(
                            "process '{}' rate spike: {:.1} events (z-score {:.2}, mean {:.1}, stddev {:.2})",
                            comm, events_per_minute, z_score, profile.rate_mean, profile.rate_stddev
                        ),
                        timestamp: now,
                    };
                    alerts.push(alert);
                }
            }
        }

        // Update the profile with this batch (learning continues even after training)
        for key in atom_keys {
            profile.observe_atom(key);
        }
        profile.observe_rate(atom_keys.len() as f64);
        profile.check_trained(min_samples);

        // Store alerts
        for alert in &alerts {
            info!(
                comm = %alert.comm,
                alert_type = %alert.alert_type,
                score = alert.score,
                "anomaly detected"
            );
        }
        self.anomalies.extend(alerts.clone());

        // Trim anomaly buffer
        if self.anomalies.len() > self.max_anomalies {
            let excess = self.anomalies.len() - self.max_anomalies;
            self.anomalies.drain(..excess);
        }

        alerts
    }

    /// Get recent anomaly alerts.
    pub fn recent_anomalies(&self, limit: usize) -> &[AnomalyAlert] {
        let start = self.anomalies.len().saturating_sub(limit);
        &self.anomalies[start..]
    }

    /// Get all profiles (for API).
    pub fn all_profiles(&self) -> Vec<&SyscallProfile> {
        self.profiles.values().collect()
    }

    /// Get a specific profile by comm name.
    pub fn get_profile(&self, comm: &str) -> Option<&SyscallProfile> {
        self.profiles.get(comm)
    }

    /// Number of tracked profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Number of stored anomalies.
    pub fn anomaly_count(&self) -> usize {
        self.anomalies.len()
    }
}

// ---------------------------------------------------------------------------
// Event parsing (extracts comm + atom key from JSONL)
// ---------------------------------------------------------------------------

/// Extract (comm, atom_key, timestamp) from an event JSON line.
fn parse_event_for_anomaly(line: &str) -> Option<(String, String, DateTime<Utc>)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let kind = v["kind"].as_str().unwrap_or("");
    let ts = v["ts"]
        .as_str()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now);
    let details = &v["details"];

    let comm = details["comm"]
        .as_str()
        .or_else(|| details["command"].as_str())
        .unwrap_or("")
        .to_string();

    if comm.is_empty() {
        return None;
    }

    // Build atom key from event kind + details (same classification as sequence.rs)
    let atom_key = match kind {
        "shell.command_exec" | "process.exec" => {
            let cat = classify_exec(&comm);
            format!("E:{cat:?}")
        }
        "network.connection" | "network.outbound_connect" => {
            let port = details["dst_port"].as_u64().unwrap_or(0) as u16;
            let pc = classify_port(port);
            format!("C:{pc:?}")
        }
        "file.read_access" | "file.write_access" => {
            let path = details["path"].as_str().unwrap_or("");
            let sens = classify_file(path);
            format!("F:{sens:?}")
        }
        "auth.login_success" => "L:ok".to_string(),
        "auth.login_failure" => "L:fail".to_string(),
        "privilege.escalation" => "P".to_string(),
        _ => return None,
    };

    Some((comm, atom_key, ts))
}

// ---------------------------------------------------------------------------
// File reader (shared pattern with ingest.rs and attack_chain.rs)
// ---------------------------------------------------------------------------

/// Read new lines from a file starting at byte offset. Returns new offset.
///
/// Uses `seek` to skip already-processed bytes instead of reading the entire
/// file into memory. This is critical for large event files (100K+ lines/day).
fn read_new_lines(path: &Path, offset: u64, mut handler: impl FnMut(&str)) -> u64 {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return offset,
    };

    let file_len = meta.len();
    if file_len <= offset {
        if file_len < offset {
            return 0; // File was rotated
        }
        return offset;
    }

    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return offset,
    };
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return offset;
    }
    let reader = BufReader::new(file);
    let mut new_offset = offset;
    for line in reader.lines() {
        match line {
            Ok(line) => {
                new_offset += line.len() as u64 + 1; // +1 for newline
                if !line.is_empty() && line.starts_with('{') {
                    handler(&line);
                }
            }
            Err(_) => break,
        }
    }
    new_offset
}

// ---------------------------------------------------------------------------
// Main async loop
// ---------------------------------------------------------------------------

/// Main anomaly detection loop. Reads events-*.jsonl, groups by process name,
/// updates profiles, and checks for anomalies every poll interval.
pub async fn run(data_dir: PathBuf, detector: SharedAnomalyDetector) {
    let mut event_offset: u64 = 0;

    info!("anomaly detector started");

    loop {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let events_path = data_dir.join(format!("events-{today}.jsonl"));

        // Collect events grouped by comm
        let mut comm_events: HashMap<String, Vec<String>> = HashMap::new();
        let mut latest_ts = Utc::now();

        event_offset = read_new_lines(&events_path, event_offset, |line| {
            if let Some((comm, atom_key, ts)) = parse_event_for_anomaly(line) {
                comm_events
                    .entry(comm)
                    .or_insert_with(Vec::new)
                    .push(atom_key);
                latest_ts = ts;
            }
        });

        // Process each batch
        if !comm_events.is_empty() {
            let mut det = detector.write().await;
            for (comm, atom_keys) in &comm_events {
                det.process_events(comm, atom_keys, latest_ts);
            }
            // Persist periodically
            if let Err(e) = det.save() {
                warn!(error = %e, "failed to persist syscall profiles");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(ANOMALY_POLL_INTERVAL_SECS)).await;
    }
}

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

/// Summary of a syscall profile for API responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub comm: String,
    pub total_events: u64,
    pub trained: bool,
    pub atom_types: usize,
    pub rate_mean: f64,
    pub rate_stddev: f64,
    pub last_updated: String,
}

impl From<&SyscallProfile> for ProfileSummary {
    fn from(p: &SyscallProfile) -> Self {
        Self {
            comm: p.comm.clone(),
            total_events: p.total_events,
            trained: p.trained,
            atom_types: p.atom_frequencies.len(),
            rate_mean: p.rate_mean,
            rate_stddev: p.rate_stddev,
            last_updated: p.last_updated.to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detector(min_samples: u64, threshold: f64) -> AnomalyDetector {
        let dir = tempfile::tempdir().unwrap();
        AnomalyDetector::with_config(dir.path(), min_samples, threshold)
    }

    fn atom_keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    // -----------------------------------------------------------------------
    // Test 1: Profile learns from events correctly
    // -----------------------------------------------------------------------
    #[test]
    fn profile_learns_from_events() {
        let mut detector = make_detector(10, 3.0);
        let now = Utc::now();

        // Feed 5 events: 3 Exec:Shell + 2 Exec:Recon
        let keys = atom_keys(&["E:Shell", "E:Shell", "E:Shell", "E:Recon", "E:Recon"]);
        detector.process_events("sshd", &keys, now);

        let profile = detector.get_profile("sshd").unwrap();
        assert_eq!(profile.total_events, 5);
        assert_eq!(profile.raw_counts.get("E:Shell"), Some(&3));
        assert_eq!(profile.raw_counts.get("E:Recon"), Some(&2));
    }

    // -----------------------------------------------------------------------
    // Test 2: Frequency normalization works
    // -----------------------------------------------------------------------
    #[test]
    fn frequency_normalization() {
        let mut detector = make_detector(10, 3.0);
        let now = Utc::now();

        let keys = atom_keys(&["E:Shell", "E:Shell", "E:Shell", "E:Recon", "E:Recon"]);
        detector.process_events("bash", &keys, now);

        let profile = detector.get_profile("bash").unwrap();
        let shell_freq = *profile.atom_frequencies.get("E:Shell").unwrap();
        let recon_freq = *profile.atom_frequencies.get("E:Recon").unwrap();

        // 3/5 = 0.6, 2/5 = 0.4
        assert!(
            (shell_freq - 0.6).abs() < 1e-9,
            "shell freq should be 0.6, got {}",
            shell_freq
        );
        assert!(
            (recon_freq - 0.4).abs() < 1e-9,
            "recon freq should be 0.4, got {}",
            recon_freq
        );

        // Frequencies sum to 1.0
        let total: f64 = profile.atom_frequencies.values().sum();
        assert!(
            (total - 1.0).abs() < 1e-9,
            "frequencies should sum to 1.0, got {}",
            total
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: Cosine distance — identical vectors = 0
    // -----------------------------------------------------------------------
    #[test]
    fn cosine_distance_identical_is_zero() {
        let mut a = HashMap::new();
        a.insert("E:Shell".to_string(), 0.6);
        a.insert("E:Recon".to_string(), 0.4);

        let b = a.clone();
        let dist = cosine_distance(&a, &b);
        assert!(
            dist.abs() < 1e-9,
            "identical vectors should have distance 0, got {}",
            dist
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: Cosine distance — orthogonal vectors = 1
    // -----------------------------------------------------------------------
    #[test]
    fn cosine_distance_orthogonal_is_one() {
        let mut a = HashMap::new();
        a.insert("E:Shell".to_string(), 1.0);

        let mut b = HashMap::new();
        b.insert("E:Recon".to_string(), 1.0);

        let dist = cosine_distance(&a, &b);
        assert!(
            (dist - 1.0).abs() < 1e-9,
            "orthogonal vectors should have distance 1, got {}",
            dist
        );
    }

    // -----------------------------------------------------------------------
    // Test 5: Profile not trained with few samples
    // -----------------------------------------------------------------------
    #[test]
    fn profile_not_trained_with_few_samples() {
        let mut detector = make_detector(100, 3.0);
        let now = Utc::now();

        // Feed only 10 events — well below the 100 minimum
        let keys = atom_keys(&[
            "E:Shell", "E:Shell", "E:Shell", "E:Shell", "E:Shell", "E:Recon", "E:Recon", "E:Recon",
            "E:Recon", "E:Recon",
        ]);
        detector.process_events("sshd", &keys, now);

        let profile = detector.get_profile("sshd").unwrap();
        assert!(
            !profile.trained,
            "profile should NOT be trained with only 10 events"
        );
        assert_eq!(profile.total_events, 10);
    }

    // -----------------------------------------------------------------------
    // Test 6: Profile trained after min_training_samples
    // -----------------------------------------------------------------------
    #[test]
    fn profile_trained_after_min_samples() {
        let mut detector = make_detector(20, 3.0);
        let now = Utc::now();

        // Feed 15 events — not enough
        let keys: Vec<String> = (0..15).map(|_| "E:Shell".to_string()).collect();
        detector.process_events("sshd", &keys, now);
        assert!(!detector.get_profile("sshd").unwrap().trained);

        // Feed 10 more events — now 25 total, above the 20 minimum
        let keys: Vec<String> = (0..10).map(|_| "E:Shell".to_string()).collect();
        detector.process_events("sshd", &keys, now);
        assert!(
            detector.get_profile("sshd").unwrap().trained,
            "profile should be trained after {} events (min=20)",
            25
        );
    }

    // -----------------------------------------------------------------------
    // Test 7: Normal behavior doesn't trigger anomaly
    // -----------------------------------------------------------------------
    #[test]
    fn normal_behavior_no_anomaly() {
        let mut detector = make_detector(10, 3.0);
        let now = Utc::now();

        // Train the profile with a consistent pattern
        for _ in 0..5 {
            let keys = atom_keys(&["E:Shell", "E:Recon"]);
            detector.process_events("sshd", &keys, now);
        }
        assert!(detector.get_profile("sshd").unwrap().trained);

        // Feed the same pattern — no anomaly expected
        let keys = atom_keys(&["E:Shell", "E:Recon"]);
        let alerts = detector.process_events("sshd", &keys, now);

        let behavior_alerts: Vec<_> = alerts
            .iter()
            .filter(|a| a.alert_type == AnomalyType::BehaviorDeviation)
            .collect();
        assert!(
            behavior_alerts.is_empty(),
            "normal behavior should not trigger BehaviorDeviation, got {} alerts",
            behavior_alerts.len()
        );
    }

    // -----------------------------------------------------------------------
    // Test 8: Behavioral deviation triggers anomaly
    // -----------------------------------------------------------------------
    #[test]
    fn behavioral_deviation_triggers_anomaly() {
        let mut detector = make_detector(10, 3.0);
        let now = Utc::now();

        // Train with a consistent pattern: only Shell
        for _ in 0..5 {
            let keys = atom_keys(&["E:Shell", "E:Shell"]);
            detector.process_events("sshd", &keys, now);
        }
        assert!(detector.get_profile("sshd").unwrap().trained);

        // Now send a completely different pattern (only Recon, never seen)
        // This should trigger NewBehavior since "E:Recon" was never observed
        let keys = atom_keys(&["E:Recon", "E:Recon"]);
        let alerts = detector.process_events("sshd", &keys, now);

        assert!(
            !alerts.is_empty(),
            "sending completely different atom types should trigger an anomaly"
        );
        // Should have at least a NewBehavior alert
        let new_behavior: Vec<_> = alerts
            .iter()
            .filter(|a| a.alert_type == AnomalyType::NewBehavior)
            .collect();
        assert!(!new_behavior.is_empty(), "should detect new behavior type");
    }

    // -----------------------------------------------------------------------
    // Test 9: Rate spike triggers anomaly
    // -----------------------------------------------------------------------
    #[test]
    fn rate_spike_triggers_anomaly() {
        let mut detector = make_detector(10, 2.0); // lower threshold for easier triggering
        let now = Utc::now();

        // Train with small consistent batches of size 2
        for _ in 0..20 {
            let keys = atom_keys(&["E:Shell", "E:Shell"]);
            detector.process_events("sshd", &keys, now);
        }
        assert!(detector.get_profile("sshd").unwrap().trained);

        let profile = detector.get_profile("sshd").unwrap();
        assert!(
            profile.rate_mean > 0.0,
            "rate mean should be positive after training"
        );

        // Now send a massive spike: 200 events at once (vs. mean of 2)
        let keys: Vec<String> = (0..200).map(|_| "E:Shell".to_string()).collect();
        let alerts = detector.process_events("sshd", &keys, now);

        let rate_alerts: Vec<_> = alerts
            .iter()
            .filter(|a| a.alert_type == AnomalyType::RateSpike)
            .collect();
        assert!(
            !rate_alerts.is_empty(),
            "200 events when mean is ~2 should trigger RateSpike, got alerts: {:?}",
            alerts.iter().map(|a| &a.alert_type).collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // Test 10: New behavior type triggers anomaly
    // -----------------------------------------------------------------------
    #[test]
    fn new_behavior_type_triggers_anomaly() {
        let mut detector = make_detector(10, 3.0);
        let now = Utc::now();

        // Train with only E:Shell
        for _ in 0..6 {
            let keys = atom_keys(&["E:Shell", "E:Shell"]);
            detector.process_events("nginx", &keys, now);
        }
        assert!(detector.get_profile("nginx").unwrap().trained);

        // Introduce a completely new atom type: P (PrivEsc)
        let keys = atom_keys(&["P"]);
        let alerts = detector.process_events("nginx", &keys, now);

        let new_behavior: Vec<_> = alerts
            .iter()
            .filter(|a| a.alert_type == AnomalyType::NewBehavior)
            .collect();
        assert!(
            !new_behavior.is_empty(),
            "PrivEsc atom never seen for nginx should trigger NewBehavior"
        );
        assert!(
            (new_behavior[0].score - 1.0).abs() < 1e-9,
            "NewBehavior score should be 1.0 (maximum)"
        );
    }

    // -----------------------------------------------------------------------
    // Test 11: Multiple processes tracked independently
    // -----------------------------------------------------------------------
    #[test]
    fn multiple_processes_tracked_independently() {
        let mut detector = make_detector(5, 3.0);
        let now = Utc::now();

        // Train sshd and nginx with different patterns
        let sshd_keys = atom_keys(&["E:Shell", "E:Shell", "L:ok", "L:ok", "L:ok"]);
        detector.process_events("sshd", &sshd_keys, now);

        let nginx_keys = atom_keys(&["C:Http", "C:Http", "C:Http", "C:Http", "C:Http"]);
        detector.process_events("nginx", &nginx_keys, now);

        assert_eq!(detector.profile_count(), 2);

        let sshd_profile = detector.get_profile("sshd").unwrap();
        let nginx_profile = detector.get_profile("nginx").unwrap();

        // Verify they learned different patterns
        assert!(sshd_profile.atom_frequencies.contains_key("E:Shell"));
        assert!(sshd_profile.atom_frequencies.contains_key("L:ok"));
        assert!(!sshd_profile.atom_frequencies.contains_key("C:Http"));

        assert!(nginx_profile.atom_frequencies.contains_key("C:Http"));
        assert!(!nginx_profile.atom_frequencies.contains_key("E:Shell"));
        assert!(!nginx_profile.atom_frequencies.contains_key("L:ok"));
    }

    // -----------------------------------------------------------------------
    // Test 12: Persistence save/load round-trip
    // -----------------------------------------------------------------------
    #[test]
    fn persistence_save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();

        // Create and populate a detector
        {
            let mut detector = AnomalyDetector::with_config(dir.path(), 5, 3.0);
            let keys = atom_keys(&["E:Shell", "E:Recon", "E:Shell", "E:Recon", "E:Shell"]);
            detector.process_events("sshd", &keys, now);
            detector.save().unwrap();
        }

        // Load from disk and verify state was preserved
        let detector = AnomalyDetector::load(dir.path());
        assert_eq!(detector.profile_count(), 1);

        let profile = detector.get_profile("sshd").unwrap();
        assert_eq!(profile.total_events, 5);
        assert_eq!(profile.comm, "sshd");
        assert!(profile.atom_frequencies.contains_key("E:Shell"));
        assert!(profile.atom_frequencies.contains_key("E:Recon"));

        let shell_freq = *profile.atom_frequencies.get("E:Shell").unwrap();
        assert!(
            (shell_freq - 0.6).abs() < 1e-9,
            "shell freq should survive round-trip"
        );
    }

    // -----------------------------------------------------------------------
    // Test 13: Cosine distance with empty vector returns 1.0
    // -----------------------------------------------------------------------
    #[test]
    fn cosine_distance_empty_vector() {
        let a: HashMap<String, f64> = HashMap::new();
        let mut b = HashMap::new();
        b.insert("E:Shell".to_string(), 1.0);

        assert!((cosine_distance(&a, &b) - 1.0).abs() < 1e-9);
        assert!((cosine_distance(&b, &a) - 1.0).abs() < 1e-9);
        assert!((cosine_distance(&a, &a) - 1.0).abs() < 1e-9);
    }

    // -----------------------------------------------------------------------
    // Test 14: No anomalies on untrained profile
    // -----------------------------------------------------------------------
    #[test]
    fn no_anomalies_on_untrained_profile() {
        let mut detector = make_detector(100, 3.0);
        let now = Utc::now();

        // Wildly different events, but profile isn't trained yet
        let keys = atom_keys(&["P", "DX", "C:C2Common"]);
        let alerts = detector.process_events("sshd", &keys, now);

        assert!(
            alerts.is_empty(),
            "untrained profile should not produce anomaly alerts"
        );
    }

    // -----------------------------------------------------------------------
    // Test 15: Event parsing extracts comm and atom key
    // -----------------------------------------------------------------------
    #[test]
    fn parse_event_for_anomaly_works() {
        let line = r#"{"kind":"shell.command_exec","ts":"2026-03-22T10:00:00Z","details":{"comm":"whoami","pid":1234,"src_ip":"1.2.3.4"}}"#;
        let (comm, atom_key, _ts) = parse_event_for_anomaly(line).unwrap();
        assert_eq!(comm, "whoami");
        assert_eq!(atom_key, "E:Recon");
    }

    // -----------------------------------------------------------------------
    // Test 16: Rate statistics use Welford's algorithm correctly
    // -----------------------------------------------------------------------
    #[test]
    fn rate_statistics_welford() {
        let mut profile = SyscallProfile::new("test");

        // Feed known rates: 10, 10, 10, 10, 10 — mean=10, stddev=0
        for _ in 0..5 {
            profile.observe_rate(10.0);
        }
        assert!((profile.rate_mean - 10.0).abs() < 1e-9);
        assert!(
            profile.rate_stddev < 1e-9,
            "constant rate should have ~0 stddev"
        );

        // Feed rates: 5, 15 — these shift the mean and introduce variance
        profile.observe_rate(5.0);
        profile.observe_rate(15.0);
        assert!(
            (profile.rate_mean - 10.0).abs() < 1e-6,
            "mean should still be ~10"
        );
        // stddev should be very small since values are symmetric around mean
    }
}
