//! Attack Chain Tracking — MITRE ATT&CK kill chain progression per attacker.
//!
//! Reads incidents from JSONL files, extracts the detector name from `incident_id`,
//! maps detectors to MITRE ATT&CK tactics, and groups by attacker IP + time window
//! to track kill chain progression in real time.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single observed MITRE ATT&CK tactic within an attack chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticObservation {
    /// MITRE tactic name (e.g., "Initial Access")
    pub tactic: String,
    /// MITRE technique ID (e.g., "T1110")
    pub technique_id: String,
    /// Human-readable technique name (e.g., "Brute Force")
    pub technique_name: String,
    /// When this tactic was first observed in the chain
    pub first_seen: DateTime<Utc>,
    /// Number of incidents that contributed to this tactic observation
    pub incident_count: usize,
}

/// Severity level of an attack chain based on kill chain progression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ChainLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainLevel::Low => write!(f, "Low"),
            ChainLevel::Medium => write!(f, "Medium"),
            ChainLevel::High => write!(f, "High"),
            ChainLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// An attack chain tracking kill chain progression for a single attacker IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    /// Source IP of the attacker
    pub source_ip: String,
    /// When the first incident in this chain was observed
    pub first_seen: DateTime<Utc>,
    /// When the most recent incident was observed
    pub last_seen: DateTime<Utc>,
    /// Ordered list of tactic observations (by first_seen)
    pub tactics_observed: Vec<TacticObservation>,
    /// Chain score 0–100 based on number of distinct tactics
    pub chain_score: u32,
    /// Derived severity level
    pub chain_level: ChainLevel,
    /// Total number of incidents in this chain
    pub total_incidents: usize,
    /// Set of all detector names that fired for this chain
    pub detectors_triggered: HashSet<String>,
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK mapping
// ---------------------------------------------------------------------------

/// Information about a MITRE technique mapped from a detector.
#[derive(Debug, Clone)]
struct TechniqueInfo {
    tactic: &'static str,
    technique_id: &'static str,
    technique_name: &'static str,
}

/// Map a detector name (extracted from `incident_id`) to a MITRE ATT&CK tactic + technique.
fn detector_to_tactic(detector: &str) -> Option<TechniqueInfo> {
    Some(match detector {
        // --- Reconnaissance ---
        "port_scan" => TechniqueInfo {
            tactic: "Reconnaissance",
            technique_id: "T1046",
            technique_name: "Network Service Scanning",
        },
        "web_scan" => TechniqueInfo {
            tactic: "Reconnaissance",
            technique_id: "T1595",
            technique_name: "Active Scanning",
        },
        "user_agent_scanner" => TechniqueInfo {
            tactic: "Reconnaissance",
            technique_id: "T1595.002",
            technique_name: "Vulnerability Scanning",
        },
        "search_abuse" => TechniqueInfo {
            tactic: "Reconnaissance",
            technique_id: "T1593",
            technique_name: "Search Open Websites/Domains",
        },
        "osquery_anomaly" => TechniqueInfo {
            tactic: "Reconnaissance",
            technique_id: "T1082",
            technique_name: "System Information Discovery",
        },

        // --- Initial Access ---
        "ssh_bruteforce" => TechniqueInfo {
            tactic: "Initial Access",
            technique_id: "T1110",
            technique_name: "Brute Force",
        },
        "credential_stuffing" => TechniqueInfo {
            tactic: "Initial Access",
            technique_id: "T1110.004",
            technique_name: "Credential Stuffing",
        },
        "distributed_ssh" => TechniqueInfo {
            tactic: "Initial Access",
            technique_id: "T1110.003",
            technique_name: "Password Spraying",
        },
        "suspicious_login" => TechniqueInfo {
            tactic: "Initial Access",
            technique_id: "T1078",
            technique_name: "Valid Accounts",
        },
        "ssh_key_injection" => TechniqueInfo {
            tactic: "Initial Access",
            technique_id: "T1098.004",
            technique_name: "SSH Authorized Keys",
        },
        "web_shell" => TechniqueInfo {
            tactic: "Initial Access",
            technique_id: "T1505.003",
            technique_name: "Web Shell",
        },

        // --- Execution ---
        "execution_guard" => TechniqueInfo {
            tactic: "Execution",
            technique_id: "T1059",
            technique_name: "Command and Scripting Interpreter",
        },
        "process_tree" => TechniqueInfo {
            tactic: "Execution",
            technique_id: "T1059.004",
            technique_name: "Unix Shell",
        },
        "fileless" => TechniqueInfo {
            tactic: "Execution",
            technique_id: "T1620",
            technique_name: "Reflective Code Loading",
        },
        "reverse_shell" => TechniqueInfo {
            tactic: "Execution",
            technique_id: "T1059.004",
            technique_name: "Unix Shell (Reverse)",
        },

        // --- Persistence ---
        "crontab_persistence" => TechniqueInfo {
            tactic: "Persistence",
            technique_id: "T1053.003",
            technique_name: "Cron",
        },
        "systemd_persistence" => TechniqueInfo {
            tactic: "Persistence",
            technique_id: "T1543.002",
            technique_name: "Systemd Service",
        },
        "user_creation" => TechniqueInfo {
            tactic: "Persistence",
            technique_id: "T1136.001",
            technique_name: "Local Account",
        },

        // --- Privilege Escalation ---
        "privesc" => TechniqueInfo {
            tactic: "Privilege Escalation",
            technique_id: "T1068",
            technique_name: "Exploitation for Privilege Escalation",
        },
        "sudo_abuse" => TechniqueInfo {
            tactic: "Privilege Escalation",
            technique_id: "T1548.003",
            technique_name: "Sudo and Sudo Caching",
        },
        "container_escape" => TechniqueInfo {
            tactic: "Privilege Escalation",
            technique_id: "T1611",
            technique_name: "Escape to Host",
        },

        // --- Defense Evasion ---
        "log_tampering" => TechniqueInfo {
            tactic: "Defense Evasion",
            technique_id: "T1070",
            technique_name: "Indicator Removal",
        },
        "rootkit" => TechniqueInfo {
            tactic: "Defense Evasion",
            technique_id: "T1014",
            technique_name: "Rootkit",
        },
        "process_injection" => TechniqueInfo {
            tactic: "Defense Evasion",
            technique_id: "T1055",
            technique_name: "Process Injection",
        },
        "docker_anomaly" => TechniqueInfo {
            tactic: "Defense Evasion",
            technique_id: "T1610",
            technique_name: "Deploy Container",
        },

        // --- Credential Access ---
        "credential_harvest" => TechniqueInfo {
            tactic: "Credential Access",
            technique_id: "T1003",
            technique_name: "OS Credential Dumping",
        },
        "integrity_alert" => TechniqueInfo {
            tactic: "Credential Access",
            technique_id: "T1552.001",
            technique_name: "Credentials In Files",
        },

        // --- Discovery ---
        "lateral_movement" => TechniqueInfo {
            tactic: "Discovery",
            technique_id: "T1018",
            technique_name: "Remote System Discovery",
        },

        // --- Lateral Movement ---
        "dns_tunneling" => TechniqueInfo {
            tactic: "Lateral Movement",
            technique_id: "T1572",
            technique_name: "Protocol Tunneling",
        },

        // --- Exfiltration ---
        "data_exfiltration" => TechniqueInfo {
            tactic: "Exfiltration",
            technique_id: "T1041",
            technique_name: "Exfiltration Over C2 Channel",
        },
        "outbound_anomaly" => TechniqueInfo {
            tactic: "Exfiltration",
            technique_id: "T1048",
            technique_name: "Exfiltration Over Alternative Protocol",
        },

        // --- Impact ---
        "crypto_miner" => TechniqueInfo {
            tactic: "Impact",
            technique_id: "T1496",
            technique_name: "Resource Hijacking",
        },
        "ransomware" => TechniqueInfo {
            tactic: "Impact",
            technique_id: "T1486",
            technique_name: "Data Encrypted for Impact",
        },
        "kernel_module_load" => TechniqueInfo {
            tactic: "Impact",
            technique_id: "T1547.006",
            technique_name: "Kernel Modules and Extensions",
        },

        // --- C2 (maps to Lateral Movement as ongoing C2 comms) ---
        "c2_callback" => TechniqueInfo {
            tactic: "Lateral Movement",
            technique_id: "T1071",
            technique_name: "Application Layer Protocol (C2)",
        },

        // --- Suricata covers network-level IDS (maps to Reconnaissance) ---
        "suricata_alert" => TechniqueInfo {
            tactic: "Reconnaissance",
            technique_id: "T1040",
            technique_name: "Network Sniffing / IDS Alert",
        },

        // --- Kill Chain (kernel eBPF LSM blocked) ---
        "kill_chain" => TechniqueInfo {
            tactic: "Execution",
            technique_id: "T1059",
            technique_name: "Kill Chain Blocked (Kernel LSM)",
        },

        _ => return None,
    })
}

/// Returns the set of all detector names that have a MITRE mapping.
pub fn all_mapped_detectors() -> HashSet<&'static str> {
    [
        "port_scan",
        "web_scan",
        "user_agent_scanner",
        "search_abuse",
        "osquery_anomaly",
        "ssh_bruteforce",
        "credential_stuffing",
        "distributed_ssh",
        "suspicious_login",
        "ssh_key_injection",
        "web_shell",
        "execution_guard",
        "process_tree",
        "fileless",
        "reverse_shell",
        "crontab_persistence",
        "systemd_persistence",
        "user_creation",
        "privesc",
        "sudo_abuse",
        "container_escape",
        "log_tampering",
        "rootkit",
        "process_injection",
        "docker_anomaly",
        "credential_harvest",
        "integrity_alert",
        "lateral_movement",
        "dns_tunneling",
        "data_exfiltration",
        "outbound_anomaly",
        "crypto_miner",
        "ransomware",
        "kernel_module_load",
        "c2_callback",
        "suricata_alert",
        "kill_chain",
    ]
    .into_iter()
    .collect()
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Calculate chain score (0–100) from the number of distinct tactics observed.
fn calculate_chain_score(num_tactics: usize) -> u32 {
    match num_tactics {
        0 => 0,
        1 => 10,
        2 => 25,
        3 => 35,
        4 => 50,
        5 => 60,
        6 => 75,
        7 => 80,
        8 => 85,
        9 => 90,
        10 => 95,
        _ => 100,
    }
}

/// Derive the chain level from the number of distinct tactics.
fn calculate_chain_level(num_tactics: usize) -> ChainLevel {
    match num_tactics {
        0..=2 => ChainLevel::Low,
        3..=4 => ChainLevel::Medium,
        5..=6 => ChainLevel::High,
        _ => ChainLevel::Critical,
    }
}

// ---------------------------------------------------------------------------
// Chain tracker
// ---------------------------------------------------------------------------

/// Time window for grouping incidents into a single chain (1 hour).
const CHAIN_WINDOW_SECS: i64 = 3600;

/// How often to poll for new incidents (seconds).
const CHAIN_POLL_INTERVAL_SECS: u64 = 5;

/// Maximum number of concurrent attack chains to prevent unbounded memory growth.
const MAX_CHAINS: usize = 10_000;

/// In-memory state for all active attack chains.
pub struct AttackChainTracker {
    /// Active chains keyed by source IP.
    chains: HashMap<String, AttackChain>,
    /// Path for persistence.
    persist_path: PathBuf,
}

impl AttackChainTracker {
    /// Load existing chains from disk or start fresh.
    pub fn load(dna_dir: &Path) -> Self {
        let persist_path = dna_dir.join("attack-chains.json");
        let chains = if persist_path.exists() {
            match std::fs::read_to_string(&persist_path) {
                Ok(content) => {
                    let list: Vec<AttackChain> = serde_json::from_str(&content).unwrap_or_default();
                    let map: HashMap<String, AttackChain> =
                        list.into_iter().map(|c| (c.source_ip.clone(), c)).collect();
                    info!(count = map.len(), "loaded attack chains from disk");
                    map
                }
                Err(e) => {
                    warn!(error = %e, "failed to read attack chains, starting fresh");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        Self {
            chains,
            persist_path,
        }
    }

    /// Save chains to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        let list: Vec<&AttackChain> = self.chains.values().collect();
        let json = serde_json::to_string_pretty(&list)?;
        std::fs::write(&self.persist_path, json)?;
        Ok(())
    }

    /// Process a single incident and update chains. Returns `true` if a new tactic
    /// was observed (chain advancement).
    pub fn ingest_incident(&mut self, ip: &str, detector: &str, ts: DateTime<Utc>) -> bool {
        let tech = match detector_to_tactic(detector) {
            Some(t) => t,
            None => {
                debug!(detector = detector, "no MITRE mapping for detector");
                return false;
            }
        };

        // Cap chains to prevent unbounded growth
        if self.chains.len() >= MAX_CHAINS && !self.chains.contains_key(ip) {
            // Evict the oldest chain by last_seen
            if let Some(oldest_ip) = self
                .chains
                .iter()
                .min_by_key(|(_, c)| c.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.chains.remove(&oldest_ip);
            }
        }

        let chain = self
            .chains
            .entry(ip.to_string())
            .or_insert_with(|| AttackChain {
                source_ip: ip.to_string(),
                first_seen: ts,
                last_seen: ts,
                tactics_observed: Vec::new(),
                chain_score: 0,
                chain_level: ChainLevel::Low,
                total_incidents: 0,
                detectors_triggered: HashSet::new(),
            });

        chain.last_seen = ts;
        chain.total_incidents += 1;
        chain.detectors_triggered.insert(detector.to_string());

        // Check if this tactic is already observed
        let tactic_name = tech.tactic;
        let existing = chain
            .tactics_observed
            .iter_mut()
            .find(|t| t.tactic == tactic_name);

        let new_tactic = if let Some(obs) = existing {
            obs.incident_count += 1;
            false
        } else {
            chain.tactics_observed.push(TacticObservation {
                tactic: tactic_name.to_string(),
                technique_id: tech.technique_id.to_string(),
                technique_name: tech.technique_name.to_string(),
                first_seen: ts,
                incident_count: 1,
            });
            true
        };

        // Recalculate score
        let num_tactics = chain.tactics_observed.len();
        chain.chain_score = calculate_chain_score(num_tactics);
        chain.chain_level = calculate_chain_level(num_tactics);

        if new_tactic {
            info!(
                ip = ip,
                tactic = tactic_name,
                technique = tech.technique_name,
                chain_score = chain.chain_score,
                chain_level = %chain.chain_level,
                tactics_total = num_tactics,
                "attack chain advancement detected"
            );
        }

        new_tactic
    }

    /// Expire chains whose last activity is older than the time window.
    pub fn expire_old_chains(&mut self, now: DateTime<Utc>) {
        let window = Duration::seconds(CHAIN_WINDOW_SECS);
        let before = self.chains.len();
        self.chains
            .retain(|_ip, chain| now - chain.last_seen <= window);
        let expired = before - self.chains.len();
        if expired > 0 {
            debug!(expired = expired, "expired stale attack chains");
        }
    }

    /// Get all active chains sorted by score (highest first).
    pub fn all_chains_sorted(&self) -> Vec<&AttackChain> {
        let mut chains: Vec<&AttackChain> = self.chains.values().collect();
        chains.sort_by(|a, b| b.chain_score.cmp(&a.chain_score));
        chains
    }

    /// Get chain for a specific IP.
    pub fn get_chain(&self, ip: &str) -> Option<&AttackChain> {
        self.chains.get(ip)
    }

    /// Number of active chains.
    pub fn len(&self) -> usize {
        self.chains.len()
    }
}

// ---------------------------------------------------------------------------
// Incident parsing (reads the same JSONL as ingest.rs)
// ---------------------------------------------------------------------------

/// Extract (source_ip, detector_name, timestamp) from an incident JSON line.
fn parse_incident_for_chain(line: &str) -> Option<(String, String, DateTime<Utc>)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let incident_id = v["incident_id"].as_str().unwrap_or("");
    // Detector name is the first segment before ':'
    let detector = incident_id.split(':').next().unwrap_or("").to_string();
    if detector.is_empty() {
        return None;
    }

    let ts = v["ts"]
        .as_str()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now);

    // Extract IP from entities
    let ip = v["entities"]
        .as_array()
        .and_then(|arr| {
            arr.iter().find_map(|e| {
                let etype = e["type"].as_str().unwrap_or("");
                if etype == "ip" || etype == "Ip" {
                    e["value"].as_str()
                } else {
                    None
                }
            })
        })
        .unwrap_or("")
        .to_string();

    if ip.is_empty() {
        return None;
    }

    Some((ip, detector, ts))
}

/// Read new lines from a file starting at byte offset. Returns new offset.
///
/// Uses `seek` to skip already-processed bytes instead of reading the entire
/// file into memory. This is critical for large incident files.
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
// Main loop
// ---------------------------------------------------------------------------

use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared tracker type for API access.
pub type SharedChainTracker = Arc<RwLock<AttackChainTracker>>;

/// Main attack chain tracking loop — runs alongside the ingest loop.
pub async fn run(data_dir: PathBuf, tracker: SharedChainTracker) {
    let mut incident_offset: u64 = 0;

    info!("attack chain tracker started");

    loop {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));

        let mut new_incidents: Vec<(String, String, DateTime<Utc>)> = Vec::new();

        incident_offset = read_new_lines(&incidents_path, incident_offset, |line| {
            if let Some(parsed) = parse_incident_for_chain(line) {
                new_incidents.push(parsed);
            }
        });

        if !new_incidents.is_empty() {
            let mut tracker = tracker.write().await;
            for (ip, detector, ts) in new_incidents {
                tracker.ingest_incident(&ip, &detector, ts);
            }
            // Expire old chains
            tracker.expire_old_chains(Utc::now());
            // Persist
            if let Err(e) = tracker.save() {
                warn!(error = %e, "failed to persist attack chains");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(CHAIN_POLL_INTERVAL_SECS)).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_tracker() -> AttackChainTracker {
        let dir = tempfile::tempdir().unwrap();
        AttackChainTracker::load(dir.path())
    }

    // -----------------------------------------------------------------------
    // Test 1: Single tactic = Low score
    // -----------------------------------------------------------------------
    #[test]
    fn single_tactic_is_low() {
        let mut tracker = make_tracker();
        let now = Utc::now();
        tracker.ingest_incident("1.2.3.4", "ssh_bruteforce", now);

        let chain = tracker.get_chain("1.2.3.4").unwrap();
        assert_eq!(chain.chain_level, ChainLevel::Low);
        assert_eq!(chain.tactics_observed.len(), 1);
        assert!(chain.chain_score <= 25);
    }

    // -----------------------------------------------------------------------
    // Test 2: Three tactics = Medium
    // -----------------------------------------------------------------------
    #[test]
    fn three_tactics_is_medium() {
        let mut tracker = make_tracker();
        let now = Utc::now();
        // Initial Access + Execution + Persistence = 3 tactics
        tracker.ingest_incident("1.2.3.4", "ssh_bruteforce", now);
        tracker.ingest_incident("1.2.3.4", "execution_guard", now);
        tracker.ingest_incident("1.2.3.4", "crontab_persistence", now);

        let chain = tracker.get_chain("1.2.3.4").unwrap();
        assert_eq!(chain.chain_level, ChainLevel::Medium);
        assert_eq!(chain.tactics_observed.len(), 3);
        assert!(chain.chain_score > 25 && chain.chain_score <= 50);
    }

    // -----------------------------------------------------------------------
    // Test 3: Five tactics = High
    // -----------------------------------------------------------------------
    #[test]
    fn five_tactics_is_high() {
        let mut tracker = make_tracker();
        let now = Utc::now();
        // Reconnaissance + Initial Access + Execution + Persistence + Privilege Escalation
        tracker.ingest_incident("1.2.3.4", "port_scan", now);
        tracker.ingest_incident("1.2.3.4", "ssh_bruteforce", now);
        tracker.ingest_incident("1.2.3.4", "execution_guard", now);
        tracker.ingest_incident("1.2.3.4", "crontab_persistence", now);
        tracker.ingest_incident("1.2.3.4", "privesc", now);

        let chain = tracker.get_chain("1.2.3.4").unwrap();
        assert_eq!(chain.chain_level, ChainLevel::High);
        assert_eq!(chain.tactics_observed.len(), 5);
        assert!(chain.chain_score > 50 && chain.chain_score <= 75);
    }

    // -----------------------------------------------------------------------
    // Test 4: Seven tactics = Critical
    // -----------------------------------------------------------------------
    #[test]
    fn seven_tactics_is_critical() {
        let mut tracker = make_tracker();
        let now = Utc::now();
        // Recon + Initial Access + Execution + Persistence + Priv Esc + Defense Evasion + Credential Access
        tracker.ingest_incident("1.2.3.4", "port_scan", now); // Reconnaissance
        tracker.ingest_incident("1.2.3.4", "ssh_bruteforce", now); // Initial Access
        tracker.ingest_incident("1.2.3.4", "execution_guard", now); // Execution
        tracker.ingest_incident("1.2.3.4", "crontab_persistence", now); // Persistence
        tracker.ingest_incident("1.2.3.4", "privesc", now); // Privilege Escalation
        tracker.ingest_incident("1.2.3.4", "log_tampering", now); // Defense Evasion
        tracker.ingest_incident("1.2.3.4", "credential_harvest", now); // Credential Access

        let chain = tracker.get_chain("1.2.3.4").unwrap();
        assert_eq!(chain.chain_level, ChainLevel::Critical);
        assert_eq!(chain.tactics_observed.len(), 7);
        assert!(chain.chain_score > 75);
    }

    // -----------------------------------------------------------------------
    // Test 5: Same IP different detectors group together
    // -----------------------------------------------------------------------
    #[test]
    fn same_ip_groups_together() {
        let mut tracker = make_tracker();
        let now = Utc::now();
        tracker.ingest_incident("10.0.0.1", "ssh_bruteforce", now);
        tracker.ingest_incident("10.0.0.1", "credential_stuffing", now);
        tracker.ingest_incident("10.0.0.1", "port_scan", now);

        assert_eq!(tracker.len(), 1);
        let chain = tracker.get_chain("10.0.0.1").unwrap();
        assert_eq!(chain.total_incidents, 3);
        assert_eq!(chain.detectors_triggered.len(), 3);
        assert!(chain.detectors_triggered.contains("ssh_bruteforce"));
        assert!(chain.detectors_triggered.contains("credential_stuffing"));
        assert!(chain.detectors_triggered.contains("port_scan"));
    }

    // -----------------------------------------------------------------------
    // Test 6: Different IPs tracked independently
    // -----------------------------------------------------------------------
    #[test]
    fn different_ips_tracked_independently() {
        let mut tracker = make_tracker();
        let now = Utc::now();
        tracker.ingest_incident("1.1.1.1", "ssh_bruteforce", now);
        tracker.ingest_incident("2.2.2.2", "port_scan", now);
        tracker.ingest_incident("3.3.3.3", "privesc", now);

        assert_eq!(tracker.len(), 3);
        assert!(tracker.get_chain("1.1.1.1").is_some());
        assert!(tracker.get_chain("2.2.2.2").is_some());
        assert!(tracker.get_chain("3.3.3.3").is_some());

        // Each should have exactly 1 incident
        assert_eq!(tracker.get_chain("1.1.1.1").unwrap().total_incidents, 1);
        assert_eq!(tracker.get_chain("2.2.2.2").unwrap().total_incidents, 1);
        assert_eq!(tracker.get_chain("3.3.3.3").unwrap().total_incidents, 1);
    }

    // -----------------------------------------------------------------------
    // Test 7: Tactic deduplication (same tactic seen twice doesn't double count)
    // -----------------------------------------------------------------------
    #[test]
    fn tactic_deduplication() {
        let mut tracker = make_tracker();
        let now = Utc::now();
        // Both ssh_bruteforce and credential_stuffing map to "Initial Access"
        tracker.ingest_incident("1.2.3.4", "ssh_bruteforce", now);
        tracker.ingest_incident("1.2.3.4", "credential_stuffing", now);
        tracker.ingest_incident("1.2.3.4", "distributed_ssh", now);

        let chain = tracker.get_chain("1.2.3.4").unwrap();
        // All three detectors map to Initial Access — only 1 tactic should be counted
        assert_eq!(chain.tactics_observed.len(), 1);
        assert_eq!(chain.tactics_observed[0].tactic, "Initial Access");
        // But incident_count should be 3
        assert_eq!(chain.tactics_observed[0].incident_count, 3);
        // Total incidents also 3
        assert_eq!(chain.total_incidents, 3);
        // Score stays Low (1 tactic)
        assert_eq!(chain.chain_level, ChainLevel::Low);
    }

    // -----------------------------------------------------------------------
    // Test 8: Chain score calculation
    // -----------------------------------------------------------------------
    #[test]
    fn chain_score_calculation() {
        assert_eq!(calculate_chain_score(0), 0);
        assert_eq!(calculate_chain_score(1), 10);
        assert_eq!(calculate_chain_score(2), 25);
        assert_eq!(calculate_chain_score(3), 35);
        assert_eq!(calculate_chain_score(4), 50);
        assert_eq!(calculate_chain_score(5), 60);
        assert_eq!(calculate_chain_score(6), 75);
        assert_eq!(calculate_chain_score(7), 80);
        assert_eq!(calculate_chain_score(8), 85);
        assert_eq!(calculate_chain_score(9), 90);
        assert_eq!(calculate_chain_score(10), 95);
        assert_eq!(calculate_chain_score(11), 100);

        // Verify level thresholds
        assert_eq!(calculate_chain_level(1), ChainLevel::Low);
        assert_eq!(calculate_chain_level(2), ChainLevel::Low);
        assert_eq!(calculate_chain_level(3), ChainLevel::Medium);
        assert_eq!(calculate_chain_level(4), ChainLevel::Medium);
        assert_eq!(calculate_chain_level(5), ChainLevel::High);
        assert_eq!(calculate_chain_level(6), ChainLevel::High);
        assert_eq!(calculate_chain_level(7), ChainLevel::Critical);
        assert_eq!(calculate_chain_level(8), ChainLevel::Critical);
    }

    // -----------------------------------------------------------------------
    // Test 9: Time window expiry (old chains expire)
    // -----------------------------------------------------------------------
    #[test]
    fn time_window_expiry() {
        let mut tracker = make_tracker();
        let old = Utc::now() - Duration::seconds(CHAIN_WINDOW_SECS + 60);
        let recent = Utc::now();

        tracker.ingest_incident("1.1.1.1", "ssh_bruteforce", old);
        tracker.ingest_incident("2.2.2.2", "port_scan", recent);

        assert_eq!(tracker.len(), 2);

        // Expire — the old chain should be removed
        tracker.expire_old_chains(Utc::now());

        assert_eq!(tracker.len(), 1);
        assert!(tracker.get_chain("1.1.1.1").is_none());
        assert!(tracker.get_chain("2.2.2.2").is_some());
    }

    // -----------------------------------------------------------------------
    // Test 10: Detector to tactic mapping covers all 36 detectors
    // -----------------------------------------------------------------------
    #[test]
    fn detector_mapping_covers_all_36() {
        let all_detectors = [
            "ssh_bruteforce",
            "credential_stuffing",
            "port_scan",
            "sudo_abuse",
            "c2_callback",
            "container_escape",
            "distributed_ssh",
            "suspicious_login",
            "process_tree",
            "docker_anomaly",
            "integrity_alert",
            "privesc",
            "search_abuse",
            "web_scan",
            "user_agent_scanner",
            "execution_guard",
            "osquery_anomaly",
            "suricata_alert",
            "dns_tunneling",
            "fileless",
            "lateral_movement",
            "log_tampering",
            "crypto_miner",
            "credential_harvest",
            "crontab_persistence",
            "data_exfiltration",
            "kernel_module_load",
            "outbound_anomaly",
            "process_injection",
            "ransomware",
            "reverse_shell",
            "rootkit",
            "ssh_key_injection",
            "systemd_persistence",
            "user_creation",
            "web_shell",
            "kill_chain",
        ];

        assert_eq!(all_detectors.len(), 37, "expected 37 detectors");

        let mapped = all_mapped_detectors();
        assert_eq!(mapped.len(), 37, "mapped set should have 37 entries");

        for det in &all_detectors {
            assert!(
                detector_to_tactic(det).is_some(),
                "detector '{}' has no MITRE mapping",
                det
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: Chain advancement returns true for new tactic
    // -----------------------------------------------------------------------
    #[test]
    fn chain_advancement_returns_true_for_new_tactic() {
        let mut tracker = make_tracker();
        let now = Utc::now();

        // First tactic — new
        let advanced = tracker.ingest_incident("1.2.3.4", "ssh_bruteforce", now);
        assert!(advanced, "first tactic should be a chain advancement");

        // Same tactic again — not new
        let advanced = tracker.ingest_incident("1.2.3.4", "credential_stuffing", now);
        assert!(!advanced, "same tactic should not be a chain advancement");

        // New tactic — advancement
        let advanced = tracker.ingest_incident("1.2.3.4", "privesc", now);
        assert!(advanced, "new tactic should be a chain advancement");
    }

    // -----------------------------------------------------------------------
    // Test 12: Unknown detector is ignored
    // -----------------------------------------------------------------------
    #[test]
    fn unknown_detector_ignored() {
        let mut tracker = make_tracker();
        let now = Utc::now();

        let advanced = tracker.ingest_incident("1.2.3.4", "made_up_detector", now);
        assert!(!advanced);
        assert!(tracker.get_chain("1.2.3.4").is_none());
    }

    // -----------------------------------------------------------------------
    // Test 13: all_chains_sorted returns highest score first
    // -----------------------------------------------------------------------
    #[test]
    fn all_chains_sorted_by_score() {
        let mut tracker = make_tracker();
        let now = Utc::now();

        // IP with 1 tactic (low score)
        tracker.ingest_incident("10.0.0.1", "ssh_bruteforce", now);

        // IP with 3 tactics (medium score)
        tracker.ingest_incident("10.0.0.2", "ssh_bruteforce", now);
        tracker.ingest_incident("10.0.0.2", "execution_guard", now);
        tracker.ingest_incident("10.0.0.2", "crontab_persistence", now);

        let sorted = tracker.all_chains_sorted();
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].source_ip, "10.0.0.2"); // higher score first
        assert_eq!(sorted[1].source_ip, "10.0.0.1");
    }

    // -----------------------------------------------------------------------
    // Test 14: Parse incident line extracts detector and IP
    // -----------------------------------------------------------------------
    #[test]
    fn parse_incident_line() {
        let line = r#"{"incident_id":"ssh_bruteforce:1.2.3.4:2026-03-22T10:00Z","ts":"2026-03-22T10:00:00Z","title":"SSH brute force","entities":[{"type":"ip","value":"1.2.3.4"}]}"#;
        let (ip, detector, _ts) = parse_incident_for_chain(line).unwrap();
        assert_eq!(ip, "1.2.3.4");
        assert_eq!(detector, "ssh_bruteforce");
    }

    // -----------------------------------------------------------------------
    // Test 15: Persistence round-trip (save and reload)
    // -----------------------------------------------------------------------
    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();

        {
            let mut tracker = AttackChainTracker::load(dir.path());
            tracker.ingest_incident("5.5.5.5", "ssh_bruteforce", now);
            tracker.ingest_incident("5.5.5.5", "privesc", now);
            tracker.save().unwrap();
        }

        let tracker = AttackChainTracker::load(dir.path());
        assert_eq!(tracker.len(), 1);
        let chain = tracker.get_chain("5.5.5.5").unwrap();
        assert_eq!(chain.tactics_observed.len(), 2);
        assert_eq!(chain.total_incidents, 2);
        assert_eq!(chain.chain_level, ChainLevel::Low);
    }
}
