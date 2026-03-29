//! Ingestion loop — reads Inner Warden JSONL files and extracts behavioral sequences.
//!
//! Watches events-*.jsonl and incidents-*.jsonl for new entries.
//! Groups events by source IP + time window into sessions.
//! Converts sessions into BehaviorSequences, fingerprints them, classifies, and stores.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::classifier;
use crate::fingerprint;
use crate::sequence::*;
use crate::store::DnaStore;

/// Map kill chain pattern string (from evidence JSON) to the enum variant.
fn classify_kill_chain_pattern(s: &str) -> KillChainPattern {
    match s.to_uppercase().as_str() {
        "REVERSE_SHELL" => KillChainPattern::ReverseShell,
        "BIND_SHELL" => KillChainPattern::BindShell,
        "CODE_INJECT" => KillChainPattern::CodeInject,
        "EXPLOIT_SHELL" => KillChainPattern::ExploitShell,
        "INJECT_SHELL" => KillChainPattern::InjectShell,
        "EXPLOIT_C2" => KillChainPattern::ExploitC2,
        "FULL_EXPLOIT" => KillChainPattern::FullExploit,
        "DATA_EXFIL" => KillChainPattern::DataExfil,
        _ => KillChainPattern::Unknown,
    }
}

/// Session timeout: if no events from same IP for this long, close the session.
const SESSION_TIMEOUT_SECS: i64 = 300;

/// How often to check for new data.
const POLL_INTERVAL_SECS: u64 = 5;

/// Maximum number of concurrent sessions to prevent unbounded memory growth.
const MAX_SESSIONS: usize = 10_000;

/// Active sessions being built.
struct SessionBuilder {
    sessions: HashMap<String, BehaviorSequence>,
}

impl SessionBuilder {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Add an event to the appropriate session.
    fn add_event(&mut self, ip: &str, atom: Atom, ts: DateTime<Utc>, pid: Option<u32>) {
        // Cap sessions to prevent unbounded growth
        if self.sessions.len() >= MAX_SESSIONS && !self.sessions.contains_key(ip) {
            // Evict oldest session by last_seen
            if let Some(oldest_ip) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.sessions.remove(&oldest_ip);
            }
        }

        let session = self
            .sessions
            .entry(ip.to_string())
            .or_insert_with(|| BehaviorSequence {
                source_ip: ip.to_string(),
                atoms: Vec::new(),
                first_seen: ts,
                last_seen: ts,
                pids: Vec::new(),
            });
        session.atoms.push(atom);
        session.last_seen = ts;
        if let Some(p) = pid {
            if !session.pids.contains(&p) {
                session.pids.push(p);
            }
        }
    }

    /// Close sessions that have timed out and return their sequences.
    fn close_stale(&mut self, now: DateTime<Utc>) -> Vec<BehaviorSequence> {
        let timeout = Duration::seconds(SESSION_TIMEOUT_SECS);
        let mut closed = Vec::new();
        self.sessions.retain(|_ip, session| {
            if now - session.last_seen > timeout {
                closed.push(session.clone());
                false
            } else {
                true
            }
        });
        closed
    }
}

/// Parse a single event JSON line and extract an atom + metadata.
fn parse_event(line: &str) -> Option<(String, Atom, DateTime<Utc>, Option<u32>)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let kind = v["kind"].as_str().unwrap_or("");
    let ts = v["ts"]
        .as_str()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now);
    let details = &v["details"];
    let pid = details["pid"].as_u64().map(|p| p as u32);

    // Extract source IP from various event fields
    let ip = details["src_ip"]
        .as_str()
        .or_else(|| details["ip"].as_str())
        .or_else(|| {
            v["entities"].as_array().and_then(|arr| {
                arr.iter().find_map(|e| {
                    if e["type"].as_str() == Some("ip") {
                        e["value"].as_str()
                    } else {
                        None
                    }
                })
            })
        })
        .unwrap_or("")
        .to_string();

    if ip.is_empty() {
        return None;
    }

    let atom = match kind {
        "shell.command_exec" | "process.exec" => {
            let comm = details["comm"]
                .as_str()
                .or_else(|| details["command"].as_str())
                .unwrap_or("");
            Some(Atom::Exec {
                category: classify_exec(comm),
            })
        }
        "network.connection" | "network.outbound_connect" => {
            let port = details["dst_port"].as_u64().unwrap_or(0) as u16;
            Some(Atom::Connect {
                port_class: classify_port(port),
            })
        }
        "file.read_access" | "file.write_access" => {
            let path = details["path"].as_str().unwrap_or("");
            let sens = classify_file(path);
            if matches!(sens, FileSensitivity::Normal) {
                None // Skip boring file access
            } else {
                Some(Atom::FileAccess { sensitivity: sens })
            }
        }
        "auth.login_success" => Some(Atom::Login { success: true }),
        "auth.login_failure" => Some(Atom::Login { success: false }),
        "privilege.escalation" => Some(Atom::PrivEsc),
        _ => None,
    };

    atom.map(|a| (ip, a, ts, pid))
}

/// Parse an incident line for enrichment (higher-level events).
fn parse_incident(line: &str) -> Option<(String, Atom, DateTime<Utc>)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let title = v["title"].as_str().unwrap_or("").to_lowercase();
    let ts = v["ts"]
        .as_str()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now);

    // Extract IP from entities
    let ip = v["entities"]
        .as_array()
        .and_then(|arr| {
            arr.iter().find_map(|e| {
                if e["type"].as_str() == Some("ip") || e["type"].as_str() == Some("Ip") {
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

    // Map incident titles/evidence to atoms
    let atom = if title.contains("kill chain") {
        // Kill chain incidents from innerwarden-killchain service
        let pattern_str = v["evidence"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|e| e["pattern"].as_str())
            .unwrap_or("");
        let pattern = classify_kill_chain_pattern(pattern_str);
        Some(Atom::KillChain { pattern })
    } else if title.contains("brute force") || title.contains("credential stuffing") {
        Some(Atom::Login { success: false })
    } else if title.contains("privilege escalation") || title.contains("privesc") {
        Some(Atom::PrivEsc)
    } else if title.contains("download") && title.contains("exec") {
        Some(Atom::DownloadExec)
    } else {
        None
    };

    atom.map(|a| (ip, a, ts))
}

/// Main ingestion loop.
pub async fn run(data_dir: PathBuf, store: Arc<RwLock<DnaStore>>, min_sequence: usize) {
    let mut builder = SessionBuilder::new();
    let mut event_offset: u64 = 0;
    let mut incident_offset: u64 = 0;

    info!("ingestion loop started");

    loop {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let events_path = data_dir.join(format!("events-{today}.jsonl"));
        let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));

        // Read new events
        event_offset = read_new_lines(&events_path, event_offset, |line| {
            if let Some((ip, atom, ts, pid)) = parse_event(line) {
                builder.add_event(&ip, atom, ts, pid);
            }
        });

        // Read new incidents
        incident_offset = read_new_lines(&incidents_path, incident_offset, |line| {
            if let Some((ip, atom, ts)) = parse_incident(line) {
                builder.add_event(&ip, atom, ts, None);
            }
        });

        // Close stale sessions and fingerprint them
        let closed = builder.close_stale(Utc::now());
        if !closed.is_empty() {
            let mut store = store.write().await;
            for seq in closed {
                if seq.atoms.len() < min_sequence {
                    continue;
                }
                let mut dna = fingerprint::fingerprint(&seq);
                classifier::classify(&mut dna);

                let is_new = store.insert(dna.clone());
                if is_new {
                    info!(
                        hash = &dna.exact_hash[..12],
                        class = ?dna.classification,
                        ip = %seq.source_ip,
                        atoms = seq.atoms.len(),
                        "new threat DNA identified"
                    );
                } else {
                    debug!(
                        hash = &dna.exact_hash[..12],
                        ip = %seq.source_ip,
                        "known threat DNA seen again"
                    );
                }
            }
            // Persist after processing closed sessions
            if let Err(e) = store.save() {
                warn!(error = %e, "failed to persist DNA store");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

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
        // File hasn't grown (or was rotated — reset)
        if file_len < offset {
            return 0;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_exec() {
        let line = r#"{"kind":"shell.command_exec","ts":"2026-03-22T10:00:00Z","details":{"comm":"whoami","pid":1234,"src_ip":"1.2.3.4"}}"#;
        let (ip, atom, _, pid) = parse_event(line).unwrap();
        assert_eq!(ip, "1.2.3.4");
        assert!(matches!(
            atom,
            Atom::Exec {
                category: ExecCategory::Recon
            }
        ));
        assert_eq!(pid, Some(1234));
    }

    #[test]
    fn parse_event_connect() {
        let line = r#"{"kind":"network.connection","ts":"2026-03-22T10:00:00Z","details":{"dst_port":4444,"dst_ip":"5.6.7.8","src_ip":"1.2.3.4"}}"#;
        let (_, atom, _, _) = parse_event(line).unwrap();
        assert!(matches!(
            atom,
            Atom::Connect {
                port_class: PortClass::C2Common
            }
        ));
    }

    #[test]
    fn session_builder_closes_stale() {
        let mut builder = SessionBuilder::new();
        let old = Utc::now() - Duration::seconds(600);
        builder.add_event(
            "1.2.3.4",
            Atom::Exec {
                category: ExecCategory::Shell,
            },
            old,
            Some(1),
        );
        let closed = builder.close_stale(Utc::now());
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].source_ip, "1.2.3.4");
    }

    #[test]
    fn session_builder_keeps_active() {
        let mut builder = SessionBuilder::new();
        let recent = Utc::now();
        builder.add_event(
            "1.2.3.4",
            Atom::Exec {
                category: ExecCategory::Shell,
            },
            recent,
            None,
        );
        let closed = builder.close_stale(Utc::now());
        assert_eq!(closed.len(), 0);
    }
}
