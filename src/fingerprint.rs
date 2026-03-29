//! Generates a stable hash ("DNA fingerprint") from a behavioral sequence.
//!
//! The fingerprint is order-preserving: [Shell, Recon, Download, Exec] produces
//! a different hash than [Download, Shell, Recon, Exec]. This captures the
//! *methodology* of the attacker, not just what tools they used.
//!
//! Two fingerprinting strategies:
//! - **Exact DNA**: SHA-256 of the full atom sequence (matches identical attacks)
//! - **Fuzzy DNA**: n-gram based hash that matches similar but not identical attacks

use sha2::{Digest, Sha256};

use crate::sequence::{Atom, BehaviorSequence};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A complete threat DNA fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDna {
    /// Exact hash of the full sequence
    pub exact_hash: String,
    /// Fuzzy hash (trigram-based) for similarity matching
    pub fuzzy_hash: String,
    /// Number of atoms in the sequence
    pub length: usize,
    /// The normalized atom sequence
    pub atoms: Vec<Atom>,
    /// Source IP that produced this DNA
    pub source_ip: String,
    /// When first observed
    pub first_seen: DateTime<Utc>,
    /// When last observed
    pub last_seen: DateTime<Utc>,
    /// How many times this exact DNA has been seen
    pub seen_count: u32,
    /// Threat classification (set by classifier)
    pub classification: Option<ThreatClass>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatClass {
    BruteForceAndExploit,
    Reconnaissance,
    DataExfiltration,
    CryptoMining,
    Botnet,
    RansomwarePrep,
    LateralMovement,
    Unknown,
}

/// Generate exact DNA hash from a behavior sequence.
pub fn exact_hash(seq: &BehaviorSequence) -> String {
    let mut hasher = Sha256::new();
    for atom in &seq.atoms {
        let token = atom_to_token(atom);
        hasher.update(token.as_bytes());
        hasher.update(b"|");
    }
    hex::encode(hasher.finalize())
}

/// Generate fuzzy DNA hash using trigrams.
/// Sequences with similar sub-patterns produce similar hashes.
pub fn fuzzy_hash(seq: &BehaviorSequence) -> String {
    let tokens: Vec<String> = seq.atoms.iter().map(atom_to_token).collect();

    if tokens.len() < 3 {
        // Too short for trigrams — just hash what we have
        let mut hasher = Sha256::new();
        for t in &tokens {
            hasher.update(t.as_bytes());
        }
        return hex::encode(hasher.finalize())[..16].to_string();
    }

    // Generate trigrams and sort them for order-independent similarity
    let mut trigrams: Vec<String> = tokens
        .windows(3)
        .map(|w| format!("{}:{}:{}", w[0], w[1], w[2]))
        .collect();
    trigrams.sort();
    trigrams.dedup();

    let mut hasher = Sha256::new();
    for tri in &trigrams {
        hasher.update(tri.as_bytes());
        hasher.update(b"\n");
    }

    hex::encode(hasher.finalize())[..16].to_string()
}

/// Calculate similarity between two fuzzy hashes (0.0 to 1.0).
/// Uses Jaccard index of trigram sets.
pub fn similarity(seq_a: &BehaviorSequence, seq_b: &BehaviorSequence) -> f64 {
    let trigrams_a = extract_trigrams(seq_a);
    let trigrams_b = extract_trigrams(seq_b);

    if trigrams_a.is_empty() && trigrams_b.is_empty() {
        return 1.0;
    }
    if trigrams_a.is_empty() || trigrams_b.is_empty() {
        return 0.0;
    }

    let intersection = trigrams_a.intersection(&trigrams_b).count();
    let union = trigrams_a.union(&trigrams_b).count();

    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

fn extract_trigrams(seq: &BehaviorSequence) -> std::collections::HashSet<String> {
    let tokens: Vec<String> = seq.atoms.iter().map(atom_to_token).collect();
    tokens
        .windows(3)
        .map(|w| format!("{}:{}:{}", w[0], w[1], w[2]))
        .collect()
}

/// Generate a ThreatDna from a behavior sequence.
pub fn fingerprint(seq: &BehaviorSequence) -> ThreatDna {
    ThreatDna {
        exact_hash: exact_hash(seq),
        fuzzy_hash: fuzzy_hash(seq),
        length: seq.atoms.len(),
        atoms: seq.atoms.clone(),
        source_ip: seq.source_ip.clone(),
        first_seen: seq.first_seen,
        last_seen: seq.last_seen,
        seen_count: 1,
        classification: None,
    }
}

/// Convert an atom to a stable string token for hashing.
fn atom_to_token(atom: &Atom) -> String {
    match atom {
        Atom::Exec { category } => format!("E:{category:?}"),
        Atom::Connect { port_class } => format!("C:{port_class:?}"),
        Atom::FileAccess { sensitivity } => format!("F:{sensitivity:?}"),
        Atom::PrivEsc => "P".to_string(),
        Atom::Login { success } => {
            if *success {
                "L:ok".to_string()
            } else {
                "L:fail".to_string()
            }
        }
        Atom::DownloadExec => "DX".to_string(),
        Atom::KillChain { pattern } => format!("KC:{pattern:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequence::*;
    use chrono::Utc;

    fn make_seq(atoms: Vec<Atom>) -> BehaviorSequence {
        BehaviorSequence {
            source_ip: "1.2.3.4".to_string(),
            atoms,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            pids: vec![1234],
        }
    }

    #[test]
    fn same_sequence_same_hash() {
        let seq1 = make_seq(vec![
            Atom::Exec {
                category: ExecCategory::Shell,
            },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
            Atom::FileAccess {
                sensitivity: FileSensitivity::Credentials,
            },
        ]);
        let seq2 = make_seq(vec![
            Atom::Exec {
                category: ExecCategory::Shell,
            },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
            Atom::FileAccess {
                sensitivity: FileSensitivity::Credentials,
            },
        ]);
        assert_eq!(exact_hash(&seq1), exact_hash(&seq2));
    }

    #[test]
    fn different_order_different_hash() {
        let seq1 = make_seq(vec![
            Atom::Exec {
                category: ExecCategory::Shell,
            },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
        ]);
        let seq2 = make_seq(vec![
            Atom::Exec {
                category: ExecCategory::Recon,
            },
            Atom::Exec {
                category: ExecCategory::Shell,
            },
        ]);
        assert_ne!(exact_hash(&seq1), exact_hash(&seq2));
    }

    #[test]
    fn similarity_identical_is_one() {
        let seq = make_seq(vec![
            Atom::Exec {
                category: ExecCategory::Shell,
            },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
            Atom::Exec {
                category: ExecCategory::Download,
            },
            Atom::DownloadExec,
        ]);
        assert!((similarity(&seq, &seq) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn similarity_different_is_low() {
        let seq1 = make_seq(vec![
            Atom::Exec {
                category: ExecCategory::Shell,
            },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
            Atom::Exec {
                category: ExecCategory::Download,
            },
            Atom::DownloadExec,
        ]);
        let seq2 = make_seq(vec![
            Atom::Connect {
                port_class: PortClass::Database,
            },
            Atom::FileAccess {
                sensitivity: FileSensitivity::Logs,
            },
            Atom::Exec {
                category: ExecCategory::Cleanup,
            },
            Atom::Connect {
                port_class: PortClass::HighPort,
            },
        ]);
        assert!(similarity(&seq1, &seq2) < 0.3);
    }

    #[test]
    fn fingerprint_creates_dna() {
        let seq = make_seq(vec![
            Atom::Login { success: true },
            Atom::Exec {
                category: ExecCategory::Shell,
            },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
        ]);
        let dna = fingerprint(&seq);
        assert_eq!(dna.length, 3);
        assert!(!dna.exact_hash.is_empty());
        assert!(!dna.fuzzy_hash.is_empty());
        assert_eq!(dna.seen_count, 1);
        assert!(dna.classification.is_none());
    }
}
