//! Classifies threat DNA into known attack patterns.
//!
//! Uses pattern matching on the atom sequence to identify the attacker's
//! objective: brute force, recon, exfiltration, crypto mining, etc.

use crate::fingerprint::{ThreatClass, ThreatDna};
use crate::sequence::*;

/// Classify a ThreatDna based on its atom sequence.
pub fn classify(dna: &mut ThreatDna) {
    dna.classification = Some(classify_atoms(&dna.atoms));
}

/// Determine the threat class from an atom sequence.
fn classify_atoms(atoms: &[Atom]) -> ThreatClass {
    let has = |pred: &dyn Fn(&Atom) -> bool| atoms.iter().any(pred);
    let count = |pred: &dyn Fn(&Atom) -> bool| atoms.iter().filter(|a| pred(a)).count();

    // Kill chain: any kernel-level kill chain detection dominates classification
    if has(&|a| matches!(a, Atom::KillChain { .. })) {
        return ThreatClass::BruteForceAndExploit;
    }

    // Crypto mining: miner execution
    if has(&|a| {
        matches!(
            a,
            Atom::Exec {
                category: ExecCategory::CryptoMiner
            }
        )
    }) {
        return ThreatClass::CryptoMining;
    }

    // Download + execute pattern with C2 connection
    if has(&|a| matches!(a, Atom::DownloadExec))
        && has(&|a| {
            matches!(
                a,
                Atom::Connect {
                    port_class: PortClass::C2Common
                }
            )
        })
    {
        return ThreatClass::BruteForceAndExploit;
    }

    // Lateral movement: internal SSH + recon
    if has(&|a| {
        matches!(
            a,
            Atom::Connect {
                port_class: PortClass::Ssh
            }
        )
    }) && has(&|a| {
        matches!(
            a,
            Atom::Exec {
                category: ExecCategory::Recon
            }
        )
    }) && count(&|a| {
        matches!(
            a,
            Atom::Connect {
                port_class: PortClass::Ssh
            }
        )
    }) >= 2
    {
        return ThreatClass::LateralMovement;
    }

    // Data exfiltration: credential access + outbound connection
    if has(&|a| {
        matches!(
            a,
            Atom::FileAccess {
                sensitivity: FileSensitivity::Credentials
            }
        )
    }) && has(&|a| {
        matches!(
            a,
            Atom::Connect {
                port_class: PortClass::Http | PortClass::HighPort | PortClass::Dns
            }
        )
    }) {
        return ThreatClass::DataExfiltration;
    }

    // Ransomware prep: cleanup + persistence
    if has(&|a| {
        matches!(
            a,
            Atom::Exec {
                category: ExecCategory::Cleanup
            }
        )
    }) && has(&|a| {
        matches!(
            a,
            Atom::Exec {
                category: ExecCategory::Persistence
            }
        )
    }) {
        return ThreatClass::RansomwarePrep;
    }

    // Botnet: login + download + C2 connection
    if has(&|a| matches!(a, Atom::Login { success: true }))
        && has(&|a| {
            matches!(
                a,
                Atom::Exec {
                    category: ExecCategory::Download
                }
            )
        })
        && has(&|a| {
            matches!(
                a,
                Atom::Connect {
                    port_class: PortClass::C2Common | PortClass::HighPort
                }
            )
        })
    {
        return ThreatClass::Botnet;
    }

    // Brute force: multiple failed logins
    if count(&|a| matches!(a, Atom::Login { success: false })) >= 3 {
        return ThreatClass::BruteForceAndExploit;
    }

    // Pure recon: mostly recon commands
    let recon_count = count(&|a| {
        matches!(
            a,
            Atom::Exec {
                category: ExecCategory::Recon
            }
        )
    });
    if recon_count >= 3 && recon_count as f64 / atoms.len() as f64 > 0.5 {
        return ThreatClass::Reconnaissance;
    }

    ThreatClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_crypto_mining() {
        let atoms = vec![
            Atom::Login { success: true },
            Atom::Exec {
                category: ExecCategory::Download,
            },
            Atom::Exec {
                category: ExecCategory::CryptoMiner,
            },
        ];
        assert_eq!(classify_atoms(&atoms), ThreatClass::CryptoMining);
    }

    #[test]
    fn classifies_lateral_movement() {
        let atoms = vec![
            Atom::Login { success: true },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
            Atom::Connect {
                port_class: PortClass::Ssh,
            },
            Atom::Connect {
                port_class: PortClass::Ssh,
            },
            Atom::Connect {
                port_class: PortClass::Ssh,
            },
        ];
        assert_eq!(classify_atoms(&atoms), ThreatClass::LateralMovement);
    }

    #[test]
    fn classifies_data_exfiltration() {
        let atoms = vec![
            Atom::Login { success: true },
            Atom::FileAccess {
                sensitivity: FileSensitivity::Credentials,
            },
            Atom::Connect {
                port_class: PortClass::Http,
            },
        ];
        assert_eq!(classify_atoms(&atoms), ThreatClass::DataExfiltration);
    }

    #[test]
    fn classifies_recon() {
        let atoms = vec![
            Atom::Exec {
                category: ExecCategory::Recon,
            },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
            Atom::Exec {
                category: ExecCategory::Recon,
            },
        ];
        assert_eq!(classify_atoms(&atoms), ThreatClass::Reconnaissance);
    }

    #[test]
    fn classifies_brute_force() {
        let atoms = vec![
            Atom::Login { success: false },
            Atom::Login { success: false },
            Atom::Login { success: false },
            Atom::Login { success: true },
        ];
        assert_eq!(classify_atoms(&atoms), ThreatClass::BruteForceAndExploit);
    }

    #[test]
    fn classifies_botnet() {
        let atoms = vec![
            Atom::Login { success: true },
            Atom::Exec {
                category: ExecCategory::Download,
            },
            Atom::Connect {
                port_class: PortClass::C2Common,
            },
        ];
        assert_eq!(classify_atoms(&atoms), ThreatClass::Botnet);
    }

    #[test]
    fn unknown_when_no_pattern() {
        let atoms = vec![Atom::Exec {
            category: ExecCategory::Other,
        }];
        assert_eq!(classify_atoms(&atoms), ThreatClass::Unknown);
    }
}
