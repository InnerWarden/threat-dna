//! Extracts behavioral sequences from raw events.
//!
//! A sequence is an ordered list of actions performed by the same session/process
//! tree. Example: SSH login → whoami → cat /etc/passwd → curl | sh → connect C2.
//!
//! We normalize actions into a small alphabet of "behavior atoms" so that
//! cosmetic differences (different filenames, IPs) don't change the fingerprint.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single normalized action in a behavioral sequence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Atom {
    /// Process execution
    Exec { category: ExecCategory },
    /// Network connection
    Connect { port_class: PortClass },
    /// File access
    FileAccess { sensitivity: FileSensitivity },
    /// Privilege change
    PrivEsc,
    /// Login event
    Login { success: bool },
    /// Download + execute pattern
    DownloadExec,
    /// Kill chain pattern detected/blocked by kernel eBPF
    KillChain { pattern: KillChainPattern },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KillChainPattern {
    ReverseShell,
    BindShell,
    CodeInject,
    ExploitShell,
    InjectShell,
    ExploitC2,
    FullExploit,
    DataExfil,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecCategory {
    Shell,       // bash, sh, zsh, fish, dash
    Recon,       // whoami, id, uname, hostname, ifconfig, ip, cat /etc/passwd
    Download,    // curl, wget, scp, ftp
    Compiler,    // gcc, cc, make, python, perl, ruby
    NetTool,     // nmap, nc, netcat, socat, ssh, telnet
    CryptoMiner, // xmrig, minerd, cpuminer
    Persistence, // crontab, at, systemctl
    Cleanup,     // rm, shred, history -c, unset HISTFILE
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PortClass {
    Ssh,      // 22
    Http,     // 80, 443, 8080, 8443
    Dns,      // 53
    Database, // 3306, 5432, 6379, 27017
    C2Common, // 4444, 4445, 1234, 5555, 6666, 7777, 8888, 9999
    HighPort, // > 10000
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileSensitivity {
    Credentials,  // /etc/shadow, /etc/passwd, .ssh/, .aws/, .env
    SystemConfig, // /etc/sudoers, /etc/crontab, /etc/hosts
    Logs,         // /var/log/*
    Tmp,          // /tmp, /dev/shm
    Normal,
}

/// A complete behavioral sequence for one session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSequence {
    /// Source IP that initiated the session
    pub source_ip: String,
    /// Ordered list of behavior atoms
    pub atoms: Vec<Atom>,
    /// When the sequence started
    pub first_seen: DateTime<Utc>,
    /// When the last action was observed
    pub last_seen: DateTime<Utc>,
    /// Process IDs involved
    pub pids: Vec<u32>,
}

/// Classify a command/binary name into an ExecCategory.
pub fn classify_exec(comm: &str) -> ExecCategory {
    let c = comm.to_lowercase();
    let name = c.rsplit('/').next().unwrap_or(&c);

    match name {
        "bash" | "sh" | "zsh" | "fish" | "dash" | "csh" | "tcsh" | "ash" => ExecCategory::Shell,
        "whoami" | "id" | "uname" | "hostname" | "ifconfig" | "ip" | "cat" | "ls" | "find"
        | "ps" | "netstat" | "ss" | "lsof" | "w" | "last" | "df" | "mount" | "env" | "printenv"
        | "getent" => ExecCategory::Recon,
        "curl" | "wget" | "scp" | "ftp" | "sftp" | "rsync" | "aria2c" => ExecCategory::Download,
        "gcc" | "cc" | "g++" | "make" | "python" | "python3" | "perl" | "ruby" | "node" | "go"
        | "rustc" => ExecCategory::Compiler,
        "nmap" | "nc" | "ncat" | "netcat" | "socat" | "ssh" | "telnet" | "masscan" | "hping3" => {
            ExecCategory::NetTool
        }
        "xmrig" | "minerd" | "cpuminer" | "ethminer" | "cgminer" | "bfgminer" | "cryptonight" => {
            ExecCategory::CryptoMiner
        }
        "crontab" | "at" | "systemctl" | "service" | "chkconfig" | "update-rc.d" => {
            ExecCategory::Persistence
        }
        "rm" | "shred" | "wipe" | "history" | "unset" => ExecCategory::Cleanup,
        _ => ExecCategory::Other,
    }
}

/// Classify a destination port into a PortClass.
pub fn classify_port(port: u16) -> PortClass {
    match port {
        22 => PortClass::Ssh,
        80 | 443 | 8080 | 8443 => PortClass::Http,
        53 => PortClass::Dns,
        3306 | 5432 | 6379 | 27017 => PortClass::Database,
        4444 | 4445 | 1234 | 5555 | 6666 | 7777 | 8888 | 9999 => PortClass::C2Common,
        p if p > 10000 => PortClass::HighPort,
        _ => PortClass::Other,
    }
}

/// Classify a file path into a sensitivity level.
pub fn classify_file(path: &str) -> FileSensitivity {
    let p = path.to_lowercase();
    if p.contains("/etc/shadow")
        || p.contains("/etc/passwd")
        || p.contains(".ssh/")
        || p.contains(".aws/")
        || p.contains(".env")
        || p.contains("credentials")
        || p.contains(".gnupg/")
    {
        FileSensitivity::Credentials
    } else if p.contains("/etc/sudoers")
        || p.contains("/etc/crontab")
        || p.contains("/etc/hosts")
        || p.contains("/etc/resolv.conf")
    {
        FileSensitivity::SystemConfig
    } else if p.contains("/var/log/") {
        FileSensitivity::Logs
    } else if p.starts_with("/tmp") || p.starts_with("/dev/shm") || p.starts_with("/var/tmp") {
        FileSensitivity::Tmp
    } else {
        FileSensitivity::Normal
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_exec_shells() {
        assert_eq!(classify_exec("bash"), ExecCategory::Shell);
        assert_eq!(classify_exec("/bin/sh"), ExecCategory::Shell);
        assert_eq!(classify_exec("zsh"), ExecCategory::Shell);
    }

    #[test]
    fn classify_exec_recon() {
        assert_eq!(classify_exec("whoami"), ExecCategory::Recon);
        assert_eq!(classify_exec("id"), ExecCategory::Recon);
        assert_eq!(classify_exec("cat"), ExecCategory::Recon);
    }

    #[test]
    fn classify_exec_miners() {
        assert_eq!(classify_exec("xmrig"), ExecCategory::CryptoMiner);
    }

    #[test]
    fn classify_port_known() {
        assert_eq!(classify_port(22), PortClass::Ssh);
        assert_eq!(classify_port(443), PortClass::Http);
        assert_eq!(classify_port(4444), PortClass::C2Common);
        assert_eq!(classify_port(3306), PortClass::Database);
        assert_eq!(classify_port(50000), PortClass::HighPort);
    }

    #[test]
    fn classify_file_sensitivity() {
        assert_eq!(classify_file("/etc/shadow"), FileSensitivity::Credentials);
        assert_eq!(
            classify_file("/home/user/.ssh/id_rsa"),
            FileSensitivity::Credentials
        );
        assert_eq!(classify_file("/etc/sudoers"), FileSensitivity::SystemConfig);
        assert_eq!(classify_file("/var/log/auth.log"), FileSensitivity::Logs);
        assert_eq!(classify_file("/tmp/payload"), FileSensitivity::Tmp);
        assert_eq!(classify_file("/usr/bin/something"), FileSensitivity::Normal);
    }
}
