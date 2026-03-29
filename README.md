# threat-dna

**Identify attackers by methodology, not IP.** Behavioral fingerprinting that persists across IP rotations, VPN changes, and proxy chains.

## The Problem

Attackers rotate IPs. Blocking an IP is temporary. But their *methodology* is stable — the order of reconnaissance steps, the tools they choose, the timing between actions.

## How it works

Threat DNA creates order-preserving hashes of behavioral sequences:

```
Attacker session:
  1. port_scan(22,80,443)
  2. ssh_brute_force(admin,root,test)
  3. ssh_login_success(root)
  4. download(/tmp/miner)
  5. execute(/tmp/miner)

DNA: sha256("port_scan→ssh_brute→ssh_success→download→execute") = 7a3f...
```

When the same attacker returns from a different IP, the DNA matches.

## Features

- **Exact DNA** — SHA-256 hash of behavior sequence (exact match across sessions)
- **Fuzzy DNA** — n-gram based similarity (catches slight variations)
- **Anomaly Detection** — learns "normal" per-process behavior profiles, flags deviations via cosine distance and z-scores
- **Attack Chain Analysis** — models multi-step attack sequences with temporal ordering
- **Classification** — categorizes threats by behavior pattern

## Install

```toml
[dependencies]
threat-dna = { git = "https://github.com/InnerWarden/threat-dna" }
```

## Modules

| Module | Purpose |
|--------|---------|
| `fingerprint` | Exact and fuzzy DNA hash computation |
| `anomaly` | Autoencoder-inspired behavior profiling with cosine distance |
| `attack_chain` | Multi-step attack sequence modeling |
| `sequence` | Behavior atom abstraction (the unit of DNA) |
| `classifier` | Threat classification by behavioral pattern |
| `store` | DNA persistence and lookup |

---

Part of the [InnerWarden](https://innerwarden.com) security ecosystem.
