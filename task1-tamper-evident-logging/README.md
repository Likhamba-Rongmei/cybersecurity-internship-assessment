# Task 1 — Tamper-Evident Logging System

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Hashing](https://img.shields.io/badge/Technique-SHA--256-orange?style=flat-square)
![Security](https://img.shields.io/badge/Focus-Log%20Integrity-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=flat-square)

---

##  Overview

This module uses cryptographic hash chaining to make a logging system that is tamper-proof.
Every log entry is connected to the one before it, creating a secure chain where any change is instantly visible.

The system shows how real-world applications make sure that logs can't be changed without leaving behind proof.

---

##  Objective

- Prevent silent modification of logs  
- Detect deletion of entries  
- Detect reordering of entries  
- Identify the exact point of tampering  

---

##  Core Concept — Hash Chaining

Each log entry contains:

- `prev_hash` → hash of previous entry  
- `entry_hash` → hash of current entry  


 If any entry is modified:
- Its hash changes  
- Chain verification fails  
- All subsequent entries are flagged  

---

##  Implementation Details

| Component | Description |
|----------|------------|
| `compute_hash()` | Generates SHA-256 hash of a log entry |
| `add_log()` | Adds new entry linked to previous hash |
| `verify_logs()` | Checks integrity, order, and chain linkage |
| `simulate_tamper()` | Modifies entry to simulate attack |
| `simulate_delete()` | Removes entry to simulate deletion |
| `simulate_reorder()` | Swaps entries to simulate reordering |

---

##  Detection Capabilities

| Attack Type | Detection Method |
|------------|-----------------|
| Modification | Hash mismatch |
| Deletion | Missing ID sequence |
| Reordering | Non-sequential IDs |
| Chain break | `prev_hash` mismatch |

---

##  Limitations

While hash chaining provides strong tamper detection, it has some inherent limitations:

- **Last Entry Vulnerability**  
  Modification to the most recent log entry may go undetected if no subsequent entry exists to validate it.

- **Chain Reconstruction Attack**  
  An attacker with full access can recompute hashes for all entries after tampering, rebuilding a valid-looking chain.

- **No External Trust Anchor**  
  The system relies entirely on internal verification without external validation.

- **Single File Storage**  
  Storing logs locally makes them vulnerable if the system itself is compromised.

---

##  Possible Improvements

To make the system more secure and closer to real-world implementations:

- **Hash Witness / External Anchoring**  
  Periodically store hashes in an external trusted system (e.g., remote server or blockchain)

- **Write-Once Storage (WORM)**  
  Use append-only or immutable storage to prevent overwriting logs

- **Digital Signatures**  
  Sign log entries using private keys to prevent unauthorized recomputation

- **Remote Logging Systems**  
  Send logs to centralized platforms (e.g., SIEM tools like Splunk, ELK)

---

## Project Structure

```text
task1-tamper-evident-logging/
│
├── README.md        # Documentation
└── logger.py        # Core implementation
```
> Note: The log file is generated dynamically.
---

##  How to Run

```bash
cd task1-tamper-evident-logging
python logger.py
```
---
