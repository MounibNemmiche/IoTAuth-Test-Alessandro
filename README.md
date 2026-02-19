# Secure Vault — IoT Authentication Protocol & Security Simulation

## Overview

This project implements a **lightweight vault-based mutual authentication protocol** designed for constrained IoT devices. It then runs a suite of cryptographic and protocol-level attacks against it, demonstrating that the protocol is resistant to all of them.

## How the Protocol Works

### The Secure Vault (`vault.py`)

A Secure Vault stores **n secret keys**, each **m bits** long. Both the IoT device and the server hold an identical copy of the vault.

- **Challenge/Response**: A challenge is a set of `p` randomly chosen key indices. The response is the **XOR** of the keys at those indices — this serves as a temporary shared secret.
- **Vault Rotation**: After every authenticated session, all keys are updated by XORing them with a mask derived from **HMAC-SHA256**. This ensures that even if an attacker observes past sessions, they cannot predict future keys.

### 3-Way Mutual Authentication (`auth_protocol.py`)

The device and server authenticate each other through a 4-message exchange:

| Message | Direction         | Content                                                                 |
|---------|-------------------|-------------------------------------------------------------------------|
| **M1**  | Device → Server   | Device ID + session ID                                                  |
| **M2**  | Server → Device   | Challenge C1 (random indices) + nonce r1                                |
| **M3**  | Device → Server   | AES-CBC encrypted: r1 + token t1 + counter-challenge C2 + nonce r2     |
| **M4**  | Server → Device   | AES-CBC encrypted: r2 + token t2                                       |

- The **device** proves it knows the vault by correctly encrypting M3 with key k1 (derived from challenge C1).
- The **server** proves it knows the vault by correctly encrypting M4 with key k2 (derived from challenge C2).
- A **session key** is established for further communication.

Neither side ever transmits the vault keys directly.

## Attacks Simulated

### Cryptographic Attacks (`crypto_attacks.py`)

| Attack | Description | Expected Result |
|--------|-------------|-----------------|
| **Brute Force Key Guessing** | Tries 50,000 random 128-bit keys to decrypt a captured M3 message. The key space is 2¹²⁸, so the probability of success is ~1.47 × 10⁻³⁴. | FAILED (protocol is SECURE) |
| **Vault Key Recovery (GF(2))** | Attempts to solve a system of XOR-based linear equations to recover individual vault keys from observed challenge/response pairs. Tested with and without vault rotation. | FAILED (protocol is SECURE) |

### Protocol-Level Attacks (`protocol_attacks.py`)

| Attack | Description | Expected Result |
|--------|-------------|-----------------|
| **Replay Attack** | Captures messages from a legitimate session, then replays old M3 after vault rotation occurs. The server rejects it because the keys have changed. | FAILED (protocol is SECURE) |
| **Man-in-the-Middle (MITM)** | Three strategies: **(A)** Tamper with nonce r1 — server detects mismatch. **(B)** Forge M3 with a random key — AES decryption fails. **(C)** Flip a bit in the ciphertext — PKCS7 padding validation fails. | FAILED (protocol is SECURE) |

## Project Structure

```
├── vault.py              # Secure Vault implementation (key storage, challenge/response, rotation)
├── auth_protocol.py      # 3-way mutual authentication protocol (IoTDevice, IoTServer, AuthSession)
├── crypto_attacks.py     # Brute force and GF(2) key recovery attacks
├── protocol_attacks.py   # Replay and MITM attacks
├── run_simulation.py     # Main entry point — runs authentication + all attacks
├── SIMULATION_REPORT.md  # Detailed simulation report
└── README.md             # This file
```

## Requirements

- **Python 3.10+**
- **cryptography** library (for AES-CBC encryption/decryption)

## Installation & Usage

1. Install dependencies:
   ```bash
   pip install cryptography
   ```

2. Run the simulation:
   ```bash
   python run_simulation.py
   ```

## Expected Output

```
SECURE VAULT - SECURITY SIMULATION

PRELIMINARY: Legitimate Authentication
Device: SENSOR_TEMP_001, vault: n=128 m=128, p=8
Result: SUCCESS

ATTACK 1: Brute Force Key Guessing        → FAILED
ATTACK 2: Vault Key Recovery (GF(2))      → FAILED
ATTACK 3: Replay Attack                   → FAILED
ATTACK 4: Man-in-the-Middle (MITM)        → FAILED

SUMMARY
  Brute Force Key Guessing            Cryptographic   SECURE
  Vault Key Recovery (GF(2))          Cryptographic   SECURE
  Replay Attack                       Protocol        SECURE
  Man-in-the-Middle (MITM)            Protocol        SECURE

PROTOCOL RESISTED ALL ATTACKS
```

## Key Security Properties

- **Mutual authentication**: Both device and server prove knowledge of the shared vault.
- **Forward secrecy via rotation**: Vault keys change after each session, invalidating past observations.
- **Replay resistance**: Stale messages are rejected because the underlying keys have rotated.
- **Tamper detection**: AES-CBC with PKCS7 padding detects any modification of ciphertext.
- **Brute force infeasibility**: 128-bit keys make exhaustive search computationally impossible.
