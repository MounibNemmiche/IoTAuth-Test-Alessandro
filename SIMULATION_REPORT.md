# Secure Vault Authentication — Simulation Report

**Reference paper**: *Authentication of IoT Device and IoT Server Using Secure Vaults* — T. Shah, University of Texas at Dallas

**Simulation parameters**: n=128 vault keys, m=128-bit key size, p=8 challenge indices, AES-128-CBC encryption.

---

## 1. Legitimate Authentication

The 3-way handshake (M1→M2→M3→M4) completes successfully in **~1.5 ms**, establishing a shared 128-bit session key. This confirms correctness of the protocol implementation before attack testing.

| Metric | Value |
|--------|-------|
| Vault size (n) | 128 keys |
| Key length (m) | 128 bits |
| Challenge size (p) | 8 indices |
| Handshake time | ~1.5 ms |
| Session key length | 128 bits |

---

## 2. Cryptographic Attacks

### 2.1 Brute Force Key Guessing

The attacker intercepts M2 (containing challenge C1 and nonce r1) and M3 (ciphertext). The goal is to guess the temporary key k1 = K[c1] ⊕ K[c2] ⊕ ... ⊕ K[c8] to decrypt M3 and recover r1.

| Metric | Value |
|--------|-------|
| Key space | 2^128 ≈ 3.4 × 10^38 |
| Keys tested | 50,000 |
| Valid keys found | 0 |
| Time elapsed | ~0.3 s |
| P(success) per attempt | 2.94 × 10^-39 |
| P(success) over 50K attempts | 1.47 × 10^-34 |

**Finding**: With a 128-bit key space, even 10^18 attempts per second for 10^9 years would only cover ~3.15 × 10^34 keys — less than 0.00001% of the space. The brute force attack is computationally infeasible.

### 2.2 Vault Key Recovery (GF(2) Linear System)

The attacker eavesdrops on multiple sessions and collects equations of the form: k_xor = K[c1] ⊕ K[c2] ⊕ ... ⊕ K[cp]. Each equation is linear over GF(2). The attacker builds a system of equations and attempts to solve for individual vault keys.

**Test parameters**: n=16 keys, m=32 bits, p=4 (reduced for simulation feasibility).

| Scenario | Sessions | Keys Recovered | Vault Compromised? |
|----------|----------|----------------|-------------------|
| **Without rotation** | 50 | 0/16 (0%) | No — underdetermined system |
| **With rotation** | 50 | 0/16 (0%) | No — inconsistent equations |

**Finding**: Even without rotation, recovering keys requires solving an underdetermined system (each equation has p=4 unknowns out of n=16). With vault rotation (HMAC-based key update after each session), the vault keys change between sessions, making the collected equations refer to different key sets — the system becomes inconsistent and has no solution.

---

## 3. Protocol Attacks

### 3.1 Replay Attack

The attacker captures a complete valid session (M1, M2, M3, M4) and replays M1 and M3 to the server in a new session.

| Step | What happens |
|------|-------------|
| Attacker sends captured M1 | Server accepts (device ID is valid) |
| Server generates new M2 | New challenge C1' ≠ C1, new nonce r1' ≠ r1 |
| Attacker sends captured M3 | Server computes k1' = XOR(K'[C1']), decrypts M3 → garbage |
| Server verification | **FAILS** — r1' not found in decrypted data |

**Finding**: The replay attack fails for two independent reasons:
1. The server generates a fresh random challenge C1' on every session, so k1' ≠ k1 and the old M3 cannot be decrypted correctly.
2. The vault has been rotated after the previous session, so K' ≠ K, adding a second layer of protection.

### 3.2 Man-in-the-Middle (MITM)

The attacker intercepts communication and attempts three strategies:

| Strategy | Description | Server Response |
|----------|-------------|-----------------|
| **A — Modify r1** | Attacker changes r1 in M2 before forwarding to device | **REJECTED** — device encrypts modified r1 in M3, server finds r1 mismatch |
| **B — Forge M3** | Attacker creates M3 with a fabricated encryption key | **REJECTED** — server decrypts with real k1, gets invalid padding/garbage |
| **C — Bit-flipping** | Attacker flips one bit in M3 ciphertext | **REJECTED** — AES-CBC produces corrupted plaintext with invalid PKCS7 padding |

**Finding**: All three strategies fail because the attacker cannot produce valid AES-CBC ciphertext without knowledge of the vault keys. The protocol provides:
- **Confidentiality**: AES-CBC encryption with XOR-composite keys derived from the vault.
- **Integrity**: PKCS7 padding validation detects any ciphertext tampering.
- **Freshness**: Random nonces (r1, r2) tie each message to a specific session.

---

## 4. Security Summary

| Attack | Type | Result |
|--------|------|--------|
| Brute Force | Cryptographic | **SECURE** |
| Vault Key Recovery | Cryptographic | **SECURE** |
| Replay | Protocol | **SECURE** |
| MITM | Protocol | **SECURE** |

### Why each attack fails

- **Brute Force**: The temporary key k1 is 128 bits long. The key space (2^128 ≈ 3.4 × 10^38) is too large to search — even testing 10^18 keys per second would take billions of years.

- **Vault Key Recovery**: The attacker collects XOR equations from eavesdropped sessions, but the vault is rotated (via HMAC) after each session. This means every session uses a different set of keys, so equations from different sessions are inconsistent and cannot be solved together.

- **Replay Attack**: The server generates a fresh random challenge C1' at each session. The replayed M3 was encrypted with the old key k1 (from old C1), but the server tries to decrypt it with k1' (from new C1'). Since k1' ≠ k1, decryption produces garbage and r1 does not match.

- **MITM**: Without knowledge of the vault keys, the attacker cannot produce valid AES-CBC ciphertext. Modifying r1 causes a mismatch at verification, forging M3 with a wrong key produces invalid decryption, and flipping bits in the ciphertext corrupts the PKCS7 padding.

## 5. Conclusions

The Secure Vault authentication protocol demonstrates robustness against both cryptographic and protocol-level attacks. The security relies on four pillars:

1. **Exponential key space** — 2^128 possible temporary keys per challenge.
2. **Multi-key XOR composition** — The encryption key is derived from p=8 vault keys, not a single shared secret.
3. **Post-session vault rotation** — HMAC-based key update ensures that compromising one session does not help with future sessions.
4. **Challenge-response freshness** — Random nonces and random challenge indices prevent replay and pre-computation attacks.

The simulation confirms that an attacker with full network visibility (eavesdropping on all messages) cannot authenticate as a legitimate device or server without physical access to the Secure Vault.
