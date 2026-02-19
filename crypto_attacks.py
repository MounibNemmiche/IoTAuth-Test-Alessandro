"""Cryptographic attacks against the Secure Vault protocol."""

import os
import time
import secrets
from typing import List, Tuple
from vault import SecureVault
from auth_protocol import AuthSession, aes_decrypt, create_paired_system


class BruteForceAttack:
    """Brute force on the temporary key k1."""

    def __init__(self, n: int = 128, m: int = 128, p: int = 8):
        self.n = n
        self.m = m
        self.p = p

    def run(self, num_attempts: int = 100_000) -> dict:
        print(f"\nATTACK 1: Brute Force Key Guessing")
        print(f"n={self.n}, m={self.m} bits, p={self.p}, attempts={num_attempts:,}, key space=2^{self.m}")

        device, server = create_paired_system(n=self.n, m=self.m, p=self.p)
        session = AuthSession(device, server)
        assert session.execute()

        captured_r1 = session.m2.r1
        captured_m3_ct = session.m3.ciphertext

        successes = 0
        start_time = time.time()
        for i in range(num_attempts):
            guessed_key = secrets.randbits(self.m)
            pt = aes_decrypt(guessed_key, self.m, captured_m3_ct)
            if pt is not None and len(pt) >= 16 and pt[:16] == captured_r1:
                successes += 1
        elapsed = time.time() - start_time

        print(f"Keys tested: {num_attempts:,}, valid: {successes}, time: {elapsed:.3f}s")
        print(f"P(success): {num_attempts / (2 ** self.m):.2e}")
        print(f"Result: {'FAILED' if successes == 0 else 'SUCCEEDED'}")

        return {"attack": "brute_force", "attempts": num_attempts, "successes": successes,
                "time_seconds": elapsed, "success": successes == 0}


class VaultKeyRecoveryAttack:
    """Vault key recovery via GF(2) linear system."""

    def __init__(self, n: int = 16, m: int = 32, p: int = 4):
        self.n = n
        self.m = m
        self.p = p

    def _collect_no_rotation(self, num_sessions):
        initial_keys = [secrets.randbits(self.m) for _ in range(self.n)]
        vault = SecureVault(n=self.n, m=self.m, initial_keys=list(initial_keys))
        equations = []
        for _ in range(num_sessions):
            indices = vault.generate_challenge(self.p)
            equations.append((indices, vault.compute_response(indices)))
        return equations, initial_keys

    def _collect_with_rotation(self, num_sessions):
        initial_keys = [secrets.randbits(self.m) for _ in range(self.n)]
        vault = SecureVault(n=self.n, m=self.m, initial_keys=list(initial_keys))
        equations = []
        for _ in range(num_sessions):
            indices = vault.generate_challenge(self.p)
            equations.append((indices, vault.compute_response(indices)))
            vault.rotate_vault(os.urandom(32))
        return equations, initial_keys

    def _try_solve(self, equations, actual_keys):
        n = self.n
        recovered = [None] * n
        known = set()
        remaining = list(equations)
        progress = True
        while progress and len(known) < n:
            progress = False
            next_remaining = []
            for indices, xor_val in remaining:
                unknown = [i for i in indices if i not in known]
                if len(unknown) == 1:
                    idx = unknown[0]
                    known_xor = 0
                    for i in indices:
                        if i != idx and recovered[i] is not None:
                            known_xor ^= recovered[i]
                    recovered[idx] = xor_val ^ known_xor
                    known.add(idx)
                    progress = True
                elif len(unknown) > 0:
                    next_remaining.append((indices, xor_val))
            remaining = next_remaining
        correct = sum(1 for i in range(n) if recovered[i] is not None and recovered[i] == actual_keys[i])
        return correct

    def run(self, num_sessions: int = 50) -> dict:
        print(f"\nATTACK 2: Vault Key Recovery (GF(2))")
        print(f"n={self.n} keys, m={self.m} bits, p={self.p}, sessions={num_sessions}")

        eq_a, keys_a = self._collect_no_rotation(num_sessions)
        recovered_a = self._try_solve(eq_a, keys_a)
        print(f"Without rotation: {recovered_a}/{self.n} keys recovered")

        eq_b, keys_b = self._collect_with_rotation(num_sessions)
        recovered_b = self._try_solve(eq_b, keys_b)
        print(f"With rotation:    {recovered_b}/{self.n} keys recovered")
        print(f"Result: {'FAILED' if recovered_b == 0 else 'SUCCEEDED'}")

        return {"attack": "vault_key_recovery", "no_rotation_recovered": recovered_a,
                "with_rotation_recovered": recovered_b, "total": self.n, "success": recovered_b == 0}


if __name__ == "__main__":
    BruteForceAttack(n=128, m=128, p=8).run(num_attempts=50_000)
    VaultKeyRecoveryAttack(n=16, m=32, p=4).run(num_sessions=50)
