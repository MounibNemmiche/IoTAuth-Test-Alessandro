"""Main runner for Secure Vault attack simulation."""

import sys
import time
from auth_protocol import AuthSession, create_paired_system
from crypto_attacks import BruteForceAttack, VaultKeyRecoveryAttack
from protocol_attacks import ReplayAttack, MITMAttack


def run_legitimate_auth():
    device, server = create_paired_system(device_id="SENSOR_TEMP_001", n=128, m=128, p=8)
    session = AuthSession(device, server)
    start = time.time()
    success = session.execute()
    elapsed = time.time() - start

    print("PRELIMINARY: Legitimate Authentication")
    print(f"Device: {session.m1.device_id}, vault: n=128 m=128, p=8")
    print(f"Time: {elapsed*1000:.2f} ms, session key: {session.session_key.hex()[:32]}...")
    print(f"Result: {'SUCCESS' if success else 'FAILED'}")
    if not success:
        sys.exit(1)
    return success


def run_all_attacks():
    results = []
    results.append(BruteForceAttack(n=128, m=128, p=8).run(num_attempts=50_000))
    results.append(VaultKeyRecoveryAttack(n=16, m=32, p=4).run(num_sessions=50))
    results.append(ReplayAttack(n=128, m=128, p=8).run())
    results.append(MITMAttack(n=128, m=128, p=8).run())
    return results


def print_summary(results):
    names = {"brute_force": "Brute Force Key Guessing", "vault_key_recovery": "Vault Key Recovery (GF(2))",
             "replay": "Replay Attack", "mitm": "Man-in-the-Middle (MITM)"}
    types = {"brute_force": "Cryptographic", "vault_key_recovery": "Cryptographic",
             "replay": "Protocol", "mitm": "Protocol"}

    print(f"\nSUMMARY")
    for r in results:
        name = names.get(r["attack"], r["attack"])
        t = types.get(r["attack"], "?")
        status = "SECURE" if r["success"] else "BREACHED"
        print(f"  {name:<35} {t:<15} {status}")

    all_secure = all(r["success"] for r in results)
    print(f"\n{'PROTOCOL RESISTED ALL ATTACKS' if all_secure else 'VULNERABILITIES DETECTED'}")


def main():
    print("SECURE VAULT - SECURITY SIMULATION\n")
    run_legitimate_auth()
    results = run_all_attacks()
    print_summary(results)


if __name__ == "__main__":
    main()
