"""Protocol-level attacks against the Secure Vault authentication system."""

import os
import secrets
from auth_protocol import (
    IoTDevice, IoTServer, AuthSession,
    M1, M2, M3, M4,
    aes_encrypt, create_paired_system, serialize_challenge,
)


class ReplayAttack:
    """Replay captured messages from a previous session."""

    def __init__(self, n: int = 128, m: int = 128, p: int = 8):
        self.n = n
        self.m = m
        self.p = p

    def run(self) -> dict:
        print(f"\nATTACK 3: Replay Attack")
        print(f"n={self.n}, m={self.m} bits, p={self.p}")

        device, server = create_paired_system(n=self.n, m=self.m, p=self.p)
        session = AuthSession(device, server)
        assert session.execute()

        captured_m1 = session.m1
        captured_m3 = session.m3
        print(f"Captured M1 (device_id={captured_m1.device_id}) and M3")

        session_data = os.urandom(32)
        device.rotate(session_data)
        server.rotate(captured_m1.device_id, session_data)

        new_m2 = server.process_request(captured_m1)
        if new_m2 is None:
            attack_failed = True
        else:
            m4_response = server.verify_and_respond(captured_m3)
            attack_failed = m4_response is None

        print(f"Replayed M3 to new session: server {'REJECTED' if attack_failed else 'ACCEPTED'}")
        print(f"Result: {'FAILED' if attack_failed else 'SUCCEEDED'}")

        return {"attack": "replay", "success": attack_failed}


class MITMAttack:
    """Man-in-the-Middle with three strategies."""

    def __init__(self, n: int = 128, m: int = 128, p: int = 8):
        self.n = n
        self.m = m
        self.p = p

    def run(self) -> dict:
        print(f"\nATTACK 4: Man-in-the-Middle (MITM)")
        print(f"n={self.n}, m={self.m} bits, p={self.p}")

        results = []

        # Strategy A: modify r1
        device, server = create_paired_system(n=self.n, m=self.m, p=self.p)
        m1 = device.create_request()
        m2 = server.process_request(m1)
        tampered_m2 = M2(C1=m2.C1, r1=os.urandom(16))
        m3 = device.respond_to_challenge(tampered_m2)
        blocked_a = server.verify_and_respond(m3) is None
        results.append(blocked_a)
        print(f"Strategy A (modify r1):    {'BLOCKED' if blocked_a else 'PASSED'}")

        # Strategy B: forge M3 with fake key
        device, server = create_paired_system(n=self.n, m=self.m, p=self.p)
        m1 = device.create_request()
        m2 = server.process_request(m1)
        fake_key = secrets.randbits(self.m)
        plaintext = m2.r1 + os.urandom(16) + serialize_challenge(list(range(self.p))) + os.urandom(16)
        forged_m3 = M3(ciphertext=aes_encrypt(fake_key, self.m, plaintext))
        blocked_b = server.verify_and_respond(forged_m3) is None
        results.append(blocked_b)
        print(f"Strategy B (forged M3):    {'BLOCKED' if blocked_b else 'PASSED'}")

        # Strategy C: bit-flipping
        device, server = create_paired_system(n=self.n, m=self.m, p=self.p)
        m1 = device.create_request()
        m2 = server.process_request(m1)
        m3 = device.respond_to_challenge(m2)
        ct = bytearray(m3.ciphertext)
        ct[20] ^= 0x01
        blocked_c = server.verify_and_respond(M3(ciphertext=bytes(ct))) is None
        results.append(blocked_c)
        print(f"Strategy C (bit-flipping): {'BLOCKED' if blocked_c else 'PASSED'}")

        all_blocked = all(results)
        print(f"Result: {'FAILED' if all_blocked else 'SUCCEEDED'}")

        return {"attack": "mitm", "all_blocked": all_blocked, "success": all_blocked}


if __name__ == "__main__":
    ReplayAttack(n=128, m=128, p=8).run()
    MITMAttack(n=128, m=128, p=8).run()
