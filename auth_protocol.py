"""3-way mutual authentication protocol based on Secure Vaults."""

import os
import secrets
import struct
from dataclasses import dataclass, field
from typing import Optional, Tuple, List, Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from vault import SecureVault


def _derive_aes_key(raw_key: int, m: int) -> bytes:
    key_bytes = raw_key.to_bytes((m + 7) // 8, byteorder='big')
    if len(key_bytes) >= 32:
        return key_bytes[:32]
    elif len(key_bytes) >= 16:
        return key_bytes[:16]
    else:
        return key_bytes.ljust(16, b'\x00')


def aes_encrypt(key_int: int, m: int, plaintext: bytes) -> bytes:
    aes_key = _derive_aes_key(key_int, m)
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv + ct


def aes_decrypt(key_int: int, m: int, ciphertext: bytes) -> Optional[bytes]:
    aes_key = _derive_aes_key(key_int, m)
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    try:
        padded = dec.update(ct) + dec.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception:
        return None


@dataclass
class M1:
    device_id: str
    session_id: bytes = field(default_factory=lambda: os.urandom(16))

@dataclass
class M2:
    C1: List[int]
    r1: bytes

@dataclass
class M3:
    ciphertext: bytes

@dataclass
class M4:
    ciphertext: bytes


def serialize_challenge(indices: List[int]) -> bytes:
    return struct.pack(f'!H{"H" * len(indices)}', len(indices), *indices)


def deserialize_challenge(data: bytes) -> Tuple[List[int], bytes]:
    count = struct.unpack('!H', data[:2])[0]
    indices = list(struct.unpack(f'!{"H" * count}', data[2:2 + count * 2]))
    return indices, data[2 + count * 2:]


class IoTDevice:
    def __init__(self, device_id: str, vault: SecureVault, p: int = 8):
        self.device_id = device_id
        self.vault = vault
        self.p = p
        self._session_id: Optional[bytes] = None
        self._r1: Optional[bytes] = None
        self._t1: Optional[bytes] = None
        self._r2: Optional[bytes] = None
        self._C2: Optional[List[int]] = None
        self._k2: Optional[int] = None
        self._session_key: Optional[bytes] = None

    def create_request(self) -> M1:
        self._session_id = os.urandom(16)
        return M1(device_id=self.device_id, session_id=self._session_id)

    def respond_to_challenge(self, m2: M2) -> M3:
        k1 = self.vault.compute_response(m2.C1)
        self._r1 = m2.r1
        self._t1 = os.urandom(16)
        self._C2 = self.vault.generate_challenge(self.p)
        self._r2 = os.urandom(16)
        self._k2 = self.vault.compute_response(self._C2)
        plaintext = m2.r1 + self._t1 + serialize_challenge(self._C2) + self._r2
        ct = aes_encrypt(k1, self.vault.m, plaintext)
        return M3(ciphertext=ct)

    def verify_server(self, m4: M4) -> bool:
        if self._k2 is None or self._r2 is None:
            return False
        pt = aes_decrypt(self._k2, self.vault.m, m4.ciphertext)
        if pt is None:
            return False
        if pt[:16] != self._r2:
            return False
        self._session_key = self._t1
        return True

    def get_session_key(self) -> Optional[bytes]:
        return self._session_key

    def rotate(self, session_data: bytes):
        self.vault.rotate_vault(session_data)


class IoTServer:
    def __init__(self, p: int = 8):
        self.p = p
        self.device_vaults: Dict[str, SecureVault] = {}
        self._current_device_id: Optional[str] = None
        self._C1: Optional[List[int]] = None
        self._r1: Optional[bytes] = None
        self._k1: Optional[int] = None

    def register_device(self, device_id: str, vault: SecureVault):
        self.device_vaults[device_id] = vault

    def process_request(self, m1: M1) -> Optional[M2]:
        if m1.device_id not in self.device_vaults:
            return None
        self._current_device_id = m1.device_id
        vault = self.device_vaults[m1.device_id]
        self._C1 = vault.generate_challenge(self.p)
        self._r1 = os.urandom(16)
        self._k1 = vault.compute_response(self._C1)
        return M2(C1=self._C1, r1=self._r1)

    def verify_and_respond(self, m3: M3) -> Optional[M4]:
        if self._k1 is None or self._r1 is None or self._current_device_id is None:
            return None
        vault = self.device_vaults[self._current_device_id]
        pt = aes_decrypt(self._k1, vault.m, m3.ciphertext)
        if pt is None:
            return None
        if pt[:16] != self._r1:
            return None
        t1 = pt[16:32]
        C2, remaining = deserialize_challenge(pt[32:])
        r2 = remaining[:16]
        k2 = vault.compute_response(C2)
        t2 = os.urandom(16)
        ct = aes_encrypt(k2, vault.m, r2 + t2)
        return M4(ciphertext=ct)

    def rotate(self, device_id: str, session_data: bytes):
        if device_id in self.device_vaults:
            self.device_vaults[device_id].rotate_vault(session_data)


class AuthSession:
    def __init__(self, device: IoTDevice, server: IoTServer):
        self.device = device
        self.server = server
        self.success = False
        self.session_key: Optional[bytes] = None
        self.m1: Optional[M1] = None
        self.m2: Optional[M2] = None
        self.m3: Optional[M3] = None
        self.m4: Optional[M4] = None

    def execute(self) -> bool:
        self.m1 = self.device.create_request()
        self.m2 = self.server.process_request(self.m1)
        if self.m2 is None:
            return False
        self.m3 = self.device.respond_to_challenge(self.m2)
        self.m4 = self.server.verify_and_respond(self.m3)
        if self.m4 is None:
            return False
        self.success = self.device.verify_server(self.m4)
        if self.success:
            self.session_key = self.device.get_session_key()
        return self.success


def create_paired_system(device_id: str = "DEVICE_001",
                         n: int = 128, m: int = 128, p: int = 8):
    initial_keys = [secrets.randbits(m) for _ in range(n)]
    device_vault = SecureVault(n=n, m=m, initial_keys=list(initial_keys))
    server_vault = SecureVault(n=n, m=m, initial_keys=list(initial_keys))
    device = IoTDevice(device_id=device_id, vault=device_vault, p=p)
    server = IoTServer(p=p)
    server.register_device(device_id, server_vault)
    return device, server
