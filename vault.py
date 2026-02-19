
import secrets
import hmac
import hashlib
from typing import List, Tuple

class SecureVault:
    def __init__(self, n: int = 128, m: int = 128, initial_keys: List[int] = None):
        self.n = n
        self.m = m
        if initial_keys:
            self.keys = initial_keys
        else:
            self.keys = [secrets.randbits(m) for _ in range(n)]

    def get_keys(self) -> List[int]:
        return self.keys

    def generate_challenge(self, p: int) -> List[int]:
        if p > self.n:
            raise ValueError("Challenge size p cannot be greater than vault size n")
        
        # Select p distinct indices securely
        indices = set()
        while len(indices) < p:
            indices.add(secrets.randbelow(self.n))
        return list(indices)

    def compute_response(self, indices: List[int]) -> int:
        #Compute the XOR sum of keys at the given indices.
        response_key = 0
        for idx in indices:
            response_key ^= self.keys[idx]
        return response_key



    #vault rotation is a post-authentication system that allows us to prevent "next password prediction" attack by updating kets by XORing current vault h

    def rotate_vault(self, session_data: bytes):
        # Serialize current vault to bytes
        vault_bytes = b"".join(k.to_bytes((self.m + 7) // 8, byteorder='big') for k in self.keys)
        
        # Calculate HMAC
        h_obj = hmac.HMAC(session_data, vault_bytes, hashlib.sha256)
        h_digest = h_obj.digest() # 32 bytes (256 bits)

        # Update each key
        new_keys = []
        digest_int = int.from_bytes(h_digest, byteorder='big')
    
        
        for k in self.keys:

            mask = digest_int & ((1 << self.m) - 1)
            new_k = k ^ mask
            new_keys.append(new_k)
            digest_int = ((digest_int << 1) | (digest_int >> 255)) & ((1 << 256) - 1)

        self.keys = new_keys
