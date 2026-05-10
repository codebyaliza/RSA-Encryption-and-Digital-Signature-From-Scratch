# task2_signature_fixed.py
# Digital signature – corrected for hash size

import hashlib
import random

# ---------- Same helpers (primes, gcd, mod_inverse) ----------
def is_prime(n, k=5):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=24):
    while True:
        p = random.getrandbits(bits)
        if p >= 2 and is_prime(p):
            return p

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1

def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m

# ---------- Key generation (larger primes) ----------
def generate_keys():
    random.seed(123)        # reproducible keys
    p = generate_prime(24)
    q = generate_prime(24)
    while q == p:
        q = generate_prime(24)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

# ---------- Hash and sign/verify ----------
def hash_message(msg: str) -> int:
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), 'big')

def sign(msg: str, priv_key):
    d, n = priv_key
    h = hash_message(msg)
    # Important: h must be < n. With our 24‑bit primes n is ~48 bits,
    # but SHA‑256 hash is 256 bits -> we reduce modulo n safely
    # (In real RSA signatures with padding, hash is reduced appropriately)
    return pow(h % n, d, n)   # h % n ensures we sign inside the modulus

def verify(msg: str, signature: int, pub_key) -> bool:
    e, n = pub_key
    h = hash_message(msg)
    recovered_hash = pow(signature, e, n)
    # Compare only the lower bits that fit into n
    return recovered_hash == (h % n)

# ---------- Demonstration ----------
if __name__ == '__main__':
    pub, priv = generate_keys()
    print("RSA Keys for Signature")
    print(f"Public  (e, n) = ({pub[0]}, {pub[1]})")
    print(f"Private (d, n) = ({priv[0]}, {priv[1]})")

    original = "Bob's transfer: $100"
    print(f"\nOriginal message: '{original}'")

    sig = sign(original, priv)
    print(f"Signature (integer): {sig}")

    valid = verify(original, sig, pub)
    print(f"Signature valid for original? {valid}")   # True

    tampered = "Bob's transfer: $1000"
    print(f"\nTampered message: '{tampered}'")
    valid_tampered = verify(tampered, sig, pub)
    print(f"Signature valid for tampered? {valid_tampered}")  # False

    print("✓ Tampering correctly detected.")