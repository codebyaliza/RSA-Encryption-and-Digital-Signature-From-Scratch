# task2_signature.py
# Digital signature using RSA and SHA-256

import hashlib

# ---------- Same math helpers (mod inverse) ----------
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y

def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m

# ---------- RSA Key Generation (same fixed primes for clarity) ----------
def generate_keys():
    p, q = 61, 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

# ---------- Hash function (SHA-256) ----------
def hash_message(message: str) -> int:
    """Return SHA-256 hash of the message as an integer."""
    digest = hashlib.sha256(message.encode('utf-8')).digest()
    return int.from_bytes(digest, 'big')

# ---------- Sign and Verify ----------
def sign(message: str, priv_key: tuple) -> int:
    d, n = priv_key
    h = hash_message(message)
    # Signature = h^d mod n
    return pow(h, d, n)

def verify(message: str, signature: int, pub_key: tuple) -> bool:
    e, n = pub_key
    # Decrypt the signature: h' = signature^e mod n
    decrypted_hash = pow(signature, e, n)
    # Recompute original hash
    original_hash = hash_message(message)
    return decrypted_hash == original_hash

# ---------- Demonstration ----------
if __name__ == '__main__':
    pub, priv = generate_keys()
    print("RSA Keys for Signature")
    print(f"Public  (e, n) = ({pub[0]}, {pub[1]})")
    print(f"Private (d, n) = ({priv[0]}, {priv[1]})")

    original_msg = "Bob's transfer: $100"
    print(f"\nOriginal message: '{original_msg}'")

    # 1. Sign
    sig = sign(original_msg, priv)
    print(f"Signature (integer): {sig}")

    # 2. Verify original
    valid = verify(original_msg, sig, pub)
    print(f"Signature valid for original? {valid}")   # True

    # 3. Modify the message slightly
    tampered = "Bob's transfer: $1000"   # only one character changed
    print(f"\nTampered message: '{tampered}'")
    valid_tampered = verify(tampered, sig, pub)
    print(f"Signature valid for tampered? {valid_tampered}")   # False

    if not valid_tampered:
        print("Tampering detected – verification correctly failed.")
    else:
        print(" Error: verification should have failed.")