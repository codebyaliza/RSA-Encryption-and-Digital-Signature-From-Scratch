# RSA Encryption & Digital Signature (From Scratch)

A pure Python implementation of RSA key generation, encryption/decryption, and digital signatures using **only the standard library** – no external crypto packages.  
Built for a university Data Security lab assignment.

## 📁 Files

- `task1_rsa.py` – Simple RSA encryption & decryption (string ↔ integer)
- `task2_signature.py` – Digital signature with SHA‑256 and tampering detection

## 🚀 How to Run

1. Clone the repository  
   ```bash
   git clone https://github.com/Laptop-Zone-BY-JK/RSA-Encryption-and-Digital-Signature-From-Scratch.git
Run each task:

bash
python task1_rsa.py
python task2_signature.py
Both scripts use 24‑bit primes to keep numbers manageable while correctly encrypting full strings and 256‑bit hashes.

🔐 Features
No libraries – All math (Miller‑Rabin, extended GCD, modular inverse) is implemented manually.
Correct message size – Modulus is generated large enough to safely encrypt any short test string.
Tampering detection – Changing even one character causes signature verification to fail.
Reproducible results – Fixed random seeds are used for predictable key generation during testing.

⚠️ Disclaimer
This is an educational implementation – it uses small primes, no padding, and textbook RSA. Not suitable for production use. Real‑world RSA requires ≥2048‑bit keys and secure padding schemes (OAEP, PSS).

👤 Author
Sayeda Aliza Hashmi
COMSATS University Islamabad
Lab Assignment 4 – Information Security

