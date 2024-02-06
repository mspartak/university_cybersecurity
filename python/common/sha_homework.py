from cryptography.hazmat.primitives import hashes
import random

def create_password(variant):
    my_rand = random.randint(1,9999)
    my_password = f"{my_rand:04d}"

    my_password_ascii = [ord(n) for n in my_password]

    my_password_bytes = bytes(my_password_ascii)

    # Calculate SHA-256 using single update
    digest = hashes.Hash(hashes.SHA256())
    digest.update(my_password_bytes)
    my_hash = digest.finalize()
    print(f"{variant:02d} - {my_hash.hex()} - {my_password}")

for n in range(20):
    create_password(n+1)