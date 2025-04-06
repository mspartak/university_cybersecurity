# This script demonstrates how to verify signature of the message using RSA public key.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import common.utils as utils

# Load RSA public key
_ , rsa_public_key_obj = utils.RsaLoadKeys("DER", "rsakey")

# Load signature from binary file
signature = utils.ReadBinaryFile("signature.sign")

# Load message from binary file
message_bytes = utils.ReadBinaryFile("signed_message.txt")

try:
    # Verify Signature using RSA and PSS padding
    rsa_public_key_obj.verify(
        signature,
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is valid.")
except Exception as e:
    print(f"ERROR: Signature is invalid: {e}")

print("completed")
