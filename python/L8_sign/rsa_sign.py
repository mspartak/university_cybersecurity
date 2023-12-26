# This script demonstrates how to sign a message using RSA private key.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import common.utils as utils

# Load RSA private key
rsa_private_key_obj, _ = utils.RsaLoadKeys("DER", "rsakey")

# Create message to be signed
message = "You have to pay 100 dollars to the account: 12131415"
print(f'Message to be signed: {message} ')

# Convert this message to bytes
message_bytes = bytes(message, 'utf-8')

# Store message to binary file.
utils.WriteBinaryFile("signed_message.txt", message_bytes)

# Sign using RSA and PSS padding
signature = rsa_private_key_obj.sign(
    message_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Write encrypted message to file
utils.WriteBinaryFile('signature.sign', signature)

print(f'Signature : {signature.hex()} ')

print("completed")
