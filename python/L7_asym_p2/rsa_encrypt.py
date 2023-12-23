from cryptography.hazmat.primitives.asymmetric import padding
import common.utils as utils

# Load public key from file
_ , rsa_public_key_obj = utils.RsaLoadKeys("DER", "demo")

# Create message to be encrypted
message = "You have to pay 100 dollars to the account: 12131415"
print(f'RSA message to encrypt: {message} ')

# Convert this message to bytes
message_bytes = bytes(message, 'utf-8')

# Encrypt using RSA and padding PKCS1 V1.5
encrypted_message = rsa_public_key_obj.encrypt(
    message_bytes,
    padding.PKCS1v15()
    )

# Write encrypted message to file
utils.WriteBinaryFile('encrypted_message.dat', encrypted_message)

print(f'RSA encrypted message : {encrypted_message.hex()} ')

print("completed")
