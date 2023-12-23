from cryptography.hazmat.primitives.asymmetric import padding
import common.utils as utils

rsa_private_key_obj, rsa_public_key_obj = utils.RsaLoadKeys("DER", "demo")

encrypted_message =  utils.ReadBinaryFile('encrypted_message.dat')

print(f'RSA encrypted message loaded from file: {encrypted_message.hex()} ')

msg_decrypted = rsa_private_key_obj.decrypt(
    encrypted_message,
    padding.PKCS1v15()
    )

print(f'RSA decrypted message using private : {msg_decrypted} ')

print("completed")
