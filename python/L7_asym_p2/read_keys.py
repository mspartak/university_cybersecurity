# This script just reads DER / PEM files and extract private and public keys and their parameters.
import common.utils as utils

rsa_private_key_obj, rsa_public_key_obj = utils.RsaLoadKeys("DER", "demo")

key_size = rsa_private_key_obj.key_size
private_key = rsa_private_key_obj.private_numbers().d
modulus = rsa_public_key_obj.public_numbers().n
exponent = rsa_public_key_obj.public_numbers().e

print(f'RSA key size: {key_size} ')
print(f'RSA modulus: {hex(modulus)} ')
print(f'RSA public exponent: {hex(exponent)} ')
print(f'RSA private key: {hex(private_key)} ')


print("completed")
