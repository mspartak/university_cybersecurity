# This script demonstrates simple (textbook) RSA implementation.

# Simple (textbook) RSA encryption/decryption.
def RsaExp(n, msg, e):
    ret = pow(msg, e, n)
    return ret

# RSA keys.
rsa_modulo      = 0xc7a1e7f94fc97f514264ee9570ee5f9cf3b49452d0789ac849f6b149ecbacc0b5abd1b478c0e4e5d5d7b28a19de61fe0fd7a382db7541a07da1cc2066a00bbbd
rsa_private_exp = 0x4587c4adf6f62d5bf60e057313545304ed74d5bc4a53d7452f4db6ce129fb4f519b9a7ca29de82945e52c4b74bfa9f984be7ca76b0a4817048dc9b6b71d5b2d9
rsa_public_exp  = 0x10001

print(f'\nRSA encrypt with public and decrypt with private exponent:')
msg_public = 0x1234567890

print(f'RSA message : {hex(msg_public)} ')
c = RsaExp(rsa_modulo, msg_public, rsa_public_exp)
print(f'RSA encrypted message : {hex(c)} ')

msg_2 = RsaExp(rsa_modulo, c, rsa_private_exp)
print(f'RSA decrypted message : {hex(msg_2)} ')


print(f'\nRSA encrypt with private and decrypt with public exponent:')
msg_private = 0x9876543210

print(f'RSA message : {hex(msg_private)} ')
c = RsaExp(rsa_modulo, msg_private, rsa_private_exp)
print(f'RSA encrypted message : {hex(c)} ')

msg_2 = RsaExp(rsa_modulo, c, rsa_public_exp)
print(f'RSA decrypted message : {hex(msg_2)} ')

print(f'\nRSA encrypt and decrypt with public exponent')

print(f'RSA message : {hex(msg_private)} ')
c = RsaExp(rsa_modulo, msg_private, rsa_public_exp)
print(f'RSA encrypted message using public exponent: {hex(c)} ')

msg_2 = RsaExp(rsa_modulo, c, rsa_public_exp)
print(f'RSA decrypted message using public exponent: {hex(msg_2)} ')

print(f'\nRSA encrypt and decrypt with private exponent')

print(f'RSA message : {hex(msg_private)} ')
c = RsaExp(rsa_modulo, msg_private, rsa_private_exp)
print(f'RSA encrypted message using private exponent: {hex(c)} ')

msg_2 = RsaExp(rsa_modulo, c, rsa_private_exp)
print(f'RSA decrypted message using private exponent: {hex(msg_2)} ')

print("completed")
