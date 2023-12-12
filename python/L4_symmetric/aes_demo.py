from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import common.utils as utils

# ==================================================
#              AES CBC
# ==================================================
print("AES CBC:")

# CAVS 11.1
# Config info for aes_values
# AESVS MMT test data for CBC
# State : Encrypt and Decrypt
# Key Length : 128
# Generated on Fri Apr 22 15:11:33 2011
#[ENCRYPT]

COUNT = 1
KEY = '0700d603a1c514e46b6191ba430a3a0c'
IV = 'aad1583cd91365e3bb2f0c3430d065bb'
PLAINTEXT = '068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91'
CIPHERTEXT = 'c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00'

# Convert HEX strings to arrays of bytes
key_bytes = bytes.fromhex(KEY)
iv_bytes  = bytes.fromhex(IV)
plaintext_bytes  = bytes.fromhex(PLAINTEXT)

print("byte key[] = " + utils.MakeCArray(KEY))
print("byte iv[] = " + utils.MakeCArray(IV))
print("byte plaintext[] = " + utils.MakeCArray(PLAINTEXT))
print("byte cipher[] = " + utils.MakeCArray(CIPHERTEXT))

# ====  Encrypt plain text ====
# Create Cipher object
cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes))
# Create instance of <encryptor>
encryptor = cipher.encryptor()
# Encrypt the first block
ct1 = encryptor.update(plaintext_bytes[0:16])
# Encrypt the second block
ct2 = encryptor.update(plaintext_bytes[16:])
encryptor.finalize()
print(f'Cypher text : {ct1.hex() + ct2.hex()} ')

# Decrypt cipher text
cipher2 = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes))
# Create decryptor block
decryptor = cipher2.decryptor()
# Decrypt the first block
recovered_pt1 = decryptor.update(ct1)
# Decrypt the second block
recovered_pt2 = decryptor.update(ct2)
decryptor.finalize()
print(f'Decrypted text : {recovered_pt1.hex() + recovered_pt2.hex()} ')


# ==================================================
#              AES ECB
# ==================================================
print("AES ECB:")

# CAVS 11.1
# Config info for aes_values
# AESVS MMT test data for ECB
# State : Encrypt and Decrypt
# Key Length : 128
# Generated on Fri Apr 22 15:11:26 2011
#[ENCRYPT]

COUNT = 1
KEY = '7723d87d773a8bbfe1ae5b081235b566'
PLAINTEXT = '1b0a69b7bc534c16cecffae02cc5323190ceb413f1db3e9f0f79ba654c54b60e'
CIPHERTEXT = 'ad5b089515e7821087c61652dc477ab1f2cc6331a70dfc59c9ffb0c723c682f6'

key_bytes = bytes.fromhex(KEY)
plaintext_bytes  = bytes.fromhex(PLAINTEXT)

print("byte key[] = " + utils.MakeCArray(KEY))
print("byte plaintext[] = " + utils.MakeCArray(PLAINTEXT))
print("byte cipher[] = " + utils.MakeCArray(CIPHERTEXT))

# Encrypt plain text
cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
encryptor = cipher.encryptor()
ct1 = encryptor.update(plaintext_bytes)
encryptor.finalize()
print(f'Cypher text : {ct1.hex()} ')

# Decrypt cipher text
cipher2 = Cipher(algorithms.AES(key_bytes), modes.ECB())
decryptor = cipher2.decryptor()
recovered_pt1 = decryptor.update(ct1)
decryptor.finalize()
print(f'Decrypted text : {recovered_pt1.hex()} ')

print("completed")
