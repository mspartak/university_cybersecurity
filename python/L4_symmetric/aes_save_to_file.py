from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import common.utils as utils

# ==================================================
#              AES ECB
# ==================================================
print("AES ECB:")

KEY = '7865f4a590ba23ff33552353aaf4d588'
PLAINTEXT = "Better late than never.........."

key_bytes = bytes.fromhex(KEY)
plaintext_bytes  = PLAINTEXT.encode("utf-8")

print("byte key[] = " + utils.MakeCArray(KEY))

# Encrypt plain text
cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
encryptor = cipher.encryptor()
ct1 = encryptor.update(plaintext_bytes)
encryptor.finalize()
print(f'Cypher text : {ct1.hex()} ')

utils.WriteBinaryFile("cipher.dat", ct1)
utils.WriteBinaryFile("key_truncated.dat", key_bytes[:15])

# Decrypt cipher text
cipher2 = Cipher(algorithms.AES(key_bytes), modes.ECB())
decryptor = cipher2.decryptor()
recovered_pt1 = decryptor.update(ct1)
decryptor.finalize()
print(f'Decrypted text : {recovered_pt1.decode("utf-8")} ')

print("completed")
