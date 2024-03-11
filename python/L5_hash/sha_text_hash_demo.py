from cryptography.hazmat.primitives import hashes
import common.utils as utils

# Define text to be hashed and make its encoding to UTF-8
message = "Let the cat out of the bag"
message_as_bytes = message.encode("utf-8")

# Calculate SHA-256
digest = hashes.Hash(hashes.SHA256())
digest.update(message_as_bytes)
my_hash = digest.finalize()

# Write results to binary file
utils.WriteBinaryFile("message.dat", message_as_bytes )
utils.WriteBinaryFile("message_hash.dat", my_hash )

print(f"my_hash: {my_hash.hex()}")
print("byte my_hash[] = " + utils.MakeCArray_Invert(my_hash.hex()) + ";")

# Lets try to change only one letter in the message and recalculate hash for it
message2 = "Let the fat out of the bag"
message2_as_bytes = message2.encode("utf-8")
digest = hashes.Hash(hashes.SHA256())
digest.update(message2_as_bytes)
my_hash2 = digest.finalize()

print(f"my_hash2: {my_hash2.hex()}")