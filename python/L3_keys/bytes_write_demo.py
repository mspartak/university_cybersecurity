import common.utils as utils

file_name = "my_bytes.bin"

# Create string that represents the HEX value
MyKey = '7865f4a590ba23ff33552353aaf4d588'
# Convert to bytes
key_bytes = bytes.fromhex(MyKey)
# Write bytes to file
utils.WriteBinaryFile(file_name, key_bytes)




