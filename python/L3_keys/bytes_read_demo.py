import common.utils as utils

file_name = "my_bytes.bin"

# Read bytes from file
my_bytes = utils.ReadBinaryFile(file_name)
print(f"Read bytes: {my_bytes}")
print(f"Read bytes as hex: {my_bytes.hex()}")





