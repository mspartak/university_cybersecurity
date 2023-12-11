import common.utils as utils
import random

# Randomize PRNG
random.seed(27)

# Key Size 128 bits
BitSize = 128
CharsInKey = BitSize // 4 # HEX characters in key

# Generate random Key
MyKey = random.randint(0, 2 ** BitSize - 1)

# Convert to HEX with leading zeros
MyKey = f"{MyKey:0{CharsInKey}X}"

print(f"MyKey = {MyKey}")

MyKey1 = utils.MakeCArray_Invert(MyKey)
print(MyKey1)








