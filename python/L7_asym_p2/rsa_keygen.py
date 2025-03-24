# This script to generate RSA keys pair and store to files.

import common.utils as utils

# Call function from utilities module to generate RSA keys pair with given bit size
# and store to DER and PEM files.
rsa_key_bitsize = 1024
utils.RsaGenerateKeys(rsa_key_bitsize, "demo")

print("completed")
