# This script to convert test vectors represented in NIST KAT test vectors to C language representation.

import utils

COUNT = 2
KEY = '7a70cc6b261eeccb05c57117d5763197'
IV = 'bb7b9667fbd76d5ee204828769a341b1'
PLAINTEXT = '823cbaae3760c85512a3c83fd60bb54b7cfc739b295b63e05ef435d86e19fd15368c89ff08a0f21ce89a728ffb5d75df'
CIPHERTEXT = 'f5c49aae8a026bf05e525a12ab7e195eea8a1b71a8d32a5113aa8974858f2cfc0339805003a0cb1a7be19f376d4604eb'

c_key = utils.MakeCArray(KEY)
print(f"key ... {c_key};")
c_iv = utils.MakeCArray(IV)
print(f"iv ... {c_iv};")
c_pt = utils.MakeCArray(PLAINTEXT)
print(f"plaintext ... {c_pt};")
c_ct = utils.MakeCArray(CIPHERTEXT)
print(f"ciphertext ... {c_ct};")
