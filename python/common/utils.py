# This file contains helper functions used in other programs.

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Function to write bytes to binary file
# Parameters:
#     filename - file name.
#     buffer - array of bytes
def WriteBinaryFile(filename, buffer):
    file_object = open(filename, 'wb')
    # Write file content
    file_object.write(buffer)
    file_object.close()

# Function to read bytes from binary file
# Parameters:
#     filename - file name.
# Returned value: array of bytes
def ReadBinaryFile(filename):
    file_object = open(filename, 'rb')
    # Read file content
    read_bytes = file_object.read()
    file_object.close()
    return read_bytes

# Function to generate C language compatible array.
# For example: input:  '7865f4a590ba23ff33552353aaf4d588'
#              output: {0x78,0x65,0xf4,0xa5,0x90,0xba,0x23,0xff,0x33,0x55,0x23,0x53,0xaa,0xf4,0xd5,0x88}
def MakeCArray(hex_string):
    if (len(hex_string) % 2):
        hex_string = '0' + hex_string
    a = bytearray.fromhex(hex_string)
    str = '{'
    for val in a:
        str = str + hex(val) + ','
    str = str[:-1] + '}'
    return str

# Function to generate C language compatible array.
# For example: input: '7865f4a590ba23ff33552353aaf4d588'
#              output: {0x88,0xd5,0xf4,0xaa,0x53,0x23,0x55,0x33,0xff,0x23,0xba,0x90,0xa5,0xf4,0x65,0x78}
def MakeCArray_Invert(hex_string):
    if (len(hex_string) % 2):
        hex_string = '0' + hex_string
    a = bytearray.fromhex(hex_string)
    str = ''
    for val in a:
        str = hex(val) + ',' + str
    str = '{' + str[:-1] + '}'
    return str

# This function generates RSA keys pair and stores to PEM and DER files.
# File format is as this:
#     <file_prefix>_private_key.<pem/der>
#     <file_prefix>_public_key.<pem/der>
# Public exponent is fixed and equal to 0x10001 (==65537)
# Parameters:
#        bitsize - size of key to be generated (bits)
#        file_prefix - file name prefix
# Returns RSA Private Key object and RSA Public Key object
def RsaGenerateKeys(bitsize, file_prefix):
    print("Generating new RSA keys...")
    # Generate private key
    rsa_private_key_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bitsize,
        backend=default_backend())

    # Get public key object from private key object
    rsa_public_key_obj  = rsa_private_key_obj.public_key()
    pub_numbers         = rsa_public_key_obj.public_numbers()

    # Store Private Key as PEM:
    pem = rsa_private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    file_object = open(f'{file_prefix}_private_key.pem', 'wb')
    file_object.write(pem)
    file_object.close()

    # Store Private Key as DER:
    der = rsa_private_key_obj.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    file_object = open(f'{file_prefix}_private_key.der', 'wb')
    file_object.write(der)
    file_object.close()

    # Store Public Key as PEM:
    pem = rsa_public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    file_object = open(f'{file_prefix}_public_key.pem', 'wb')
    file_object.write(pem)

    # Store Public Key as DER:
    der = rsa_public_key_obj.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    file_object = open(f'{file_prefix}_public_key.der', 'wb')
    file_object.write(der)

    pr_numbers = rsa_private_key_obj.private_numbers()

    rsa_private_exp = pr_numbers.d
    print(f'RSA private key : {hex(rsa_private_exp)} ')

    rsa_modulo = pub_numbers.n
    print(f'RSA modulo : {hex(rsa_modulo)} ')

    rsa_public_exp = pub_numbers.e
    print(f'RSA public exponent : {hex(rsa_public_exp)} ')

    return rsa_private_key_obj, rsa_public_key_obj

# Extracts RSA keys from PEM or DER file.
# Filenames: <file_prefix>_private_key.pem(der) or <file_prefix>_public_key.pem(der)
# Parameters:
#        filetype - EncodingType type is "PEM" or "DER"
#        file_prefix - file name prefix
# Returns RSA Private Key object and RSA Public Key object
def RsaLoadKeys(filetype, file_prefix):
    print("Loading existing RSA keys...")
    if ("PEM" == filetype):
        private_key_filename = f'{file_prefix}_private_key.pem'
        public_key_filename = f'{file_prefix}_public_key.pem'
        file_object = open(private_key_filename, 'rb')
        # Load private key in PEM format
        file_content = file_object.read()
        rsa_private_key_obj = serialization.load_pem_private_key(file_content, None)
        file_object.close()
        # Load public key in PEM format
        file_object = open(public_key_filename, 'rb')
        file_content = file_object.read()
        rsa_public_key_obj = serialization.load_pem_public_key(file_content, None)
        file_object.close()
    elif ("DER" == filetype):
        private_key_filename = f'{file_prefix}_private_key.der'
        public_key_filename = f'{file_prefix}_public_key.der'
        file_object = open(private_key_filename, 'rb')
        # Load private key in DER format
        file_content = file_object.read()
        rsa_private_key_obj = serialization.load_der_private_key(file_content, None)
        file_object.close()
        # Load public key in DER format
        file_object = open(public_key_filename, 'rb')
        file_content = file_object.read()
        rsa_public_key_obj = serialization.load_der_public_key(file_content, None)
        file_object.close()
    else:
        raise Exception("FileType parameter is wrong.")

    return rsa_private_key_obj, rsa_public_key_obj