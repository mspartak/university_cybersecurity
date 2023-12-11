# This file contains helper functions used in other programs.

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
