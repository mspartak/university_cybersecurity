import common.utils as utils

# Create string that represents the HEX value
MyKey = '7865f4a590ba23ff33552353aaf4d588'

MyKey1 = utils.MakeCArray(MyKey)
print(MyKey1)

MyKey2 = utils.MakeCArray_Invert(MyKey)
print(MyKey2)





