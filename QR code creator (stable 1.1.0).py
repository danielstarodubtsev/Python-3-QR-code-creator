# -*- coding: utf-8 -*-

'''
This program creates QR codes

Written by Daniel Starodubtsev (also known as DanTheMan), August 2021

References:
    https://habr.com/ru/post/172525/ (in Russian)
    https://en.wikipedia.org/wiki/QR_code
    https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction
'''

from functools import reduce
from copy import deepcopy
from PIL import Image, ImageDraw


def encode_data(data):
    '''
    Encodes data into binary (using utf-8 encoding)
    '''

    data = list(data.encode('utf-8')) # Get the bytes
    data = [bin(piece)[2:].zfill(8) for piece in data] # Transform into binary
    data = reduce(lambda x, y: x + y, data) # Concatenate into a single binary string
    
    return data


def get_data():
    data = input('Enter data to QR code >>> ')
    data = encode_data(data)

    return data


def help_on_correction_levels():
    print('''
Corection level  |  Maximum acceptable damage  |  Maximum bits to encode  |
-----------------|-----------------------------|--------------------------|
L (Low)          |  7%                         |  23648                   |
-----------------|-----------------------------|--------------------------|
M (Medium)       |  15%                        |  18672                   |
-----------------|-----------------------------|--------------------------|
Q (Quartile)     |  25%                        |  13328                   |
-----------------|-----------------------------|--------------------------|
H (High)         |  30%                        |  10208                   |
-----------------|-----------------------------|--------------------------|
''')

    correction_level = input("Now enter the correction level you've chosen (if you're not sure, medium is recommended) >>> ")
    return correction_level


def get_correction_level():
    '''
    Asking the user to choose correction level
    '''
    
    INVALID_CORRECTION_LEVEL_EXCEPTION = Exception('Invalid correction level value')
    
    correction_level = input('\nEnter correction level or type "help" to get more info about correction levels >>> ')

    if correction_level == 'help':
        correction_level = help_on_correction_levels()

    correction_level = correction_level.upper()

    if correction_level not in {'L', 'M', 'Q', 'H', 'LOW', 'MEDIUM', 'QUARTILE', 'HIGH'}:
        raise INVALID_CORRECTION_LEVEL_EXCEPTION

    return correction_level[0] # Will always return one of {'L', 'M', 'Q', 'H'}


def determine_version(data, correction_level):
    '''
    Determines optimal QR version (size) depending on the size of data
    '''
    
    L = {1: 152, 2: 272, 3: 440, 4: 640,
         5: 864, 6: 1088, 7: 1248, 8: 1552,
         9: 1856, 10: 2192, 11: 2592, 12: 2960,
         13: 3424, 14: 3688, 15: 4184, 16: 4712,
         17: 5176, 18: 5768, 19: 6360, 20: 6888,
         21: 7456, 22: 8048, 23: 8752, 24: 9392,
         25: 10208, 26: 10960, 27: 11744, 28: 12248,
         29: 13048, 30: 13880, 31: 14744, 32: 15640,
         33: 16568, 34: 17528, 35: 18448, 36: 19472,
         37: 20528, 38: 21616, 39: 22496, 40: 23648}

    M = {1: 128, 2: 224, 3: 352, 4: 512,
         5: 688, 6: 864, 7: 992, 8: 1232,
         9: 1456, 10: 1728, 11: 2032, 12: 2320,
         13: 2672, 14: 2920, 15: 3320, 16: 3624,
         17: 4056, 18: 4504, 19: 5016, 20: 5352,
         21: 5712, 22: 6256, 23: 6880, 24: 7312,
         25: 8000, 26: 8496, 27: 9024, 28: 9544,
         29: 10136, 30: 10984, 31: 11640, 32: 12328,
         33: 13048, 34: 13800, 35: 14496, 36: 15312,
         37: 15936, 38: 16816, 39: 17728, 40: 18672}

    Q = {1: 104, 2: 176, 3: 272, 4: 384,
         5: 496, 6: 608, 7: 704, 8: 880,
         9: 1056, 10: 1232, 11: 1440, 12: 1648,
         13: 1952, 14: 2088, 15: 2360, 16: 2600,
         17: 2936, 18: 3176, 19: 3560, 20: 3880,
         21: 4096, 22: 4544, 23: 4912, 24: 5312,
         25: 5744, 26: 6032, 27: 6464, 28: 6968,
         29: 7288, 30: 7880, 31: 8264, 32: 8920,
         33: 9368, 34: 9848, 35: 10288, 36: 10832,
         37: 11408, 38: 12016, 39: 12656, 40: 13328}

    H = {1: 72, 2: 128, 3: 208, 4: 288,
         5: 368, 6: 480, 7: 528, 8: 688,
         9: 800, 10: 976, 11: 1120, 12: 1264,
         13: 1440, 14: 1576, 15: 1784, 16: 2024,
         17: 2264, 18: 2504, 19: 2728, 20: 3080,
         21: 3248, 22: 2526, 23: 3712, 24: 4112,
         25: 4304, 26: 4768, 27: 5024, 28: 5288,
         29: 5608, 30: 5960, 31: 6344, 32: 6760,
         33: 7208, 34: 7688, 35: 7888, 36: 8432,
         37: 8768, 38: 9136, 39: 9776, 40: 10208}

    correction_level = eval(correction_level)

    items = correction_level.items()

    version = [item[0] for item in items if item[1] > len(data)][0]
    max_bits = correction_level[version]

    return version, max_bits


def add_service_fields(data, version, max_bits):
    '''
    Adding service field in the beginning of the data bits string
    Also returns updated version in case it's changed
    '''
    
    coding_method_field = '0100' # We're using bytes input mode
                                 # TODO: choose optimal mode, not always bytes

    if version < 10:
        data_amount_length = 8
    else:
        data_amount_length = 16

    byte_data_length = len(data) // 8

    data_amount_field = bin(byte_data_length)[2:].zfill(data_amount_length)

    new_data = coding_method_field + data_amount_field + data

    if len(new_data) <= max_bits:
        return new_data, version

    # It can happen that adding service fields makes data too big for chosen version
    # If so, we increase the version by 1 (that's always enough) and add the fields again

    version += 1

    if version < 10:
        data_amount_length = 8
    else:
        data_amount_length = 16

    data_amount_field = bin(byte_data_length)[2:].zfill(data_amount_length)

    new_data = coding_method_field + data_amount_field + data

    return new_data, version


def fill_data_until_required_length(data, max_bits):
    '''
    Fills the data with zeros until its length is a multiple of 8
    Then fills with alternating bytes 11101100 and 00010001 until length max_bits is reached
    '''

    need_zeros = (8 - (len(data) % 8)) % 8

    data += '0' * need_zeros

    counter = 0
    while len(data) < max_bits:
        if counter % 2 == 0:
            data += '11101100'
        else:
            data += '00010001'
        counter += 1

    return data


def split_data_into_blocks(data, correction_level, version):
    '''
    Splits data into a certain amount of equal pieces,
    which will later be used to create correction blocks
    '''
    
    L = {1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 2, 7: 2, 8: 2,
         9: 2, 10: 4, 11: 4, 12: 4, 13: 4, 14: 4, 15: 6, 16: 6,
         17: 6, 18: 6, 19: 7, 20: 8, 21: 8, 22: 9, 23: 9, 24: 10,
         25: 12, 26: 12, 27: 12, 28: 13, 29: 14, 30: 15, 31: 16, 32: 17,
         33: 18, 34: 19, 35: 19, 36: 20, 37: 21, 38: 22, 39: 24, 40: 25}

    M = {1: 1, 2: 1, 3: 1, 4: 2, 5: 2, 6: 4, 7: 4, 8: 4,
         9: 5, 10: 5, 11: 5, 12: 8, 13: 9, 14: 9, 15: 10, 16: 10,
         17: 11, 18: 13, 19: 14, 20: 16, 21: 17, 22: 17, 23: 18, 24: 20,
         25: 21, 26: 23, 27: 25, 28: 26, 29: 28, 30: 29, 31: 31, 32: 33,
         33: 35, 34: 37, 35: 37, 36: 40, 37: 43, 38: 45, 39: 47, 40: 49}

    Q = {1: 1, 2: 1, 3: 2, 4: 2, 5: 4, 6: 4, 7: 6, 8: 6,
         9: 8, 10: 8, 11: 8, 12: 10, 13: 12, 14: 16, 15: 12, 16: 17,
         17: 16, 18: 18, 19: 21, 20: 20, 21: 23, 22: 23, 23: 25, 24: 27,
         25: 29, 26: 34, 27: 34, 28: 35, 29: 38, 30: 40, 31: 43, 32: 45,
         33: 48, 34: 51, 35: 53, 36: 56, 37: 59, 38: 62, 39: 65, 40: 68}

    H = {1: 1, 2: 1, 3: 2, 4: 4, 5: 4, 6: 4, 7: 5, 8: 6,
         9: 8, 10: 8, 11: 11, 12: 11, 13: 16, 14: 16, 15: 18, 16: 16,
         17: 19, 18: 21, 19: 25, 20: 25, 21: 25, 22: 34, 23: 30, 24: 32,
         25: 35, 26: 37, 27: 40, 28: 42, 29: 45, 30: 48, 31: 51, 32: 54,
         33: 57, 34: 60, 35: 63, 36: 66, 37: 70, 38: 74, 39: 77, 40: 81}

    correction_level = eval(correction_level)
    blocks = correction_level[version] # Determine required number of blocks

    # Create a list (split_bytes) of blocks size
    # Example: data is 22 bytes long, then blocks will have sizes in bytes [4, 4, 4, 5, 5]
    total_bytes = len(data) // 8
    split_bytes = [total_bytes // blocks] * blocks
    index = -1
    while sum(split_bytes) < total_bytes:
        split_bytes[index] += 1
        index -= 1

    data_blocks = []
    for block in range(blocks):
        need_bits = split_bytes[block] * 8
        data_blocks.append(data[:need_bits])
        data = data[need_bits:]

    return data_blocks


def bit_string_into_decimal_bytes(string):
    '''
    Example: 001010110010101001010101 -> [43, 42, 85]
    '''

    assert len(string) % 8 == 0

    string = [string[i:i + 8] for i in range(0, len(string), 8)]
    string = [int(i, 2) for i in string]

    return string


def create_correction_block(block, correction_level, version):
    '''
    Creates a correction block for the block given
    Uses Reed–Solomon error correction algorithm
    '''
    
    L = {1: 7, 2: 10, 3: 15, 4: 20, 5: 26, 6: 18, 7: 20, 8: 24,
         9: 30, 10: 18, 11: 20, 12: 24, 13: 26, 14: 30, 15: 22, 16: 24,
         17: 28, 18: 30, 19: 28, 20: 28, 21: 28, 22: 28, 23: 30, 24: 30,
         25: 26, 26: 28, 27: 30, 28: 30, 29: 30, 30: 30, 31: 30, 32: 30,
         33: 30, 34: 30, 35: 30, 36: 30, 37: 30, 38: 30, 39: 30, 40: 30}

    M = {1: 10, 2: 16, 3: 26, 4: 18, 5: 24, 6: 16, 7: 18, 8: 22,
         9: 22, 10: 26, 11: 30, 12: 22, 13: 22, 14: 24, 15: 24, 16: 28,
         17: 28, 18: 26, 19: 26, 20: 26, 21: 26, 22: 28, 23: 28, 24: 28,
         25: 28, 26: 28, 27: 28, 28: 28, 29: 28, 30: 28, 31: 28, 32: 28,
         33: 28, 34: 28, 35: 28, 36: 28, 37: 28, 38: 28, 39: 28, 40: 28}

    Q = {1: 13, 2: 22, 3: 18, 4: 26, 5: 18, 6: 24, 7: 18, 8: 22,
         9: 20, 10: 24, 11: 28, 12: 26, 13: 24, 14: 20, 15: 30, 16: 24,
         17: 28, 18: 28, 19: 26, 20: 30, 21: 28, 22: 30, 23: 30, 24: 30,
         25: 30, 26: 30, 27: 30, 28: 30, 29: 30, 30: 30, 31: 30, 32: 30,
         33: 30, 34: 30, 35: 30, 36: 30, 37: 30, 38: 30, 39: 30, 40: 30}

    H = {1: 17, 2: 28, 3: 22, 4: 16, 5: 22, 6: 28, 7: 26, 8: 26,
         9: 24, 10: 28, 11: 24, 12: 28, 13: 22, 14: 24, 15: 24, 16: 30,
         17: 28, 18: 28, 19: 26, 20: 28, 21: 30, 22: 24, 23: 30, 24: 30,
         25: 30, 26: 30, 27: 30, 28: 30, 29: 30, 30: 30, 31: 30, 32: 30,
         33: 30, 34: 30, 35: 30, 36: 30, 37: 30, 38: 30, 39: 30, 40: 30}

    generating_polynoms = {
        7: [87, 229, 146, 149, 238, 102, 21],
        10: [251, 67, 46, 61, 118, 70, 64, 94, 32, 45],
        13: [74, 152, 176, 100, 86, 100, 106, 104, 130, 218, 206, 140, 78],
        15: [8, 183, 61, 91, 202, 37, 51, 58, 58, 237, 140, 124, 5, 99, 105],
        16: [120, 104, 107, 109, 102, 161, 76, 3, 91, 191, 147, 169, 182, 194, 225, 120],
        17: [43, 139, 206, 78, 43, 239, 123, 206, 214, 147, 24, 99, 150, 39, 243, 163, 136],
        18: [215, 234, 158, 94, 184, 97, 118, 170, 79, 187, 152, 148, 252, 179, 5, 98, 96, 153],
        20: [17, 60, 79, 50, 61, 163, 26, 187, 202, 180, 221, 225, 83, 239, 156, 164, 212, 212, 188, 190],
        22: [210, 171, 247, 242, 93, 230, 14, 109, 221, 53, 200, 74, 8, 172, 98, 80, 219, 134, 160, 105, 165, 231],
        24: [229, 121, 135, 48, 211, 117, 251, 126, 159, 180, 169, 152, 192, 226, 228, 218, 111, 0, 117, 232, 87, 96, 227, 21],
        26: [173, 125, 158, 2, 103, 182, 118, 17, 145, 201, 111, 28, 165, 53, 161, 21, 245, 142, 13, 102, 48, 227, 153, 145, 218, 70],
        28: [168, 223, 200, 104, 224, 234, 108, 180, 110, 190, 195, 147, 205, 27, 232, 201, 21, 43, 245, 87, 42, 195, 212, 119, 242, 37, 9, 123],
        30: [41, 173, 145, 152, 216, 31, 179, 182, 50, 48, 110, 86, 239, 96, 222, 125, 42, 173, 226, 193, 224, 130, 156, 37, 251, 216, 238, 40, 192, 180]
        }

    # If needed, Galua field can be easily computed. I used ready tables
    # The same can be said about the inverse galua field
    galua_field = {0: 1, 1: 2, 2: 4, 3: 8, 4: 16, 5: 32, 6: 64, 7: 128,
                   8: 29, 9: 58, 10: 116, 11: 232, 12: 205, 13: 135, 14: 19, 15: 38,
                   16: 76, 17: 152, 18: 45, 19: 90, 20: 180, 21: 117, 22: 234, 23: 201,
                   24: 143, 25: 3, 26: 6, 27: 12, 28: 24, 29: 48, 30: 96, 31: 192,
                   32: 157, 33: 39, 34: 78, 35: 156, 36: 37, 37: 74, 38: 148, 39: 53,
                   40: 106, 41: 212, 42: 181, 43: 119, 44: 238, 45: 193, 46: 159, 47: 35,
                   48: 70, 49: 140, 50: 5, 51: 10, 52: 20, 53: 40, 54: 80, 55: 160,
                   56: 93, 57: 186, 58: 105, 59: 210, 60: 185, 61: 111, 62: 222, 63: 161,
                   64: 95, 65: 190, 66: 97, 67: 194, 68: 153, 69: 47, 70: 94, 71: 188,
                   72: 101, 73: 202, 74: 137, 75: 15, 76: 30, 77: 60, 78: 120, 79: 240,
                   80: 253, 81: 231, 82: 211, 83: 187, 84: 107, 85: 214, 86: 177, 87: 127,
                   88: 254, 89: 225, 90: 223, 91: 163, 92: 91, 93: 182, 94: 113, 95: 226,
                   96: 217, 97: 175, 98: 67, 99: 134, 100: 17, 101: 34, 102: 68, 103: 136,
                   104: 13, 105: 26, 106: 52, 107: 104, 108: 208, 109: 189, 110: 103, 111: 206,
                   112: 129, 113: 31, 114: 62, 115: 124, 116: 248, 117: 237, 118: 199, 119: 147,
                   120: 59, 121: 118, 122: 236, 123: 197, 124: 151, 125: 51, 126: 102, 127: 204,
                   128: 133, 129: 23, 130: 46, 131: 92, 132: 184, 133: 109, 134: 218, 135: 169,
                   136: 79, 137: 158, 138: 33, 139: 66, 140: 132, 141: 21, 142: 42, 143: 84,
                   144: 168, 145: 77, 146: 154, 147: 41, 148: 82, 149: 164, 150: 85, 151: 170,
                   152: 73, 153: 146, 154: 57, 155: 114, 156: 228, 157: 213, 158: 183, 159: 115,
                   160: 230, 161: 209, 162: 191, 163: 99, 164: 198, 165: 145, 166: 63, 167: 126,
                   168: 252, 169: 229, 170: 215, 171: 179, 172: 123, 173: 246, 174: 241, 175: 255,
                   176: 227, 177: 219, 178: 171, 179: 75, 180: 150, 181: 49, 182: 98, 183: 196,
                   184: 149, 185: 55, 186: 110, 187: 220, 188: 165, 189: 87, 190: 174, 191: 65,
                   192: 130, 193: 25, 194: 50, 195: 100, 196: 200, 197: 141, 198: 7, 199: 14,
                   200: 28, 201: 56, 202: 112, 203: 224, 204: 221, 205: 167, 206: 83, 207: 166,
                   208: 81, 209: 162, 210: 89, 211: 178, 212: 121, 213: 242, 214: 249, 215: 239,
                   216: 195, 217: 155, 218: 43, 219: 86, 220: 172, 221: 69, 222: 138, 223: 9,
                   224: 18, 225: 36, 226: 72, 227: 144, 228: 61, 229: 122, 230: 244, 231: 245,
                   232: 247, 233: 243, 234: 251, 235: 235, 236: 203, 237: 139, 238: 11, 239: 22,
                   240: 44, 241: 88, 242: 176, 243: 125, 244: 250, 245: 233, 246: 207, 247: 131,
                   248: 27, 249: 54, 250: 108, 251: 216, 252: 173, 253: 71, 254: 142, 255: 1}

    inverse_galua_field = {0: 0, 1: 0, 2: 1, 3: 25, 4: 2, 5: 50, 6: 26, 7: 198,
                           8: 3, 9: 223, 10: 51, 11: 238, 12: 27, 13: 104, 14: 199, 15: 75,
                           16: 4, 17: 100, 18: 224, 19: 14, 20: 52, 21: 141, 22: 239, 23: 129,
                           24: 28, 25: 193, 26: 105, 27: 248, 28: 200, 29: 8, 30: 76, 31: 113,
                           32: 5, 33: 138, 34: 101, 35: 47, 36: 225, 37: 36, 38: 15, 39: 33,
                           40: 53, 41: 147, 42: 142, 43: 218, 44: 240, 45: 18, 46: 130, 47: 69,
                           48: 29, 49: 181, 50: 194, 51: 125, 52: 106, 53: 39, 54: 249, 55: 185,
                           56: 201, 57: 154, 58: 9, 59: 120, 60: 77, 61: 228, 62: 114, 63: 166,
                           64: 6, 65: 191, 66: 139, 67: 98, 68: 102, 69: 221, 70: 48, 71: 253,
                           72: 226, 73: 152, 74: 37, 75: 179, 76: 16, 77: 145, 78: 34, 79: 136,
                           80: 54, 81: 208, 82: 148, 83: 206, 84: 143, 85: 150, 86: 219, 87: 189,
                           88: 241, 89: 210, 90: 19, 91: 92, 92: 131, 93: 56, 94: 70, 95: 64,
                           96: 30, 97: 66, 98: 182, 99: 163, 100: 195, 101: 72, 102: 126, 103: 110,
                           104: 107, 105: 58, 106: 40, 107: 84, 108: 250, 109: 133, 110: 186, 111: 61,
                           112: 202, 113: 94, 114: 155, 115: 159, 116: 10, 117: 21, 118: 121, 119: 43,
                           120: 78, 121: 212, 122: 229, 123: 172, 124: 115, 125: 243, 126: 167, 127: 87,
                           128: 7, 129: 112, 130: 192, 131: 247, 132: 140, 133: 128, 134: 99, 135: 13,
                           136: 103, 137: 74, 138: 222, 139: 237, 140: 49, 141: 197, 142: 254, 143: 24,
                           144: 227, 145: 165, 146: 153, 147: 119, 148: 38, 149: 184, 150: 180, 151: 124,
                           152: 17, 153: 68, 154: 146, 155: 217, 156: 35, 157: 32, 158: 137, 159: 46,
                           160: 55, 161: 63, 162: 209, 163: 91, 164: 149, 165: 188, 166: 207, 167: 205,
                           168: 144, 169: 135, 170: 151, 171: 178, 172: 220, 173: 252, 174: 190, 175: 97,
                           176: 242, 177: 86, 178: 211, 179: 171, 180: 20, 181: 42, 182: 93, 183: 158,
                           184: 132, 185: 60, 186: 57, 187: 83, 188: 71, 189: 109, 190: 65, 191: 162,
                           192: 31, 193: 45, 194: 67, 195: 216, 196: 183, 197: 123, 198: 164, 199: 118,
                           200: 196, 201: 23, 202: 73, 203: 236, 204: 127, 205: 12, 206: 111, 207: 246,
                           208: 108, 209: 161, 210: 59, 211: 82, 212: 41, 213: 157, 214: 85, 215: 170,
                           216: 251, 217: 96, 218: 134, 219: 177, 220: 187, 221: 204, 222: 62, 223: 90,
                           224: 203, 225: 89, 226: 95, 227: 176, 228: 156, 229: 169, 230: 160, 231: 81,
                           232: 11, 233: 245, 234: 22, 235: 235, 236: 122, 237: 117, 238: 44, 239: 215,
                           240: 79, 241: 174, 242: 213, 243: 233, 244: 230, 245: 231, 246: 173, 247: 232,
                           248: 116, 249: 214, 250: 244, 251: 234, 252: 168, 253: 80, 254: 88, 255: 175}

    
    correction_level = eval(correction_level)

    number_of_correction_bytes = correction_level[version]
    polynom = generating_polynoms[number_of_correction_bytes]

    block = bit_string_into_decimal_bytes(block)

    if len(block) >= number_of_correction_bytes:
        prepared_array = block.copy()
    else:
        prepared_array = block.copy() + [0] * (number_of_correction_bytes - len(block))

    for _ in range(len(block)):
        A = prepared_array.pop(0)
        prepared_array.append(0)

        if A == 0:
            continue

        B = inverse_galua_field[A]

        for i in range(number_of_correction_bytes):
            prepared_array[i] ^= galua_field[(B + polynom[i]) % 255]

    prepared_array = prepared_array[:number_of_correction_bytes]
    prepared_array = [bin(i)[2:].zfill(8) for i in prepared_array]
    prepared_array = reduce(lambda x, y: x + y, prepared_array)

    return prepared_array


def combine_blocks(data_blocks, correction_blocks):
    '''
    Combines data and correction blocks together

    Result format (it is a string):
    <1st byte 1st data block><1st byte 2nd data block>...<1st byte n-th data block><2nd byte 1st data block>...
    <(m — 1)-th byte 1st data block>...<(m — 1)-th byte n-th data block><m-th byte k-th data block>...
    <m-th byte n-th data block><1st byte 1st correction block><1st byte 2nd correction block>...
    <1st byte n-th correction block><2nd byte 1st correction block>...
    <lst byte 1st correction block>...<lst byte n-th блока correction block>

    Here n — number of data blocks
         m — normal amount of bytes in a data block
         l — number of correction bytes
         k — number of normal data blocks minus number of bigger data blocks (those which are one byte longer).
    '''
    
    resulting_data = ''
    
    while any([len(block) for block in data_blocks]):
        for index, block in enumerate(data_blocks):
            if block:
                resulting_data += block[:8]
                data_blocks[index] = data_blocks[index][8:]

    while any([len(block) for block in correction_blocks]):
        for index, block in enumerate(correction_blocks):
            if block:
                resulting_data += block[:8]
                correction_blocks[index] = correction_blocks[index][8:]

    return resulting_data


def add_search_patterns(qr):
    '''
    Creates three squares in the corners of the QR
    '''
    
    qr = deepcopy(qr)
    size = len(qr[0])

    for x in range(8):
        for y in range(8):
            qr[y][x] = 0

    for x in range(size - 8, size):
        for y in range(8):
            qr[y][x] = 0
            qr[x][y] = 0

    for x in range(7):
        for y in {0, 6, size - 7, size - 1}:
            qr[y][x] = 1
            qr[x][y] = 1

    for x in range(2, 5):
        for y in {2, 3, 4, size - 3, size - 4, size - 5}:
            qr[y][x] = 1
            qr[x][y] = 1

    for x in {0, 6}:
        for y in range(size - 7, size):
            qr[y][x] = 1
            qr[x][y] = 1

    return qr


def add_sync_lanes(qr):
    '''
    Creates sync lanes (alternating black/white lines connecting the serach patterns)
    '''

    qr = deepcopy(qr)
    size = len(qr[0])

    for num in range(8, size - 8):
        if num % 2 == 0:
            qr[6][num] = 1
            qr[num][6] = 1
        else:
            qr[6][num] = 0
            qr[num][6] = 0

    return qr


def add_leveling_patterns(qr, version):
    '''
    Creates smaller squares in different places
    '''

    all_coords = {1: [],
              2: [18],
              3: [22],
              4: [26],
              5: [30],
              6: [34],
              7: [6, 22, 38],
              8: [6, 24, 42],
              9: [6, 26, 46],
              10: [6, 28, 50],
              11: [6, 30, 54],
              12: [6, 32, 58],
              13: [6, 34, 62],
              14: [6, 26, 46, 66],
              15: [6, 26, 48, 70],
              16: [6, 26, 50, 74],
              17: [6, 30, 54, 78],
              18: [6, 30, 56, 82],
              19: [6, 30, 58, 86],
              20: [6, 34, 62, 90],
              21: [6, 28, 50, 72, 94],
              22: [6, 26, 50, 74, 98],
              23: [6, 30, 54, 78, 102],
              24: [6, 28, 54, 80, 106],
              25: [6, 32, 58, 84, 110],
              26: [6, 30, 58, 86, 114],
              27: [6, 34, 62, 90, 118],
              28: [6, 26, 50, 74, 98, 122],
              29: [6, 30, 54, 78, 102, 126],
              30: [6, 26, 52, 78, 104, 130],
              31: [6, 30, 56, 82, 108, 134],
              32: [6, 34, 60, 86, 112, 138],
              33: [6, 30, 58, 86, 114, 142],
              34: [6, 34, 62, 90, 118, 146],
              35: [6, 30, 54, 78, 102, 126, 150],
              36: [6, 24, 50, 76, 102, 128, 154],
              37: [6, 28, 54, 80, 106, 132, 158],
              38: [6, 32, 58, 84, 110, 136, 162],
              39: [6, 26, 54, 82, 110, 138, 166],
              40: [6, 30, 58, 86, 114, 142, 170]}

    coords = all_coords[version]
    places = []
    
    for x in coords:
        for y in coords:
            places.append((x, y))

    if version >= 7:
        places.remove((coords[0], coords[0]))
        places.remove((coords[-1], coords[0]))
        places.remove((coords[0], coords[-1]))

    for place in places:
        x, y = place
        qr[y][x] = 1

        for i in range(-1, 2):
            for j in range(-1, 2):
                if i or j:
                    qr[y + i][x + j] = 0

        for i in range(-2, 3):
            for j in range(-2, 3):
                if abs(i) == 2 or abs(j) == 2:
                    qr[y + i][x + j] = 1

    return qr


def add_version_code(qr, version):
    '''
    Starting from version 7 there are special places near bottom-left and upper-right corners for the version code
    '''

    qr = deepcopy(qr)
    size = len(qr[0])

    if version <= 6:
        return qr

    version_codes = {7: '000010 011110 100110',
                     8: '010001 011100 111000',
                     9: '110111 011000 000100',
                     10: '101001 111110 000000',
                     11: '001111 111010 111100',
                     12: '001101 100100 011010',
                     13: '101011 100000 100110',
                     14: '110101 000110 100010',
                     15: '010011 000010 011110',
                     16: '011100 010001 011100',
                     17: '111010 010101 100000',
                     18: '100100 110011 100100',
                     19: '000010 110111 011000',
                     20: '000000 101001 111110',
                     21: '100110 101101 000010',
                     22: '111000 001011 000110',
                     23: '011110 001111 111010',
                     24: '001101 001101 100100',
                     25: '101011 001001 011000',
                     26: '110101 101111 011100',
                     27: '010011 101011 100000',
                     28: '010001 110101 000110',
                     29: '110111 110001 111010',
                     30: '101001 010111 111110',
                     31: '001111 010011 000010',
                     32: '101000 011000 101101',
                     33: '001110 011100 010001',
                     34: '010000 111010 010101',
                     35: '110110 111110 101001',
                     36: '110100 100000 001111',
                     37: '010010 100100 110011',
                     38: '001100 000010 110111',
                     39: '101010 000110 001011',
                     40: '111001 000100 010101'}

    code = version_codes[version].split()

    for x in range(6):
        for y in range(size - 11, size - 8):
            line_num = y - size + 11
            qr[y][x] = int(code[line_num][x])
            qr[x][y] = int(code[line_num][x])

    return qr


def add_mask_and_correction_level_codes(qr, version, correction_level):
    # Now I always use mask 0 ((X+Y) % 2), best mask choice will be implemented later

    qr = deepcopy(qr)
    size = len(qr[0])

    codes = {'L': '111011111000100',
             'M': '101010000010010',
             'Q': '011010101011111',
             'H': '001011010001001'}

    code = codes[correction_level]

    qr[8][0] = int(code[0])
    qr[8][1] = int(code[1])
    qr[8][2] = int(code[2])
    qr[8][3] = int(code[3])
    qr[8][4] = int(code[4])
    qr[8][5] = int(code[5])
    qr[8][7] = int(code[6])
    qr[8][8] = int(code[7])
    qr[7][8] = int(code[8])
    qr[5][8] = int(code[9])
    qr[4][8] = int(code[10])
    qr[3][8] = int(code[11])
    qr[2][8] = int(code[12])
    qr[1][8] = int(code[13])
    qr[0][8] = int(code[14])

    qr[size - 1][8] = int(code[0])
    qr[size - 2][8] = int(code[1])
    qr[size - 3][8] = int(code[2])
    qr[size - 4][8] = int(code[3])
    qr[size - 5][8] = int(code[4])
    qr[size - 6][8] = int(code[5])
    qr[size - 7][8] = int(code[6])
    qr[size - 8][8] = 1 # One certain square is always black

    qr[8][size - 8] = int(code[7])
    qr[8][size - 7] = int(code[8])
    qr[8][size - 6] = int(code[9])
    qr[8][size - 5] = int(code[10])
    qr[8][size - 4] = int(code[11])
    qr[8][size - 3] = int(code[12])
    qr[8][size - 2] = int(code[13])
    qr[8][size - 1] = int(code[14])

    return qr


def fill_qr_with_data(qr, data):
    '''
    Finally filling all space left with our data
    '''

    qr = deepcopy(qr)
    size = len(qr[0])

    x = size - 1
    y = size - 1
    going = 'up'
    last_movement = 'vertical'

    while any([None in i for i in qr]):
        # Fill square with a bit from data if it's empty
        if qr[y][x] is None:
            if data:
                bit = int(data[0])
                data = data[1:]
            else:
                bit = 0

            # Here a function to choose the best mask should be written
            mask = lambda x, y: (x + y) % 2
            
            if mask(x, y) == 0:
                bit = 1 - bit # Invert bit

            qr[y][x] = bit

        # Move to next square
        if x == 6: # Skip the vertical sync line
            x -= 1
        elif last_movement == 'vertical':
            x -= 1
            last_movement = 'horizontal'
        else:
            last_movement = 'vertical'
            
            if going == 'up':
                if y > 0:
                    x += 1
                    y -= 1
                else:
                    x -= 1
                    going = 'down'

            elif going == 'down':
                if y < size - 1:
                    x += 1
                    y += 1
                else:
                    x -= 1
                    going = 'up'
                    

    return qr


def create_QR_code(resulting_data, version, correction_level):
    '''
    Creates a 2D binary list which will be the QR
    0 is white, 1 is black, None - not yet determined
    '''

    # The size of the QR code depends only on its version and can be directly calculated
    size = 17 + version * 4

    qr = [[None] * size for _ in range(size)]

    qr = add_search_patterns(qr)
    qr = add_sync_lanes(qr)
    qr = add_leveling_patterns(qr, version)
    qr = add_version_code(qr, version)
    qr = add_mask_and_correction_level_codes(qr, version, correction_level)
    qr = fill_qr_with_data(qr, resulting_data)

    return qr


def save_QR_code(QR_code, res):
    size = len(QR_code[0])
    square_side = res / (size + 4)

    image = Image.new(mode='RGBA', size=(res, res))
    draw = ImageDraw.Draw(image)

    for x in range(size):
        for y in range(size):
            if QR_code[y][x] == 1:
                draw.rectangle(((x + 2) * square_side, (y + 2) * square_side, (x + 3) * square_side, (y + 3) * square_side),
                               fill=(0, 0, 0, 255))
            elif QR_code[y][x] == 0:
                draw.rectangle(((x + 2) * square_side, (y + 2) * square_side, (x + 3) * square_side, (y + 3) * square_side),
                               fill=(255, 255, 255, 255))

    draw.rectangle((0, 0, res, 2 * square_side), fill=(255, 255, 255, 255))
    draw.rectangle((0, res - 2 * square_side, res, res), fill=(255, 255, 255, 255))
    draw.rectangle((0, 0, 2 * square_side, res), fill=(255, 255, 255, 255))
    draw.rectangle((res - 2 * square_side, 0, res, res), fill=(255, 255, 255, 255))

    image.save('qr.png')

    
def main():
    '''
    Algorithm consists of 6 clear steps:
    
    1) Encoding the data
    2) Adding service fields and filling the data
    3) Splitting the data into blocks
    4) Creating correction bytes
    5) Combining blocks
    6) Placement of information on the QR code
    '''

    # Step 1 - Encoding the data
    data = get_data()
    correction_level = get_correction_level()
    version, max_bits = determine_version(data, correction_level)

    # Step 2 - Adding service fields and filling the data
    data, version = add_service_fields(data, version, max_bits)
    data = fill_data_until_required_length(data, max_bits)

    # Step 3 - Splitting the data into blocks
    data_blocks = split_data_into_blocks(data, correction_level, version)

    # Step 4 - Creating correction bytes
    correction_blocks = [create_correction_block(block, correction_level, version) for block in data_blocks]

    # Step 5 - Combining blocks
    resulting_data = combine_blocks(data_blocks, correction_blocks)

    # Step 6 - Placement of information on the QR code
    QR_code = create_QR_code(resulting_data, version, correction_level)
    save_QR_code(QR_code, 500)

    print('\nQR code succesfully created!')




if __name__ == '__main__':
    main()
