from Crypto.Cipher import AES
from Crypto import Random
import base64

def decrypt(key, value, block_segments=False):
    # The base64 library fails if value is Unicode. Luckily, base64 is ASCII-safe.
    value = value.encode('utf-8')  # Convert to bytes
    # We add back the padding ("=") here so that the decode won't fail.
    value = base64.b64decode(value + b'=' * (4 - len(value) % 4), b'-_')
    iv, value = value[:AES.block_size], value[AES.block_size:]
    if block_segments:
        # Python uses 8-bit segments by default for legacy reasons. In order to support
        # languages that encrypt using 128-bit segments, without having to use data with
        # a length divisible by 16, we need to pad and truncate the values.
        remainder = len(value) % 16
        padded_value = value + b'\0' * (16 - remainder) if remainder else value
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        # Return the decrypted string with the padding removed.
        return cipher.decrypt(padded_value)[:len(value)]
    return AES.new(key, AES.MODE_CFB, iv).decrypt(value)

# def encrypt(key, value, block_segments=False):
#     iv = Random.new().read(AES.block_size)
#     value = value.encode('utf-8')  # Convert to bytes
#     if block_segments:
#         # See comment in decrypt for information.
#         remainder = len(value) % 16
#         padded_value = value + b'\0' * (16 - remainder) if remainder else value
#         cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
#         value = cipher.encrypt(padded_value)[:len(value)]
#     else:
#         value = AES.new(key, AES.MODE_CFB, iv).encrypt(value)
#     # The returned value has its padding stripped to avoid query string issues.
#     return base64.b64encode(iv + value, b'-_').rstrip(b'=').decode('utf-8')

# def decrypt(key, value, block_segments=False):
#     # The base64 library fails if value is Unicode. Luckily, base64 is ASCII-safe.
#     value = value.encode('utf-8')
#     # We add back the padding ("=") here so that the decode won't fail.
#     value = base64.b64decode(value + b'=' * (4 - len(value) % 4), b'-_')
#     iv, value = value[:AES.block_size], value[AES.block_size:]
#     if block_segments:
#         # Python uses 8-bit segments by default for legacy reasons. In order to support
#         # languages that encrypt using 128-bit segments, without having to use data with
#         # a length divisible by 16, we need to pad and truncate the values.
#         remainder = len(value) % 16
#         padded_value = value + b'\0' * (16 - remainder) if remainder else value
#         cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
#         # Return the decrypted string with the padding removed.
#         return cipher.decrypt(padded_value)[:len(value)]
#     return AES.new(key, AES.MODE_CFB, iv).decrypt(value)


def encrypt(key, value, block_segments=False):
    iv = Random.new().read(AES.block_size)
    if block_segments:
        # See comment in decrypt for information.
        remainder = len(value) % 16
        padded_value = value + '\0' * (16 - remainder) if remainder else value
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        value = cipher.encrypt(padded_value)[:len(value)]
    else:
        value = AES.new(key, AES.MODE_CFB, iv).encrypt(value)
    # The returned value has its padding stripped to avoid query string issues.
    return base64.b64encode(iv + value, b'-_').rstrip(b'=')

# Secret key (must match the one used in Go application)
key = b"32-byte-long-key-1234567890ABCDE"  # Replace with the same secret key

# Encrypted data received from Go application (base64 encoded)
data = "This is the data to encrypt"  # Replace with the actual encoded data

# enc_data = encrypt(key, data)
# print("Encrypted data:", enc_data)

dec_data = decrypt(key, "ebQSGWNvx88WUaylC2dDPCwO4ngs46OWYBJGgJaOd5FOQUh6ie8TqrGNOxRi7k-_NKHW8rdmVsZsat4qIvLKOKx8lq0sE5R5Qt01HiH_O9ac8hEnFtlBm4eAQp3HhZtJNw5bVaAVkg0Kq-98t-eWf81XWmnMhkTasrEP8DOYAhV5cFQNyb8S3DKJ5fSFaA66rQfJJI666P7a9sudic8euktXjNPCT4Trfs5BIZO3Wl7pQ_oNa_7KhfAHMpan037x1mifEIGcuXDTvt_OTEsodhJcpJ3LhzbZGVImCmMgBIq3UM4de1Ub_YMcn1FNKM-EB8RXiW2_sNC20QIeh5XR4gbu7D3AT3L84gAkBPNpIBgBfPWo54aii3VzKhWYiLE7nEWhvBYb1maLhS-xpKcL_-LgzCsXlZ7iysia6Mgeywg", True)
print("Decrypted data:", dec_data)
