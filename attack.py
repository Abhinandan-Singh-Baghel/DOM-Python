
# import pandas as pd
# import numpy as np

# # Load power traces from a CSV file
# df = pd.read_csv('HW_power_trace_1.csv', header=None)

# # Extract plaintexts, ciphertexts, and power traces
# plaintexts_hex = df.iloc[:, 0].values
# ciphertexts_hex = df.iloc[:, 1].values
# power_traces = df.iloc[:, 2:].values

# # Convert hex strings to integers for plaintexts and ciphertexts
# plaintexts = np.array([int(plaintext, 16) for plaintext in plaintexts_hex])
# ciphertexts = np.array([int(ciphertext, 16) for ciphertext in ciphertexts_hex])

# # AES S-Box function
# def aes_sbox(input_bytes):
#     s_box = np.array([
#     0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
#     0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
#     0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
#     0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
#     0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
#     0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
#     0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
#     0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
#     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
#     0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
#     0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
#     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
#     0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
#     0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
#     0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
#     0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

#     ], dtype=np.uint8)
#     return s_box[input_bytes]

# # Differential Mean Attack function
# def differential_mean_attack(traces, plaintexts_hex, byte_positions):
#     num_traces = traces.shape[0]
#     key_candidates = np.zeros(len(byte_positions), dtype=np.uint8)

#     # Convert hex strings to integers for plaintexts
#     plaintexts = np.array([int(plaintext, 16) for plaintext in plaintexts_hex], dtype=np.uint32)

#     for byte_idx, byte_position in enumerate(byte_positions):
#         for guess in range(256):
#             hypothetical_power = aes_sbox(np.bitwise_xor(plaintexts, guess))
#             power_difference = np.mean(traces[:, byte_position] ^ hypothetical_power)
#             key_candidates[byte_idx] = guess if power_difference > key_candidates[byte_idx] else key_candidates[byte_idx]

#     return key_candidates


# # Perform the differential mean attack to recover the 4th and 5th bytes of the key
# recovered_bytes = differential_mean_attack(power_traces, plaintexts, [4, 5])

# # Print the recovered key bytes
# print("Recovered 4th Byte of the Key:", format(recovered_bytes[0], '02x'))
# print("Recovered 5th Byte of the Key:", format(recovered_bytes[1], '02x'))


import pandas as pd
import numpy as np

# Load power traces from a CSV file
df = pd.read_csv('HW_power_trace_1.csv', header=None)

# Extract ciphertexts and power traces
ciphertexts_hex = df.iloc[:, 1].values
power_traces = df.iloc[:, 2:].values

# Convert hex strings to integers for ciphertexts
ciphertexts = [int(ciphertext, 16) for ciphertext in ciphertexts_hex]

# Constants
NCipher = 256  # Number of possible ciphertext values (0 to 255)
NPoint = len(power_traces[0])  # Number of power consumption values in each trace

# Initialize arrays to store partial sums and counts for bins 0 and 1
sumBin0 = np.zeros(NPoint)
sumBin1 = np.zeros(NPoint)
countBin0 = 0
countBin1 = 0

# Loop over all ciphertexts and compute partial sums and counts for bins 0 and 1
for cipher in range(NCipher):
    partial_cipher = cipher ^ key  # Apply inverse S-box operation (substitute key byte)
    bin_index = partial_cipher & 1  # Extract the least significant bit of partial cipher
    if bin_index == 1:
        sumBin1 += power_traces[cipher]
        countBin1 += 1
    else:
        sumBin0 += power_traces[cipher]
        countBin0 += 1

# Compute mean differences and find the key byte with the maximum bias
biasKey = np.zeros(256)  # Stores the bias values for each possible key byte
biasIndex = np.zeros(256, dtype=int)  # Stores the corresponding index with maximum bias for each key byte

for key in range(256):
    meanDiff = (sumBin0 / countBin0 - sumBin1 / countBin1)  # Compute mean differences
    biasIndex[key] = np.argmax(np.abs(meanDiff))  # Find the index with maximum bias
    biasKey[key] = np.max(np.abs(meanDiff))  # Store the maximum bias value

# Recover the 4th and 5th bytes of the key
recovered_4th_byte = biasIndex[4]
recovered_5th_byte = biasIndex[5]

# Print the recovered key bytes
print("Recovered 4th Byte of the Key:", format(recovered_4th_byte, '02x'))
print("Recovered 5th Byte of the Key:", format(recovered_5th_byte, '02x'))
