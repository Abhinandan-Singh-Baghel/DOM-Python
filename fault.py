from Crypto.Cipher import AES
from binascii import hexlify, unhexlify

# Given ciphertext pairs
correct_ciphertext1 = "d8fdc9b896a929cb33df86b634e0dc04"
correct_ciphertext2 = "aa5e77e2064d15e14babd14f5feafa77"
faulty_ciphertext1 = "32622c1f5deed912b18a59996444273f"
faulty_ciphertext2 = "b7565eced22c123b2d6e2fc9101d2315"

# Convert hex strings to bytes
correct_ct1_bytes = unhexlify(correct_ciphertext1)
correct_ct2_bytes = unhexlify(correct_ciphertext2)
faulty_ct1_bytes = unhexlify(faulty_ciphertext1)
faulty_ct2_bytes = unhexlify(faulty_ciphertext2)

# XOR operation to get the difference between correct and faulty ciphertexts
diff_ct1 = bytes([a ^ b for a, b in zip(correct_ct1_bytes, faulty_ct1_bytes)])
diff_ct2 = bytes([a ^ b for a, b in zip(correct_ct2_bytes, faulty_ct2_bytes)])

# Create AES objects for decryption
aes1 = AES.new(correct_ct1_bytes, AES.MODE_ECB)
aes2 = AES.new(correct_ct2_bytes, AES.MODE_ECB)

# Decrypt the difference ciphertexts to get the round 10 key column
round10_key_column = bytes([a ^ b for a, b in zip(aes1.decrypt(diff_ct1), aes2.decrypt(diff_ct2))])

# Print the recovered round 10 key column
print("Recovered Round 10 Key Column: 0x" + hexlify(round10_key_column).decode())
