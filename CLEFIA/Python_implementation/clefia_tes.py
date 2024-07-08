from fungsi import xor_, f0, f1, gFn4_18
from clefia_key_scheduling import rk
import time
from clefia_main_inverse import decypt

print("Test for CLEFIA-128")
print("------------------------------------------------------------------------------------------")
# ------------------------------------------------------------------------------------------
print("DATA PROCESSING\n")
start = time.time()

plaintext = [0x00, 0x01, 0x02, 0x03,
             0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b,
             0x0c, 0x0d, 0x0e, 0x0f]

plaintext = [int(hex(i)[2:], base=16) for i in plaintext]

plain = []
for i in range(4):
    plain.append(plaintext[i*4:i*4+4])

print(f"16 bytes plaintext: {plain}")
print("------------------------------------------------------------------------------------------")
print("KEY SETTING\n")
keytext = [0xff, 0xee, 0xdd, 0xcc,
           0xbb, 0xaa, 0x99, 0x88,
           0x77, 0x66, 0x55, 0x44,
           0x33, 0x22, 0x11, 0x00]

key = [int(hex(i)[2:], base=16) for i in keytext]
# print(key)

wk = []
for i in range(4):
    wk.append(key[i*4:i*4+4])
print("Key length is set to 128 bits.")
print(f"key: {wk}")

print("------------------------------------------------------------------------------------------")
# ------------------------------------------------------------------------------------------
# DATA PROCESSING
# ------------------------------------------------------------------------------------------
# input x pada F0 dan F1 berukuran 32bit
# x adalah T0 atau T2

# misal:
# x  = 0x00010203 (plain[0])
# rk = 0xf3e6cef9 (rk[0])
# T0 = [0, 1, 2, 3]
# rk0 = [243, 230, 206, 249]
# maka fungsi F0 pada round-0 adalah:
# from fungsi import f0

lane0 = f0(plain[0], rk[0])
# print(f"f0 after M (round-0): {lane0}")
lane0_hex = [hex(i)[2:] for i in lane0]
# print(f"f0_hex after M (round-0): {lane0_hex}")

# ------------------------------------------------------------------------------------------
# misal:
# x  = 0x08090a0b (plain[2])
# rk = 0x8df75e38 (rk[1])
# T2 = [8, 9, 10, 11]
# rk1 = [141, 247, 94, 56]
# maka fungsi F1 pada round-0 adalah:
# from fungsi import f1
# ------------------------------------------------------------------------------------------

lane3 = f1(plain[2], rk[1])
# print(f"f1 after M (round-0): {lane3}")
lane3_hex = [hex(i)[2:] for i in lane3]
# print(f"f1_hex after M (round-0): {lane3_hex}")

# ------------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------
# KEY SCHEDULING
# ------------------------------------------------------------------------------------------
# Generate L from K


# ------------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------
# encrypt:
print("ENCRYPTING\n")
c0, c1, c2, c3 = gFn4_18(plain, wk, rk)
cipher = c3 + (xor_(c0, wk[2])) + c1 + (xor_(c2, wk[3]))
cipher_hex = [hex(i)[2:] for i in cipher]
print(f"cipher: {cipher}")
print(f"cipher_hex: {cipher_hex}")


# con_128 = redefine_con128(con128)
print("------------------------------------------------------------------------------------------")
print("DECRYPTING\n")
new_cipher = []
for i in range(4):
    new_cipher.append([0, 0, 0, 0])
for i in range(4):
    for j in range(4):
        new_cipher[i][j] = cipher[4 * i + j]
# DECRYPT:

dec = decypt(cipher=new_cipher, key=wk)
print(f"plaintext:  {dec}")
end = time.time()
print("------------------------------------------------------------------------------------------")
print("TIME ANALYSIS\n")
print("Time:",end - start, "s.")