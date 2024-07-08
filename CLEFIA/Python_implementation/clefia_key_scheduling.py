from fungsi import con128, redefine_con128, gFn4_12, generate_rk

# plaintext                00010203 04050607 08090a0b 0c0d0e0f
# key                      ffeeddcc bbaa9988 77665544 33221100
# L                        8f89a61b 9db9d0f3 93e65627 da0d027e
# ciphertext               de2bf2fd 9b74aacd f1298555 459494fd


# ----------------------------------------------------------------------------------------
keytext = [0xff, 0xee, 0xdd, 0xcc,
           0xbb, 0xaa, 0x99, 0x88,
           0x77, 0x66, 0x55, 0x44,
           0x33, 0x22, 0x11, 0x00]

# get key (later will be user input)
key = [int(hex(i)[2:], base=16) for i in keytext]
# print(f"key: {key}")

wk = []
for i in range(4):
    wk.append(key[i*4:i*4+4])

# print(f"WK: {wk}\n")

# -------------------------------------------
# Create GFN_4,12 function:
# seperti gfn, bedanya:
# - RK[i] diganti dengan con_128[i]
# - Key jadi input
# - Tidak ada xor dengan initial dan final whitening key

# -------------------------------------------
# get Constant Value
con_128 = redefine_con128(con128)

# -------------------------------------------
# GENERATE L[i] (Intermediate Key):
l0, l1, l2, l3 = gFn4_12(wk, con_128)

# disusun spt ini karena pada round-12 tidak ada swap
l_key = l3 + l0 + l1 + l2
l_key_hex = [hex(i)[2:] for i in l_key]
# print(f"L: {l_key}")
# print(f"L (hex): {l_key_hex}\n")


# -------------------------------------------
# Expanding K and L to generate round-key
keyz = wk[0] + wk[1] + wk[2] + wk[3]

# -------------------------------------------
# Generate RK
rk = generate_rk(key=keyz, L=l_key, constant_value=con_128)
# print(rk)
# for i in range(len(rk)):
    # print(f"rk{i}: {rk[i]}")
