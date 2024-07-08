from fungsi import xor_, gFn4_18, break_input, con128, redefine_con128, generate_rk, gFn4_12, gFn4_18

# plaintext                00010203 04050607 08090a0b 0c0d0e0f
# key                      ffeeddcc bbaa9988 77665544 33221100
# L                        8f89a61b 9db9d0f3 93e65627 da0d027e
# ciphertext               de2bf2fd 9b74aacd f1298555 459494fd


# ----------------------------------------------------------------------------------------
# plain = [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
# key = [[255, 238, 221, 204], [187, 170, 153, 136],
#        [119, 102, 85, 68], [51, 34, 17, 0]]

# tes custom plain dan key:
# -----------------------------------------
# 16 char
# plaintext = "526455"
plaintext = "abcdefghijkl"
plain = break_input(plaintext)
print(f"plaintext\t: {plaintext}")
print(f"plain break\t: {plain}\n")

# -----------------------------------------
# 16 char
# key_user = "mun12311"
key_user = "two one halo tes"
key = break_input(key_user)
keyhex = [hex(ord(i))[2:] for i in key_user]
print(f"key user\t: {key_user}")
print(f"len key user\t: {len(key_user)}")
print(f"key\t\t: {key}")
print(f"key_hex \t: {keyhex}")
keyhexx = ''
for i in keyhex:
    keyhexx += i

print(f"key_hex \t: {keyhexx}\n")

    

# get Constant Value
con_128 = redefine_con128(con128)


# -----------------------------------------
# create ENC-function
def encrypt(plain, key):

    # generate L
    l0, l1, l2, l3 = gFn4_12(key, con_128)
    l_key = l3 + l0 + l1 + l2
    l_key_hex = [hex(i)[2:] for i in l_key]
    print(f"L \t\t: {l_key}")
    print(f"L_hex \t\t: {l_key_hex}")

    # Expanding K and L to generate round-key
    keyz = key[0] + key[1] + key[2] + key[3]
    rk = generate_rk(key=keyz, L=l_key, constant_value=con_128)

    # menampilkan RK[i]:
    for i in range(len(rk)):
        print(f"rk{i} \t\t: {rk[i]}")

    # generate ciphertext
    c0, c1, c2, c3 = gFn4_18(plain, key, rk)
    cipher = c3 + (xor_(c0, key[2])) + c1 + (xor_(c2, key[3]))
    cipher_hex = []
    for i in cipher:
        cek = hex(i)[2:]
        if len(cek) == 1:
            cek = '0' + cek
        cipher_hex.append(cek)
    return cipher_hex


# -----------------------------------------
enc = encrypt(plain=plain, key=key)
print(f"ciphertext \t: {enc}")
print(f"len cipher \t: {len(enc)}")

enc_int = [int(i, base=16) for i in enc]
print(f"cip_int \t: {enc_int}")

for i in enc:
    print(i, end='')
