from fungsi import xor_, con128, redefine_con128, generate_rk, gFn4_12, gFn4_inv_18
# from clefia_key_scheduling import rk  # import karena key sama

# plaintext                00010203 04050607 08090a0b 0c0d0e0f
# key                      ffeeddcc bbaa9988 77665544 33221100
# L                        8f89a61b 9db9d0f3 93e65627 da0d027e
# ciphertext               de2bf2fd 9b74aacd f1298555 459494fd


# ----------------------------------------------------------------------------------------
# cipher = [[222, 43, 242, 253], [155, 116, 170, 205],
#           [241, 41, 133, 85], [69, 148, 148, 253]]
# key = [[255, 238, 221, 204], [187, 170, 153, 136],
#        [119, 102, 85, 68], [51, 34, 17, 0]]

cipher = [[9, 24, 224, 208], [50, 251, 14, 7], [63, 229, 174, 237], [176, 189, 99, 22]]
key = [[109, 117, 110, 49], [50, 51, 49, 49], [0, 0, 0, 0], [0, 0, 0, 0]]

# cipher = [[196, 83, 106, 47], [144, 73, 188, 15], [190, 221, 245, 217], [184, 156, 20, 176]]
# key = [[116, 119, 111, 32], [111, 110, 101, 32], [104, 97, 108, 111], [32, 116, 101, 115]]


# INVERSE:
# t0, t1, t2, t3 = gFn4_inv_18(inp=cipher, key=key, rk=rk)
# plain = t1 + xor_(t2, key[0]) + t3 + xor_(t0, key[1])
# print(plain)
# plain = [hex(i)[2:] for i in plain]
# print(plain)
# print(len(plain))

# get Constant Value
con_128 = redefine_con128(con128)

# DECRYPT:


def decypt(cipher, key):
    con_128 = redefine_con128(con128)
    # print(con_128)
    # generate L
    l0, l1, l2, l3 = gFn4_12(key, con_128)
    l_key = l3 + l0 + l1 + l2
    l_key_hex = [hex(i)[2:] for i in l_key]
    # print(f"L \t\t: {l_key}")
    # print(f"L_hex \t\t: {l_key_hex}")

    # Expanding K and L to generate round-key
    keyz = key[0] + key[1] + key[2] + key[3]
    rk = generate_rk(key=keyz, L=l_key, constant_value=con_128)

    # menampilkan RK[i]:
    # for i in range(len(rk)):
        # print(f"rk{i} \t\t: {rk[i]}")

    # generate plaintext
    t0, t1, t2, t3 = gFn4_inv_18(inp=cipher, wk=key, rk=rk)
    plain = t1 + xor_(t2, key[0]) + t3 + xor_(t0, key[1])
    plain_hex = []
    for i in plain:
        cek = hex(i)[2:]
        if len(cek) == 1:
            cek = '0' + cek
        plain_hex.append(cek)
    return plain_hex


# dec = decypt(cipher=cipher, key=key)
# print(f"plaintext \t: {dec}")
# print(f"len plain \t: {len(dec)}")
# for i in dec:
    # print((chr(int(i, base=16))), end='')
