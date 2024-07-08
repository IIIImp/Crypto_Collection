import binascii
# import time
from fungsi import con128, redefine_con128, generate_rk, xor_, gFn4_12, break_input, gFn4_inv_18

# start = time.time()

# key
key_user = "two one tes12"
key = break_input(key_user)
print(f"key user\t: {key_user}")
print(f"key\t\t: {key}")


# file to hex
with open('enkrip/hasil.mp3', 'rb') as fp:
    hexstring = binascii.hexlify(fp.read())

print(f"panjang file: {len(hexstring)}")

# decode bytes into str(hex)
to_hex = hexstring.decode("ascii")
print(f"panjang decode: {len(to_hex)}")


# function: split each hex
def split_each_hex(state):
    split_2 = []
    for i in range(0, len(state), 2):
        split_2.append(state[i:i+2])
    return split_2


# split each hex
to_each_hex = split_each_hex(to_hex)

# convert each hex into dec
to_each_dec = [int(i, base=16) for i in to_each_hex]

# group dec into 1 block (16 bytes)
split_16 = []
for i in range(0, len(to_each_dec), 16):
    split_16.append(to_each_dec[i: i+16])


akan_unconvert = split_16
# --------------------------------------------------------------------------------------------------------


def break_input_into_4split(inputan):
    temp = []
    while len(inputan) < 16:                          # padd 0 jika item < 16
        inputan.append(0)
    for i in range(0, len(inputan), 4):
        temp.append(inputan[i:i+4])
    return temp


# get Constant Value
con_128 = redefine_con128(con128)

# generate L
l0, l1, l2, l3 = gFn4_12(key, con_128)
l_key = l3 + l0 + l1 + l2
# print(f"L \t\t: {l_key}")

# Expanding K and L to generate round-key
keyz = key[0] + key[1] + key[2] + key[3]
rk = generate_rk(key=keyz, L=l_key, constant_value=con_128)


# function: dekripsi per block
def decypt(ciphertext, key):
    cipher = break_input_into_4split(ciphertext)

    # generate plaintext
    t0, t1, t2, t3 = gFn4_inv_18(inp=cipher, wk=key, rk=rk)
    plain = t1 + xor_(t2, key[0]) + t3 + xor_(t0, key[1])

    # convert output menjadi hex, lalu add 0 jika hex hanya 1 char, ex: 'a' -> '0a'
    plain_hex = []
    for i in plain:
        cek = hex(i)[2:]
        if len(cek) == 1:
            cek = '0' + cek
        plain_hex.append(cek)
    return plain_hex


# function: enkripsi semua block, join hasil enkripsi kedalam 1 variable
def unconvert_file(state):
    semua = ''
    for i in range(len(state)):
        temp = decypt(ciphertext=state[i], key=key)
        for item in temp:
            semua += item
    return semua


unconvert = unconvert_file(akan_unconvert)
# print(sem)
print(f"panjang dekrip file: {len(unconvert)}")
print(type(unconvert))


# ---------------------------------------------------------------------------------------------
# hex to file
with open('dekrip/hasil_unconvert.mp3', 'wb') as fp:
    fp.write(binascii.unhexlify(unconvert))


# end = time.time()
# print("time execution:", (end-start), "secs")
