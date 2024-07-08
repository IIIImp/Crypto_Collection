import binascii


# file to hex
with open('music.mp3', 'rb') as fp:
    hexstring = binascii.hexlify(fp.read())

print(f"panjang file: {len(hexstring)}")

# decode bytes into str(hex)
to_hex = hexstring.decode("ascii")
print(f"panjang decode: {len(to_hex)}")


# function: split each hex
def split(state):
    split_2 = []
    for i in range(0, len(state), 2):
        split_2.append(state[i:i+2])
    return split_2


# split each hex
to_each_hex = split(to_hex)

# convert each hex into dec
to_each_dec = [int(i, base=16) for i in to_each_hex]

# group dec into 1 block (16 bytes)
split_16 = []
for i in range(0, len(to_each_dec), 16):
    split_16.append(to_each_dec[i: i+16])


# --------------------------------------------------------------------------------------------------------
akan_diconvert = split_16


# def convert_per_i(state):
#     temp = [hex(i)[2:] for i in state]
#     temp2 = []
#     for i in temp:
#         if len(i) == 1:
#             i = '0' + i
#         temp2.append(i)
#     return temp2


# nantinya diganti dengan "enkripsi per block"
# ---------------------------------------------------------------------------------------------
# function: convert tiap block menjadi hex
def convert_per_x(state):
    temp = []
    for i in state:
        cek = hex(i)[2:]
        if len(cek) == 1:
            cek = '0' + cek
        temp.append(cek)
    return temp


# nantinya diganti dengan "enkripsi semua, join hasil enkripsi kedalam 1 variable"
# ---------------------------------------------------------------------------------------------
# function: convert tiap block menjadi hex, lalu digabung dalam 1 variable
def convert_semua(statex):
    semua = ''
    for i in range(len(statex)):
        temp = convert_per_x(statex[i])
        for item in temp:
            semua += item
    return semua


sem = convert_semua(akan_diconvert)
# print(sem)
print(len(sem))
print(type(sem))


# hex to file
# with open('hasil/hasil.mp3', 'wb') as fp:
#     fp.write(binascii.unhexlify(sem))
