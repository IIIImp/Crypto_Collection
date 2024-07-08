import time
import os

lokasi_enc = 'D:/Kuliah/"SMT XI (terakhir)"/"Skripsi XI"/"Clefia-128 python"/clefia_encrypt_file.py'
lokasi_dec = 'D:/Kuliah/"SMT XI (terakhir)"/"Skripsi XI"/"Clefia-128 python"/clefia_decrypt_file.py'


# def repeat(path, iter):
#     waktuAll = []
#     i = 0
#     while i < iter:
#         print(i)
#         start = time.time()
#         os.system('python ' + path)
#         end = time.time()
#         waktu = end - start
#         waktuAll.append(waktu)
#         i += 1
#     return waktuAll


def repeat(path, iter):
    waktuAll = []
    for i in range(iter):
        print(i)

        start = time.perf_counter()
        os.system('python ' + path)
        end = time.perf_counter()

        waktu = end - start
        waktuAll.append(waktu)
    return waktuAll


coba = repeat(path=lokasi_dec, iter=100)

print(f"waktu total \t: {coba}")
print(f"rata-rata \t: {sum(coba)/len(coba)}")
