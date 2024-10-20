#PROYECTO 1 LAURA HENRIQUEZ CAZORLA
#PARTE 1

#PROGRAMA decrypt-tea.py

import sys
import hashlib

#usamoslas funciones dadas en teoría
def tea_cbc_decrypt(ctext, key):
    ptext = bytearray ()
    sk = (int.from_bytes(key[0:4], byteorder="big"), int.from_bytes(key[4:8], byteorder="big"), int.from_bytes(key[8:12], byteorder="big"), int.from_bytes(key[12:16], byteorder="big"))
    ivect = ctext [:8]
    iv = (int.from_bytes(ivect[0:4], byteorder="big"),int.from_bytes(ivect[4:8], byteorder="big")) 
    for i in range(1,len(ctext)//8):
        c = (int.from_bytes(ctext[8*i:8*i+4], byteorder="big"), int.from_bytes(ctext[8*i+4:8*i+8], byteorder="big"))
        m = tea_decrypt_block(c, sk)
        ptext += int.to_bytes(m[0] ^ iv[0], length=4, byteorder="big")
        ptext += int.to_bytes(m[1] ^ iv[1], length=4, byteorder="big")
        iv = c
    return pkcs_unpad(bytes(ptext), 8)

def tea_decrypt_block(c, sk):
    v0 = c[0]
    v1 = c[1]
    suma = 0xc6ef3720
    for i in range (32):
        v1 -= ((v0 << 4) + sk[2]) ^ (v0 + suma) ^ ((v0 >> 5) + sk[3]) 
        v1 &= 0xffffffff
        v0 -= ((v1 << 4) + sk[0]) ^ (v1 + suma) ^ ((v1 >> 5) + sk[1]) 
        v0 &= 0xffffffff
        suma -= 0x9e3779b9
        suma &= 0xffffffff 
    return (v0, v1)

def pkcs_unpad(ptext, blocksize):
    n = len(ptext)
    if n == 0 or n % blocksize != 0:
        raise ValueError("invalid PKCS padded plaintext")
    e = ptext[-1]
    if e > blocksize or e > n or ptext[-e:] != bytes([e] * e): 
        raise ValueError("invalid PKCS padded plaintext", ptext)
    return ptext[:-e]

#función principal del programa, que nos desencriptará el archivo tea_enc_file
def decrypt_tea(tea_enc_file, clear_file,phrase):
    #abrimos el archivo tea_enc_file y leemos sus elementos
    with open (tea_enc_file,'rb') as f:
        #los 7 primeros bytes son el encabezado
        header = f.read(7)
        if header != b"crip23\x01":
            print("Formato de archivo incorrecto.")
            return
        #los 8 siguientes el salt
        salt = f.read(8)
        #al resto lo llamamos cipher
        cipher = f.read()
    #dentro de cipher tomamos el ctext
    ctext=cipher[:-20]
    #codificamos la phrase
    phrase2 = phrase.encode('utf-8')
    #obtenemos la secret key
    for _ in range(1000):
        phrase2 = hashlib.sha1(salt+phrase2).digest()
    sk = phrase2[:16]
    #desencriptamos y obtenemos el plaintext
    ptext = tea_cbc_decrypt(ctext,sk)
    #escribimos el plaintext en clear_file
    with open(clear_file,'wb') as f:
        f.write(ptext)


#La función main() se ejecuta cuando el programa se inicia 
def main():
    # tea_enc_file = "prueba.tea"
    # clear_file = "prueba.txt"
    # phrase = "x8YjKK2.6W"
    tea_enc_file = sys.argv[1]
    clear_file = sys.argv[2]
    phrase = sys.argv[3]

    #Llamamos a la función de desencriptar
    decrypt_tea(tea_enc_file, clear_file, phrase)

if __name__ == "__main__":
    main()
    