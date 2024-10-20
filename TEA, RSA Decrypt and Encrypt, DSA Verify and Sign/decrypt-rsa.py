#PROYECTO 1 LAURA HENRIQUEZ CAZORLA
#PARTE 2

#PROGRAMA decrypt-rsa.py

import sys

#usamos las funciones dadas en teoría
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

# esta funci ́on descifra el texto cifrado ctext conociendo la # clave secreta
def dec_with_seckey(ctext, seckey):
    b = int(ctext)
    a = pow(b, seckey[3], seckey[4]) 
    ptext = str(a-1)
    ptext = "0" * (7-len(ptext)) + ptext 
    return ptext

def pkcs_unpad(ptext, blocksize):
    n = len(ptext)
    if n == 0 or n % blocksize != 0:
        raise ValueError("invalid PKCS padded plaintext")
    e = ptext[-1]
    if e > blocksize or e > n or ptext[-e:] != bytes([e] * e): 
        raise ValueError("invalid PKCS padded plaintext", ptext)
    return ptext[:-e]

def exponenciacion_binaria_modular_iterativa(a, e, n):
    b = a
    x = 1
    while e > 0:
        if e & 1 != 0:
            x = (b*x) % n
        b = (b*b) % n
        e >>= 1
    return  x

#esta es la función principal del programa que se encarga de desencriptar con rsa el archivo rsa_enc_file
def decrypt_rsa(rsa_enc_file,clear_file,rsa_skey_file):
    #leemos los datos del archivo a desencriptar
    with open (rsa_enc_file,'rb') as f:
        
        header = f.read(7)
        if header != b"crip23\x04":
            print("Formato de archivo incorrecto.")
            return
        len_c = f.read(2)
        len_c=int.from_bytes(len_c, byteorder='big')
        c = f.read(len_c)
        cipher=f.read()
    ctext=cipher[0:len(cipher)-20]
    #leemos los datos de la clave secreta, para obtener p,q,e,d,n
    with open(rsa_skey_file,'rb') as f:
        header=f.read(7)
        if header != b"crip23\x02":
            print("Formato de archivo incorrecto.")
            return
        len_p=f.read(2)
        len_p=int.from_bytes(len_p, byteorder='big')
        p=f.read(len_p)
        len_q=f.read(2)
        len_q=int.from_bytes(len_q, byteorder='big')
        q=f.read(len_q)
        len_e=f.read(2)
        len_e=int.from_bytes(len_e, byteorder='big')
        e=f.read(len_e)
        len_d=f.read(2)
        len_d=int.from_bytes(len_d, byteorder='big')
        d=f.read(len_d)
        len_n=f.read(2)
        len_n=int.from_bytes(len_n, byteorder='big')
        n=f.read(len_n)
    skey=[p,q,e,d,n]
    #transformamos a enteros los elementos de la skey
    for i in range(len(skey)):
        skey[i]=int.from_bytes(skey[i], byteorder='big')
    #transformamos a entero c
    c_int=int.from_bytes(c, byteorder='big')

    #desciframos c_int con la skey
    m=exponenciacion_binaria_modular_iterativa(c_int, skey[3], skey[4])
    len_m= (m.bit_length() + 7) // 8
    m=m.to_bytes(len_m, byteorder='big')
    sk=m[-16:]
    #desciframos y obtenemos el plaintext
    ptext=tea_cbc_decrypt(ctext,sk)
    #escribimos en clear_file el texto descifrado
    with open(clear_file,'wb') as f:
        f.write(ptext)
        
#La función main() se ejecuta cuando el programa se inicia 
def main():
    # rsa_enc_file = "prueba.enc"
    # clear_file = "prueba.txt"
    # rsa_skey_file = "martin.rsa.sk"
    rsa_enc_file = sys.argv[1]
    clear_file = sys.argv[2]
    rsa_skey_file = sys.argv[3]

    #Llamamos a la función de desencriptar
    decrypt_rsa(rsa_enc_file,clear_file,rsa_skey_file)

if __name__ == "__main__":
    main()

