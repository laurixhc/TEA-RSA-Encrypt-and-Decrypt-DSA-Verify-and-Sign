#PROYECTO 1 LAURA HENRIQUEZ CAZORLA
#PARTE 2

#PROGRAMA encrypt-rsa.py

import hashlib
import random
import hmac
import sys

#usamos las funciones dadas en teoría
def tea_cbc_encrypt(ptext, key, ivect):
    ctext = bytearray ()
    sk = (int.from_bytes(key[0:4], byteorder="big"),int.from_bytes(key[4:8], byteorder="big"), int.from_bytes(key[8:12], byteorder="big"), int.from_bytes(key[12:16], byteorder="big"))
    ctext += ivect
    iv = (int.from_bytes(ivect[0:4], byteorder="big"),int.from_bytes(ivect[4:8], byteorder="big"))
    ptext = pkcs_pad(ptext , 8)
    for i in range(len(ptext)//8):
        m = (int.from_bytes(ptext[8*i:8*i+4], byteorder="big") ^ iv[0], int.from_bytes(ptext[8*i+4:8*i+8], byteorder="big") ^ iv[1])
        c = tea_encrypt_block(m, sk)
        ctext += int.to_bytes(c[0], length=4, byteorder="big")
        ctext += int.to_bytes(c[1], length=4, byteorder="big")
        iv = c
    return bytes(ctext)
    
def tea_encrypt_block(m, sk):
    v0 = m[0]
    v1 = m[1]
    suma = 0
    for i in range (32):
        suma += 0x9e3779b9 
        suma &= 0xffffffff
        v0 += ((v1 << 4) + sk[0]) ^ (v1 + suma) ^ ((v1 >> 5) + sk[1]) 
        v0 &= 0xffffffff
        v1 += ((v0 << 4) + sk[2]) ^ (v0 + suma) ^ ((v0 >> 5) + sk[3]) 
        v1 &= 0xffffffff
    return (v0, v1)

def pkcs_pad(ptext, blocksize): 
    n = len(ptext)
    e = blocksize - (n % blocksize) 
    return ptext + bytes([e] * e)

# esta funci ́on cifra un texto plano ptext, que es una cadena de # EXACTAMENTE k-1 = 7 caracteres {"0", "1", ..., "9"}
def enc_with_pubkey(ptext, pubkey):
    a = int(ptext) + 1
    ctext = pow(a, pubkey[0], pubkey[1])
    return ctext

def exponenciacion_binaria_modular_iterativa(a, e, n):
    b = a
    x = 1
    while e > 0:
        if e & 1 != 0:
            x = (b*x) % n
        b = (b*b) % n
        e >>= 1
    return  x

#función principal del programa que nos encriptará con rsa el clear_file
def rsa_encrypt(clear_file,rsa_enc_file,rsa_pkey_file):
    #abrimos la public key y separamosa los diferentes elementos
    with open(rsa_pkey_file,'rb') as f:
        header=f.read(7)
        if header != b"crip23\x03":
            print("Formato de archivo incorrecto.")
            return
        len_e=f.read(2)
        len_e=int.from_bytes(len_e, byteorder='big')
        e=f.read(len_e)
        len_n=f.read(2)
        len_n=int.from_bytes(len_n, byteorder='big')
        n=f.read(len_n)
    #pasamos e y n a enteros
    e=int.from_bytes(e, byteorder='big')
    n=int.from_bytes(n, byteorder='big')
    #k será la longitud de n
    k=len_n
    # creamos una sk con 16 bytes tomados al azar
    sk=bytes(random.randint(0,255) for i in range(16))
    #rnd será de k-16-3 bytes (usamos lo visto en la teoría)
    rnd=bytes(random.randint(1,255) for i in range(k-16-3))
    #Así obtenemos el numero entero de la secret key
    sk_int=int.from_bytes(b"\x02" + rnd + b"\x00" + sk, byteorder="big")
    #la pasamos a bytes
    # sk=sk_int.to_bytes(k-1,byteorder='big')
    pkey=[e,n]
    #encriptamos el ptext con la sk_int
    c=exponenciacion_binaria_modular_iterativa(sk_int,pkey[0],pkey[1])
    #leemos el archivo a cifrar en cuestion
    with open(clear_file, 'rb') as f:
        clear_text = f.read()
    #creamos una cadena de 8 bytes al azar
    initvec = bytes(random.randint(0,255) for i in range(8))
    #ciframos el clear_file
    ctext = tea_cbc_encrypt(clear_text, sk, initvec)
    #un nuevo objeto hmac para el codigo de autenticacion e integridad de salt+ctext
    #digest() para obtener el valor final del hash que representa el resultado del proceso.
    mac = hmac.new(sk, ctext, hashlib.sha1).digest()
    nueva=[]
    #para el valor de c y su longitud
    long = (c.bit_length() + 7) // 8
    nueva.append(long.to_bytes(2, byteorder='big'))
    nueva.append(c.to_bytes(long, byteorder='big'))
    #escribimos el cifrado en el rsa_enc_file
    with open(rsa_enc_file,'wb') as f:
        f.write(b"crip23\x04")
        f.write(nueva[0])
        f.write(nueva[1])
        f.write(ctext)
        f.write(mac)
        
#La función main() se ejecuta cuando el programa se inicia 
def main():
    # clear_file = "prueba.txt"
    # rsa_enc_file = "prueba.enc"
    # rsa_pkey_file = "martin.rsa.pk"
    clear_file = sys.argv[1]
    rsa_enc_file = sys.argv[2]
    rsa_pkey_file = sys.argv[3]

     #Llamamos a la función de encriptar
    rsa_encrypt(clear_file,rsa_enc_file,rsa_pkey_file)

if __name__ == "__main__":
    main()

