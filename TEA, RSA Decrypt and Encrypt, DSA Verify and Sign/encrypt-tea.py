#PROYECTO 1 LAURA HENRIQUEZ CAZORLA
#PARTE 1

#PROGRAMA encrypt-tea.py

import sys
import hmac
import os
import hashlib

#usamoslas funciones dadas en teoría
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


#función principal del programa, que nos encriptará el archivo clear_file
def encrypt_tea(clear_file, tea_enc_file, phrase):
    # Generar salt y convertir phrase en una cadena de bytes
    salt = os.urandom(8)
    phrase2 = phrase.encode('utf-8')
    #Para crear la clave secreta sk
    sk = phrase2
    for _ in range(1000):
        sk = hashlib.sha1(salt + sk).digest()
    sk = sk[:16]  # Asegura que la clave tenga 16 bytes


    # Leer el archivo clear_file
    #rb lectura de bytes
    with open(clear_file, 'rb') as f:
        clear_text = f.read()
    #Creamos una cadena de 8 bytes aleatoria
    initvec = os.urandom(8)
    #Ciframos el archivo clear_file con TEA en modo CBC
    ctext = tea_cbc_encrypt(clear_text, sk, initvec)
    #un nuevo objeto hmac para el codigo de autenticacion e integridad de salt+ctext
    #digest() para obtener el valor final del hash que representa el resultado del proceso.
    mac = hmac.new(sk, salt + ctext, hashlib.sha1).digest()

    # Escribir los datos cifrados y el código de autenticación en el archivo de salida
    #wb para la escritura de bytes
    with open(tea_enc_file, 'wb') as f:
        f.write(b"crip23\x01")
        f.write(salt)
        f.write(ctext)
        f.write(mac)
        
#La función main() se ejecuta cuando el programa se inicia 
def main():
    # clear_file = "prueba.txt"
    # tea_enc_file = "prueba.tea"
    # phrase = "x8YjKK2.6W"
    clear_file = sys.argv[1]
    tea_enc_file = sys.argv[2]
    phrase = sys.argv[3]

    #Llamamos a la función de encriptar
    encrypt_tea(clear_file, tea_enc_file, phrase)

if __name__ == "__main__":
    main()
    
