#PROYECTO 1 LAURA HENRIQUEZ CAZORLA
#PARTE 2

#PROGRAMA gen-rsa-key.py

import secrets
import sys
import random


#Usamos el programa de Miller Rabin explicado en clase por nuestro compañero
def test(n,a):
    '''
    Parameters
    ----------
    n : an odd integer larger than 3 we want to check whether or not it's a prime
    a : an integer between 2 and n-2 which will hopefully test whether or not n is a prime

    Returns
    -------
    True if n is a composite
    False if it COULD be a prime (with Probability >= 0.75)
    '''
    
    e = 0
    d = n
    for j in range(n//2):
        d = d//2
        e = e+1
        if (d%2!=0):
            break
    
    if (pow(a,d,n)==1):
        return False
    else:
        for j in range (e):
            if (pow(a,d*(2**j),n)==(n-1)):
                return False
    return True

def MR(n,k):
    '''
    Parameters
    ----------
    n : an integer larger than 3 we want to check whether or not it's a prime
    k: the accuracy (number of Miler-Rabin tests)
                        
    Returns
    -------
    True if n (most likely) is prime
    False if it's a composite
    '''
    
    if (n%2==0):
        return False
        
    #Now we'll apply the Miller_Rabin test propper
    
    for i in range(k):
        a = random.randint(2,n-2)
        if (test(n,a)):
            return False
        
    return True

#función que calcula el gcd mediante el algoritmo de euclides
def alg_euclides(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    #a será el valor del gcd
    return a, x0, y0

#funnción principal del programa que nos genera la clave rsa
def gen_rsa_key(len_n,rsa_skey_file ,rsa_pkey_file):
    #len_n lo convertimos en entero por si nos la dan en una cadena de caracteres
    len_n=int(len_n)
    #len_n se debe mover entre 80 y 1024
    if len_n<80 or len_n>1024:
        print("La longitud es incorrecta")
        return
    #definimos byteorder
    byteorder="big"
    #tomamos la longitud de p,q de aproximadamente la mitad de len_n
    size=len_n//2
    #tomamos una cadena de bytes de longitud size
    p= bytes(random.randint(0,255) for i in range(size))
    #convertimos p en entero
    p=int.from_bytes(p, byteorder)
    #tomamos una cadena de bytes de longitud size
    q= bytes(random.randint(0,255) for i in range(size))
    #convertimos q en entero
    q=int.from_bytes(q, byteorder)
    lista=[p,q]
    #vemos que cumplan el test de rabin miller y que p y q sean diferentes
    for i in range(len(lista)):
        contador=False
        while (not contador):
            if (not MR(lista[i],50))or lista[0]==lista[1]:
                lista[i]= secrets.token_bytes(size)
                lista[i]=int.from_bytes(lista[i], byteorder)
            else:
                contador=True
    #hacemos que p sea el valor más pequeño, y q el mayor
    if lista[0]<lista[1]:
        p=lista[0]
        q=lista[1]
    else:
        q=lista[0]
        p=lista[1]
    #tomamos n=p*q
    n=p*q
    phi_n=(p-1)*(q-1)
    #tomamos un numero al azar entre 2 y phi de n
    e=random.randint(2, phi_n)
    #queremos que el gcd entre e y phi de n sea 1
    while alg_euclides(e,phi_n)[0]!=1:
         e=random.randint(2, phi_n)
    #d será el inverso multiplicativo
    d=alg_euclides(e,phi_n)[1]
    if d<0:
        d=(d%phi_n)
    lista=[p,q,e,d,n]
    lista_resultado=[]
    #vamos a convertir todos los datos obtenidos en bytes
    for j in range(len(lista)):
        nueva=[]
        if j==4:
            len_p=len_n
        else:
            len_p = (lista[j].bit_length() + 7) // 8
        nueva.append((len_p).to_bytes(2, byteorder))
        nueva.append(lista[j].to_bytes(len_p, byteorder))
        lista_resultado.append(nueva)
    #en la secret key están p,q,e,d,n y sus longitudes
    with open(rsa_skey_file,'wb') as skey:
        skey.write(b"crip23\x02")
        for k in range(len(lista)):
            skey.write(lista_resultado[k][0])
            skey.write(lista_resultado[k][1])
    #en la public key estarán e,n y sus longitudes
    with open(rsa_pkey_file,'wb') as pkey:
        pkey.write(b"crip23\x03")
        pkey.write(lista_resultado[2][0])
        pkey.write(lista_resultado[2][1])
        pkey.write(lista_resultado[4][0])
        pkey.write(lista_resultado[4][1])
        

#La función main() se ejecuta cuando el programa se inicia 
def main():
    # len_n = 81
    # rsa_skey_file = "martin.rsa.sk"
    # rsa_pkey_file = "martin.rsa.pk"
    len_n=sys.argv[1]
    rsa_skey_file=sys.argv[2]
    rsa_pkey_file=sys.argv[3]

     #Llamamos a la función de generar la rsa key
    gen_rsa_key(len_n, rsa_skey_file, rsa_pkey_file)

if __name__ == "__main__":
    main()
