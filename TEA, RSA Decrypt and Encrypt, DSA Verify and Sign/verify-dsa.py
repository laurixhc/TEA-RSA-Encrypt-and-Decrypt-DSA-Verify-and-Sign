#PROYECTO 1 LAURA HENRIQUEZ CAZORLA
#PARTE 3

#PROGRAMA verify-dsa.py

import hashlib
import sys

#tomamos los valores de N,L,p,q,g que nos da el ejercico
(N, L) = (32, 256)
#f= SHA2-256
q=76059926100834997168886959259974740827583969659752342540152905438681210714437
p=26637745837864131290700910256631620935532246474050686527637391468419091311421880145341862249503983175226708703703661735488742213383465030982895875788926645847543100936984964689552401143720365660806586261622312208209907802788353335550988113329377762056962777935038202695984437718796564028377524795121411128417239049880037897623625218684231069376604983923311880338650116426101686882634583273617073415070596281127783708350617705699955850411723129046709467644647263001426990578838799951132559449076256833633442682618016711044060862782705884649094038765533134537498873864962695295894049714523337586163138984368317828966377
g=13869781642129328376115686255757519025046394720817076227369621463598519136790821512770014943841063097415311879198490263181852759477735694879381610155969968840949577003778703127777570458151324186361219048645563382596013367328431343101155121233664253327838139853881054095249017718738765124290784493127045821543970487420997108733819204592024289844334636828827355786525240165121735815210025381271825673037154876405881573754092854510881817887156574277603772501530315831851738630813076998681026785327941353650544285716176876336878500064480503856129699028778883619035073700877640807263793990172844221585041178137680800871102

#función que calcula el gcd mediante el algoritmo de euclides
def alg_euclides(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    #a será el valor del gcd
    return a, x0, y0

#Cremaos la función H hash,que produce digests de al menos N bytes
def H(msg):
    sha256_hash = hashlib.sha256(msg).digest()
    entero_digest = int.from_bytes(sha256_hash[:N], byteorder="big")
    return entero_digest

#función rpincipal del programa que verifica si la firma es correcta o incorrecta
def verify_dsa(clear_file,dsa_signature_file,dsa_pkey_file):
    #leemos el archivo clear_file
    with open(clear_file, 'rb') as f:
        clear_text = f.read()
    #leemos el archivo de la public key
    with open(dsa_pkey_file,'rb') as f:
        header=f.read(7)
        if header != b"crip23\x06":
            print("Formato de archivo incorrecto.")
            return
        len_y=f.read(2)
        len_y=int.from_bytes(len_y, byteorder='big')
        y=f.read(len_y)
        y=int.from_bytes(y, byteorder='big')
    #leemos el archivo de la firma DSA
    with open(dsa_signature_file,'rb') as f:
        header=f.read(7)
        if header != b"crip23\x07":
            print("Formato de archivo incorrecto.")
            return
        len_r=f.read(2)
        len_r=int.from_bytes(len_r, byteorder='big')
        r=f.read(len_r)
        r=int.from_bytes(r, byteorder='big')
        len_s=f.read(2)
        len_s=int.from_bytes(len_s, byteorder='big')
        s=f.read(len_s)
        s=int.from_bytes(s, byteorder='big')
    #si no se cumple esto, directamente será inválida la firma
    if not 0<r<q or not 0<s<q:
        print("firma inválida")
    #en el resto de casos
    else:
        #seguimos lo dado en teoría,
        s_inv=alg_euclides(s,q)[1]
        w=s_inv%q
        h_msg=H(clear_text)
        u1=(h_msg*w)%q
        u2=(r*w)%q
        dentro= (pow(g, u1, p) * pow(y, u2, p)) % p
        v=dentro%q
        #será válida si v es igual a r, si no inválida
        if v==r:
            print("firma válida")
        else:
            print("firma inválida")
    
#La función main() se ejecuta cuando el programa se inicia 
def main():
    # clear_file = "prueba.txt"
    # dsa_signature_file = "prueba.sign"
    # dsa_pkey_file = "martin.dsa.pk" 
    clear_file = sys.argv[1]
    dsa_signature_file = sys.argv[2]
    dsa_pkey_file = sys.argv[3]
    
    #Llamamos a la función de verificación de la firma dsa
    verify_dsa(clear_file,dsa_signature_file,dsa_pkey_file)

if __name__ == "__main__":
    main()
