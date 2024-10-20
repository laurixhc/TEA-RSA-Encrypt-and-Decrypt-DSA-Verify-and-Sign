#PROYECTO 1 LAURA HENRIQUEZ CAZORLA
#PARTE 3

#PROGRAMA sign-dsa.py

import random
import hashlib
import sys

#tomamos los valores de N,L,p,q,g que nos da el ejercico
(N, L) = (32, 256)
#f= SHA2-256
q=76059926100834997168886959259974740827583969659752342540152905438681210714437
p=26637745837864131290700910256631620935532246474050686527637391468419091311421880145341862249503983175226708703703661735488742213383465030982895875788926645847543100936984964689552401143720365660806586261622312208209907802788353335550988113329377762056962777935038202695984437718796564028377524795121411128417239049880037897623625218684231069376604983923311880338650116426101686882634583273617073415070596281127783708350617705699955850411723129046709467644647263001426990578838799951132559449076256833633442682618016711044060862782705884649094038765533134537498873864962695295894049714523337586163138984368317828966377
g=13869781642129328376115686255757519025046394720817076227369621463598519136790821512770014943841063097415311879198490263181852759477735694879381610155969968840949577003778703127777570458151324186361219048645563382596013367328431343101155121233664253327838139853881054095249017718738765124290784493127045821543970487420997108733819204592024289844334636828827355786525240165121735815210025381271825673037154876405881573754092854510881817887156574277603772501530315831851738630813076998681026785327941353650544285716176876336878500064480503856129699028778883619035073700877640807263793990172844221585041178137680800871102

#Cremaos la función H hash,que produce digests de al menos N bytes
def H(msg):
    sha256_hash = hashlib.sha256(msg).digest()
    entero_digest = int.from_bytes(sha256_hash[:N], byteorder="big")
    return entero_digest

#función que calcula el gcd mediante el algoritmo de euclides
def alg_euclides(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    #a será el valor del gcd
    return a, x0, y0

#función principal del programa que nos genera una firma dsa
def sign_dsa(clear_file,dsa_signature_file,dsa_skey_file):
    #inicializamos, r y s en cero
    r=0
    s=0
    #abrimos la secret key y leemos sus elementos
    with open(dsa_skey_file,'rb') as f:
        header=f.read(7)
        if header != b"crip23\x05":
            print("Formato de archivo incorrecto.")
            return
        len_x=f.read(2)
        len_x=int.from_bytes(len_x, byteorder='big')
        x=f.read(len_x)
        x=int.from_bytes(x, byteorder='big')
    #leemos el clear_file
    with open(clear_file, 'rb') as f:
        clear_text = f.read()
    #mientras r y s sean cero, buscamos unos nuevos valores de r y s (aplicamos la teoría)
    while(r==0 or s==0):
        #numero rnadom entre 1 y q-1
        k=random.randint(1,q-1)
        valor_izq=pow(g,k,p)
        r=valor_izq%q  
        #función hash al texto
        h_msg=H(clear_text)
        dentro=h_msg + x*r
        k_inv=alg_euclides(k,q)[1]
        s=(k_inv*dentro)%q
    #transformamos en bytes r,s y sus longitudes
    len_r = (r.bit_length() + 7) // 8
    r=r.to_bytes(len_r, byteorder='big')
    len_r= len_r.to_bytes(2, byteorder='big')
    len_s = (s.bit_length() + 7) // 8
    s=s.to_bytes(len_s, byteorder='big')
    len_s= len_s.to_bytes(2, byteorder='big')
    #escribimos en el archivo dsa_signature_file la firma
    with open(dsa_signature_file,'wb') as firma:
        firma.write(b"crip23\x07")
        firma.write(len_r)
        firma.write(r)
        firma.write(len_s)
        firma.write(s)
    
    
#La función main() se ejecuta cuando el programa se inicia 
def main():
    # clear_file = "prueba.txt"
    # dsa_signature_file = "prueba.sign"
    # dsa_skey_file = "martin.dsa.sk" 
    clear_file = sys.argv[1]
    dsa_signature_file = sys.argv[2]
    dsa_skey_file = sys.argv[3]
    
     #Llamamos a la función de firma dsa
    sign_dsa(clear_file,dsa_signature_file,dsa_skey_file)

if __name__ == "__main__":
    main()

