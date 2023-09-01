import base64
import binascii
import http.server
import socketserver
import json
from flask import Flask, request, jsonify
from werkzeug.serving import make_server
from cryptography.hazmat.primitives.asymmetric import ec
import os
import sys
import hashlib
import numpy as np
import random
import struct
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher ,algorithms,modes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

messages = []
private_key_alice = ec.generate_private_key(curve=ec.SECP256R1(),backend=default_backend())
public_key_alice = private_key_alice.public_key()
#private_key_bob = ec.generate_private_key(ec.SECP256R1(),backend=default_backend())
#public_key_bob = private_key_bob.public_key()
#shared_key=private_key_alice.exchange(ec.ECDH(),public_key_bob)
#shared_key2=private_key_bob.exchange(ec.ECDH(),public_key_alice)
#tsmsno=private_key_alice


serialized_public = public_key_alice.public_bytes(encoding=serialization.Encoding.X962,format=serialization.PublicFormat.UncompressedPoint)
print(serialized_public.hex())
hex_string2=serialized_public.hex()
key=b'hola'

bytes_resultantes=bytes.fromhex(hex_string2)

#hex_string = binascii.hexlify(decoded_bytes).decode('utf-8')
#print("Cadena hexadecimal:", hex_string)
print("Cadena hexadecimal2:", hex_string2)
print(bytes_resultantes)

#if (shared_key==shared_key2):
    #print('ok')

compartidaB=None

DATA_DIR = 'data'
SERVER_DATA_FILE = 'server_data.json'
SERVER_DATA_PATH = os.path.join(DATA_DIR, SERVER_DATA_FILE)

DATA_DIR2 = 'data2'
SERVER_DATA_FILE2 = 'server_data2.json'
SERVER_DATA_PATH2 = os.path.join(DATA_DIR, SERVER_DATA_FILE)
counter=0
def load_server_data():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if os.path.exists(SERVER_DATA_PATH):
        with open(SERVER_DATA_PATH, 'r') as f:
            data = json.load(f)
    else:
        data = {}
    return data

def save_server_data2(data):
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    with open(SERVER_DATA_PATH, 'w') as f:
        json.dump(data, f)

def load_server_data2():
    if not os.path.exists(DATA_DIR2):
        os.makedirs(DATA_DIR2)
    if os.path.exists(SERVER_DATA_PATH2):
        with open(SERVER_DATA_PATH2, 'r') as f:
            data = json.load(f)
    else:
        data = {}
    return data

def save_server_data(data):
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    with open(SERVER_DATA_PATH, 'w') as f:
        json.dump(data, f)
#def load_server_data():
 #   with open('server_data.json', 'r') as f:
  ## return data

#def save_server_data(data):
#    with open('server_data.json', 'w') as f:
 #       json.dump(data, f)


@app.route('/iniciar', methods=['GET'])
def iniciar():
    global messages
    server_id = request.headers.get('X-Server-ID')
    data = load_server_data()
    if server_id in data:
        messages = data[server_id]['messages']
        print(f'Servidor {server_id} iniciado')
        return 'Servidor iniciado'
    else:
        data[server_id] = {'messages': []}
        save_server_data(data)
        messages = []
        print(f'Servidor {server_id} agregado')
        return f'Servidor {server_id} agregado'

@app.route('/enviarMSG', methods=['POST'])
def enviar_msg():
    server_id = request.headers.get('X-Server-ID')
    message = request.json['message']
    data = load_server_data()
    if server_id in data:
        if 'messages' not in data[server_id]:
            data[server_id]['messages'] = []
        data[server_id]['messages'].append(message)
        save_server_data(data)
        print(f'Mensaje recibido clave publica ESP: {message}')
        return 'Mensaje recibido'
    else:
        print(f'Error: el servidor {server_id} no se encuentra en el archivo')
        return f'Error: el servidor {server_id} no se encuentra en el archivo'

@app.route('/mensajes', methods=['GET'])
def obtener_mensajes():
    server_id = request.headers.get('X-Server-ID')
    data = load_server_data()
    #public_key_alice_bytes = public_key_alice.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    #public_key_alice_dict =  public_key_alice_bytes.hex()
    data[server_id]['public_key_alice']= hex_string2
    save_server_data(data)
    data = load_server_data()
    if server_id in data:
        messages = data[server_id]['messages']
        public_key_alice_dict = data[server_id]['public_key_alice']
         # public_key_alice.public_numbers().x  public_key_alice.public_numbers().y agregar clave pública de Alice a los datos del servidor
        try:
            save_server_data(data) # guardar datos en el archivo
        except Exception as e:
            print(f'Error al guardar los datos del servidor: {str(e)}')
        
        diccionario={
            "esp1":{
                "messages":[messages],
                "public_key_alice": [public_key_alice_dict]
            }
        }
        return jsonify(diccionario)
    #'messages': messages,{ 'id': server_id, 'messages':messages,'publica_server': public_key_alice_dict}
        
    else:
        print(f'Error: el servidor {server_id} no se encuentra en el archivo')
        return f'Error: el servidor {server_id} no se encuentra en el archivo'

@app.route('/compartida', methods=['POST'])
def compartida():
    global compartidaB
    server_id = request.headers.get('X-Server-ID')
    compartidaB = request.json['compartidaB']
    data = load_server_data()
    if server_id in data:
        if 'compartidaB' not in data[server_id]:
            data[server_id]['compartidaB'] = []
        data[server_id]['compartidaB'].append(compartidaB)

        save_server_data(data)
        print(f'Mensaje recibido de clave compartida: {compartidaB}')
        time.sleep(4)
        return 'Mensaje recibido'
    else:
        print(f'Error: el servidor {server_id} no se encuentra en el archivo')
        return f'Error: el servidor {server_id} no se encuentra en el archivo'

@app.route('/verificacion', methods=['GET'])

def verify():
    global shared
    server_id = request.headers.get('X-Server-ID')
    data = load_server_data()
    data2=load_server_data2()
    time.sleep(4)
    if server_id in data:
        server_data = data[server_id]
        publica_bob_list = server_data['messages']
        publica_bob_points = []
        for publica_bob in publica_bob_list:
            print(len(publica_bob))
            pares = [publica_bob[i:i+2] for i in range(0, len(publica_bob), 2)]
            print(pares)
            try:
                    publica_bob_bytes = bytes.fromhex(publica_bob)
                    publica_bob_points.append(publica_bob_bytes)
            except ValueError:
                    print(f'Error: cadena hexadecimal no válida: {publica_bob}')
        compartida_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), publica_bob_bytes)
        compartida = private_key_alice.exchange(ec.ECDH(), compartida_obj)
        compartida_dict = compartida.hex()
        shared=compartida
        
        print (compartida_dict)


        compartidaB_list = data[server_id]['compartidaB']
        compartidaB_points = []
        for compartidaB in compartidaB_list:
            print(len(publica_bob))
            pares = [compartidaB[i:i+2] for i in range(0, len(compartidaB), 2)]
            print(pares)
            try:
                    compartidaB_bytes = bytes.fromhex(compartidaB)
                    compartidaB_points.append(compartidaB_bytes)
            except ValueError:
                    print(f'Error: cadena hexadecimal no válida: {compartidaB}')
        print(compartidaB_bytes.hex())
        if compartidaB_bytes.hex() ==compartida_dict:
            print(f'Mensaje Valido: {compartidaB}')
            valor=0
            diccionario2={
            "esp1":{
                "valor": valor
                
            }
        }
            return jsonify(diccionario2)
            print("\n")
        else:
            valor=1
            diccionario2={
            "esp1":{
                "valor": valor
                
            }
        }
            return jsonify(diccionario2)
            print("\n")
    else:
        print(f'No tiene {server_id} agregado')
        return f'No tiene {server_id} agregado'


@app.route('/Derivada', methods=['POST'])
def derivada():
    global key
    global derivadaB
    time.sleep(4)
    server_id = request.headers.get('X-Server-ID')
    derivadaB = request.json['DerivadaB']
    data = load_server_data()
    if server_id in data:
        if 'DerivadaB' not in data[server_id]:
            data[server_id]['DerivadaB'] = []
        data[server_id]['DerivadaB'].append(derivadaB)
        save_server_data(data)
        
        print(f'Mensaje recibido: {derivadaB}')
        return 'Mensaje recibido'
        print("\n")
    else:
        print(f'Error: el servidor {server_id} no se encuentra en el archivo')
        return f'Error: el servidor {server_id} no se encuentra en el archivo'
    


def generar_hash(clave, info, salt):
    # Concatenar la clave, el info y el salt
    texto_a_hash = clave + info + salt

    # Crear el objeto hash utilizando SHA256
    sha256 = hashlib.sha256()

    # Actualizar el hash con el texto a hashear
    sha256.update(texto_a_hash)

    # Obtener el hash resultante en formato hexadecimal
    hash_resultante = sha256.hexdigest()

    return hash_resultante    

@app.route('/verificacion2', methods=['GET'])
def verify2():
    global shared
    time.sleep(4)
    global compartidaB
    global der
    server_id = request.headers.get('X-Server-ID')
    data = load_server_data()
    data2=load_server_data2()
    if server_id in data:
        derivadaB_list = data[server_id]['DerivadaB']
        derivadaB_points = []
        for derivadaB in derivadaB_list:
            print(len(derivadaB))
            pares = [derivadaB[i:i+2] for i in range(0, len(derivadaB), 2)]
            print(pares)
            try:
                    derivadaB_bytes = bytes.fromhex(derivadaB)
                    derivadaB_points.append(derivadaB_bytes)
            except ValueError:
                    print(f'Error: cadena hexadecimal no válida: {derivadaB}')
        
        # Definir el valor creciente
          # Valor inicial, puede ser cualquier número
        global counter
        # Definir el valor creciente como salt
        salt = counter.to_bytes(4, 'big')  # Suponiendo un contador de 4 bytes (32 bits)
        print(salt)
        # Incrementar el contador para la siguiente iteración o sesión
        salt = b'aaaa'
        saludo=b"HOLA" 
        info = b"isma_crypto_send"
        
        #print(salt)
        #print(salt.hex())
        #print(saludo)
        #print(saludo.hex())
        hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Longitud de la clave de salida deseada
        salt=salt,
        info=info
        )
        der=hkdf.derive(bytes.fromhex(compartidaB))
# Convertir a big endian
        

# Inicializar el bytearray a 0
        

        print("COMPARTIDA; "+ compartidaB)#derivadaB_bytes.hex())
        clave=bytes.fromhex(compartidaB)
        
        
        print("DERIVADA; "+der.hex())
        if derivadaB_bytes.hex() ==der.hex():
            print(f'Mensaje Valido: {derivadaB}')
            valor2=0
            diccionario2={
            "esp1":{
                "valor": valor2
                
            }
        }
            return jsonify(diccionario2)
        else:
            valor2=1
            diccionario2={
            "esp1":{
                "valor": valor2
                
            }
        }
            return jsonify(diccionario2)
    else:
        print(f'No tiene {server_id} agregado')
        return f'No tiene {server_id} agregado'
    


@app.route('/cifrado', methods=['POST'])
def cifrado():
    global cifrado
    time.sleep(4)
    global compartidaB
    global iv
    global der
    iv=np.zeros(16)
    server_id = request.headers.get('X-Server-ID')
    cif = request.json['msg']
    data = load_server_data()
    if server_id in data:
        if 'msg' not in data[server_id]:
            data[server_id]['msg'] = []
        data[server_id]['msg'].append(cif)
        save_server_data(data)
        print(f'Mensaje recibido: {cif}')
        cifrado_bytes=bytes.fromhex(cif)
        comp_bytes=der
        cipher = Cipher(algorithms.AES(comp_bytes), modes.CTR(iv))
        decryptor = cipher.decryptor()
        pt=decryptor.update(cifrado_bytes) + decryptor.finalize()
        print("DERIVADA;",comp_bytes.hex())
        print("CIFRADO:", cifrado_bytes.hex())
        print("DESCIFRADO;",pt.hex())
        return 'Mensaje recibido'
    
    else:
        print(f'Error: el servidor {server_id} no se encuentra en el archivo')
        return f'Error: el servidor {server_id} no se encuentra en el archivo'
    
@app.route('/descifrado', methods=['GET'])
def descifrado():
    global compartidaB
    global der
    server_id = request.headers.get('X-Server-ID')
    data = load_server_data()

# Generar un array de tamaño 32 con números aleatorios entre 0 y 100
    array = [random.randint(0, 100) for _ in range(32)]

# Imprimir el array generado
    print(array)

    save_server_data(data)
    data = load_server_data()
    if server_id in data:
        iv2=np.zeros(16)
        cifrado_bytes=bytes.fromhex(''.join(format(num, '02x') for num in array))
        comp_bytes=der
        cipher = Cipher(algorithms.AES(comp_bytes), modes.CTR(iv2))
        cryptor = cipher.encryptor()
        pt=cryptor.update(cifrado_bytes)+cryptor.finalize()
        cifrado_hex = pt.hex()
        decryptor = cipher.decryptor()
        pt2=decryptor.update(pt) + decryptor.finalize()
        print("DERIVADA;",comp_bytes.hex())
        print("MSG:", cifrado_bytes.hex())
        print("CIFRADO;",pt.hex())
        print("DESCIFRADO2;",pt2.hex())
        
        try:
            save_server_data(data) # guardar datos en el archivo
        except Exception as e:
            print(f'Error al guardar los datos del servidor: {str(e)}')
        diccionario = {"cifrado": cifrado_hex}
        return jsonify(diccionario)
    #'messages': messages,{ 'id': server_id, 'messages':messages,'publica_server': public_key_alice_dict}
        
    else:
        print(f'Error: el servidor {server_id} no se encuentra en el archivo')
        return f'Error: el servidor {server_id} no se encuentra en el archivo'




    """"
    server_id = request.headers.get('X-Server-ID')
    data = load_server_data()

    if server_id in data:
        server_data = data[server_id]
        publica_bob_list = server_data['messages']
        public_key_alice = server_data['public_key_alice']

        publica_bob_points = []
        for publica_bob in publica_bob_list:
            print(len(publica_bob))
            pares = [publica_bob[i:i+2] for i in range(0, len(publica_bob), 2)]
            print(pares)
            #if len(publica_bob) % 2 != 0:
                # Asegurarse de que la cadena tenga longitud par agregando un '0' al principio si es necesario
             #   publica_bob = '0' + publica_bob#[2:]
            #else:
                #publica_bob=publica_bob[2:]
            try:
                publica_bob_bytes = bytes.fromhex(publica_bob)
                publica_bob_points.append(publica_bob_bytes)
            except ValueError:
                print(f'Error: cadena hexadecimal no válida: {publica_bob}')

        compartida_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), publica_bob_bytes)
        compartida = private_key_alice.exchange(ec.ECDH(), compartida_obj)
        compartida_dict = compartida.hex()
        print (compartida_dict)
        server_data['compartida'] = compartida_dict
        save_server_data(data)

        diccionario = {
            "esp1": {
                "messages": publica_bob_list,
                "public_key_alice": public_key_alice,
                "compartida": compartida_dict
            }
        }
        return jsonify(diccionario)
    else:
        print(f'Error: el servidor {server_id} no se encuentra en el archivo')
        return f'Error: el servidor {server_id} no se encuentra en el archivo'
"""
if __name__ == '__main__':
    PORT = 500
    httpd = make_server('', PORT, app)
    print("Servidor en puerto", PORT)
    httpd.serve_forever()

#Para url prueba netstat -ano | findstr :500 (puerto que se ponga)
#ip 192.168.1.69
