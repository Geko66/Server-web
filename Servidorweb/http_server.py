import http.server
import socketserver
import json
from flask import Flask, request, jsonify
from werkzeug.serving import make_server
from cryptography.hazmat.primitives.asymmetric import ec
import os
import sys
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher ,algorithms,modes
from cryptography.fernet import Fernet

app = Flask(__name__)

messages = []
private_key_alice = ec.generate_private_key(ec.SECP384R1())
public_key_alice = private_key_alice.public_key()
private_key_bob = ec.generate_private_key(ec.SECP384R1())
public_key_bob = private_key_bob.public_key()
shared_key=private_key_alice.exchange(ec.ECDH(),public_key_bob)
shared_key2=private_key_bob.exchange(ec.ECDH(),public_key_alice)
if (shared_key==shared_key2):
    print('ok')



DATA_DIR = 'data'
SERVER_DATA_FILE = 'server_data.json'
SERVER_DATA_PATH = os.path.join(DATA_DIR, SERVER_DATA_FILE)

def load_server_data():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if os.path.exists(SERVER_DATA_PATH):
        with open(SERVER_DATA_PATH, 'r') as f:
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
        print(f'Mensaje recibido: {message}')
        return 'Mensaje recibido'
    else:
        print(f'Error: el servidor {server_id} no se encuentra en el archivo')
        return f'Error: el servidor {server_id} no se encuentra en el archivo'

@app.route('/mensajes', methods=['GET'])
def obtener_mensajes():
    server_id = request.headers.get('X-Server-ID')
    data = load_server_data()
    if server_id in data:
        messages = data[server_id]['messages']
        public_key_alice_dict = {'x': public_key_alice.public_numbers().x, 'y': public_key_alice.public_numbers().y}
        data[server_id]['public_key_alice'] = public_key_alice_dict # agregar clave pública de Alice a los datos del servidor
        try:
            save_server_data(data) # guardar datos en el archivo
        except Exception as e:
            print(f'Error al guardar los datos del servidor: {str(e)}')
        return jsonify({'messages': messages, 'publica_server': public_key_alice_dict})
    else:
        print(f'Error: el servidor {server_id} no se encuentra en el archivo')
        return f'Error: el servidor {server_id} no se encuentra en el archivo'

if __name__ == '__main__':
    PORT = 500
    httpd = make_server('', PORT, app)
    print("Servidor en puerto", PORT)
    httpd.serve_forever()

#Para url prueba netstat -ano | findstr :500 (puerto que se ponga)
#ip 192.168.1.69