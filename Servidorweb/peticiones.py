
import requests
import json

# URL base del servidor
BASE_URL = 'http://192.168.1.69:500'

# Iniciar servidor
response = requests.get(f'{BASE_URL}/iniciar', headers={'X-Server-ID': 'server1'})
print(response.text)

# Enviar mensaje
message = 'Hola, servidor!'
response = requests.post(f'{BASE_URL}/enviarMSG', headers={'X-Server-ID': 'server1'}, json={'message': message})
print(response.text)

# Obtener mensajes
response = requests.get(f'{BASE_URL}/mensajes', headers={'X-Server-ID': 'server1'})
data = json.loads(response.text)
print(f'Mensajes: {data["messages"]}, publica_server: {data["publica_server"]}')
