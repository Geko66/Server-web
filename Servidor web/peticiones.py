import requests

# URL base del servidor Flask
base_url = 'http://localhost:5000'

# Iniciar sesión en el servidor
response = requests.get(base_url + '/iniciar?id=1')
print(response.content)

# Enviar un mensaje al servidor
response = requests.post(base_url + '/enviarMSG', json={'message': 'Hola, servidor'})
print(response.content)

# Obtener los mensajes actuales del servidor
response = requests.get(base_url + '/mensajes')
print(response.json())

# Enviar un mensaje al cliente
response = requests.post(base_url + '/enviar_mensaje_cliente', json={'message': 'Hola, cliente'})
print(response.json())
