import http.server
import socketserver
from flask import Flask, request, jsonify
from werkzeug.serving import make_server

app = Flask(__name__)

messages = []

@app.route('/iniciar', methods=['GET'])
def iniciar():
    global messages
    messages = []
    print('Servidor iniciado')
    return 'Servidor iniciado'

@app.route('/enviarMSG', methods=['POST'])
def enviar_msg():
    message = request.json['message']
    messages.append(message)
    print(f'Mensaje recibido: {message}')
    return 'Mensaje recibido'

@app.route('/mensajes', methods=['GET'])
def obtener_mensajes():
    return jsonify(messages)

if __name__ == '__main__':
    PORT = 500
    httpd = make_server('', PORT, app)
    print("Servidor en puerto", PORT)
    httpd.serve_forever()
#Para url prueba netstat -ano | findstr :500 (puerto que se ponga)
#ip 192.168.1.69
