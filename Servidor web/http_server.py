from flask import Flask, request, jsonify, redirect, url_for

app = Flask(__name__)

messages = []

@app.route('/iniciar', methods=['GET'])
def iniciar():
    global messages
    messages = []
    id = request.args.get('id')
    print(f'Servidor iniciado con ID: {id}')
    return redirect(url_for('enviar_mensaje_cliente', id=id))


@app.route('/enviarMSG', methods=['POST'])
def enviar_msg():
    message = request.json['message']
    messages.append(message)
    print(f'Mensaje recibido: {message}')
    return 'Mensaje recibido'

@app.route('/mensajes', methods=['GET'])
def obtener_mensajes():
    return jsonify(messages)

@app.route('/enviar_mensaje_cliente', methods=['POST'])
def enviar_mensaje_cliente():
    message = request.json['message']
    print(f'Mensaje enviado al cliente: {message}')
    return message

if __name__ == '__main__':
    PORT = 5000
    app.run(port=PORT)

#Para url prueba netstat -ano | findstr :500 (puerto que se ponga)
#ip 192.168.1.69
