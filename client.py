import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Адрес и порт сервера
HOST = '127.0.0.1'
PORT = 8080

# Загрузка публичного ключа
with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read(), backend=default_backend()
    )

# Установка сокета и соединение с сервером
sock = socket.socket()
sock.connect((HOST, PORT))

# Сообщение для шифрования
message = "Привет, сервер!"
encrypted_message = public_key.encrypt(
    message.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Отправка зашифрованного сообщения
sock.send(encrypted_message)

# Закрытие соединения
sock.close()
