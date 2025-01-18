import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

# Адрес и порт сервера
HOST = '127.0.0.1'
PORT = 8080

# Путь к файлам ключей
private_key_file = 'private_key.pem'
public_key_file = 'public_key.pem'


# Функция для генерации и сохранения ключей
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сохранение ключей в файлы
    with open(private_key_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(public_key_file, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key


# Функция для загрузки ключей из файлов
def load_keys():
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return private_key, public_key


# Проверка существования файлов ключей и их загрузка или генерация
if os.path.exists(private_key_file) and os.path.exists(public_key_file):
    private_key, public_key = load_keys()
else:
    private_key = generate_keys()
    public_key = private_key.public_key()

# Создание сервера
server_socket = socket.socket()
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"Сервер запущен на {HOST}:{PORT}...")
conn, addr = server_socket.accept()
print(f"Подключено к {addr}")

# Прием зашифрованного сообщения от клиента
encrypted_message = conn.recv(1024)
print(f"Зашифрованное сообщение получено: {encrypted_message}")

# Расшифровка сообщения
try:
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Расшифрованное сообщение: {decrypted_message.decode()}")
except Exception as e:
    print(f"Ошибка при расшифровке сообщения: {e}")

# Закрытие соединения
conn.close()
server_socket.close()
