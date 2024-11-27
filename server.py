import socket
import ssl
import threading
import sqlite3
from cryptography.fernet import Fernet

# Генерація ключа шифрування (цей самий ключ має бути використаний на клієнті та сервері)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Сертифікати SSL (створіть самопідписаний сертифікат для тестування)
SSL_CERT = "server_cert.pem"
SSL_KEY = "server_key.pem"

# Ініціалізація бази даних
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            group_name TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            group_name TEXT PRIMARY KEY,
            members TEXT
        )
    ''')
    conn.commit()
    conn.close()

def register_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return False  # Користувач вже існує
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()
    return True

def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result and result[0] == password

def save_message(username, group_name, message):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO messages (username, group_name, message) VALUES (?, ?, ?)', (username, group_name, message))
    conn.commit()
    conn.close()

def list_groups():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT group_name FROM groups')
    groups = cursor.fetchall()
    conn.close()
    return [group[0] for group in groups]

def add_group_member(group_name, username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT members FROM groups WHERE group_name = ?', (group_name,))
    result = cursor.fetchone()
    if result:
        members = result[0].split(',')
        if username not in members:
            members.append(username)
            cursor.execute('UPDATE groups SET members = ? WHERE group_name = ?', (','.join(members), group_name))
            conn.commit()
    conn.close()

clients = {}

def broadcast_message(message, group_name, sender):
    for client, (username, active_group) in clients.items():
        if active_group == group_name and username != sender:
            encrypted_message = cipher.encrypt(message.encode('utf-8'))
            client.send(encrypted_message)

def handle_client(client_socket):
    try:
        client_socket.send(cipher.encrypt(b"AUTH"))
        auth_data = cipher.decrypt(client_socket.recv(1024)).decode('utf-8')
        username, password = auth_data.split('|')

        if not authenticate_user(username, password):
            client_socket.send(cipher.encrypt(b"Invalid credentials"))
            client_socket.close()
            return

        clients[client_socket] = (username, None)
        client_socket.send(cipher.encrypt(b"Welcome!"))

        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            message = cipher.decrypt(data).decode('utf-8')

            if message.startswith("REGISTER"):
                _, username, password = message.split("|")
                if register_user(username, password):
                    client_socket.send(cipher.encrypt(b"OK"))
                else:
                    client_socket.send(cipher.encrypt(b"User already exists"))
            elif message.startswith("AUTH"):
                _, username, password = message.split("|")
                if authenticate_user(username, password):
                    client_socket.send(cipher.encrypt(b"Welcome!"))
                else:
                    client_socket.send(cipher.encrypt(b"Invalid credentials"))
            elif message == "LIST_GROUPS":
                groups = list_groups()
                client_socket.send(cipher.encrypt("|".join(groups).encode('utf-8')))
            elif message.startswith("/group"):
                _, group_name = message.split()
                clients[client_socket] = (username, group_name)
                client_socket.send(cipher.encrypt(f"Joined group: {group_name}".encode('utf-8')))
            else:
                _, group_name = clients[client_socket]
                save_message(username, group_name, message)
                broadcast_message(f"{username}: {message}", group_name, username)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        del clients[client_socket]
        client_socket.close()

def main():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server = ssl.wrap_socket(server, server_side=True, certfile=SSL_CERT, keyfile=SSL_KEY)
    server.bind(('0.0.0.0', 12345))
    server.listen(5)
    print("Server listening...")
    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == '__main__':
    main()
