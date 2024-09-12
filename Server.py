import asyncio
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import datetime

HOST = '127.0.0.1'
PORT = 65432
key = b'1234567890abcdef'

users = {
    "sauron": {"password_hash": hashlib.sha256("sau123".encode()).hexdigest(), "role": "admin"},
    "aragorn": {"password_hash": hashlib.sha256("ara123".encode()).hexdigest(), "role": "admin"},
    "legolas": {"password_hash": hashlib.sha256("leg123".encode()).hexdigest(), "role": "user"},
    "gandalf": {"password_hash": hashlib.sha256("gan123".encode()).hexdigest(), "role": "user"},
    "frodo": {"password_hash": hashlib.sha256("fro123".encode()).hexdigest(), "role": "user"}
}

audit_log = []  # List to store audit logs

def log_event(event):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    audit_log.append(f"{timestamp}: {event}")
    print(f"Audit Log - {timestamp}: {event}")  # Print to console or write to file

def encrypt_message(message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ct

def decrypt_message(encrypted_message):
    iv = encrypted_message[:16]
    ct = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def authenticate_user(username, password_hash):
    if username in users and users[username]['password_hash'] == password_hash:
        log_event(f"User {username} authenticated successfully")
        return True
    else:
        log_event(f"Failed authentication attempt for {username}")
        return False

def authorize_user(username, action):
    user_role = users.get(username, {}).get("role", "user")
    if action in ["broadcast", "kick"] and user_role != "admin":
        log_event(f"User {username} unauthorized to {action}")
        return False
    return True

clients = {}

def kick_user(username_to_kick, admin_username):
    client_writer = clients.get(username_to_kick)
    if client_writer:
        kick_notification = f"You have been kicked out by {admin_username}."
        encrypted_notification = encrypt_message(kick_notification)
        client_writer.write(encrypted_notification)
        asyncio.create_task(client_writer.drain())
        log_event(f"User {username_to_kick} kicked out by {admin_username}")
        return True
    log_event(f"Failed kick attempt on {username_to_kick} by {admin_username}")
    return False

async def broadcast_message(message, sender, action="message"):
    if not authorize_user(sender, action):
        return
    encrypted_message = encrypt_message(message)
    for username, client_writer in clients.items():
        if username != sender or action == "broadcast":
            try:
                client_writer.write(encrypted_message)
                await client_writer.drain()
            except Exception as e:
                log_event(f"Error broadcasting to {username}: {e}")

async def handle_client(reader, writer):
    address = writer.get_extra_info('peername')
    encrypted_credentials = await reader.read(100)
    credentials = decrypt_message(encrypted_credentials).decode('utf-8')
    username, password_hash = credentials.split('|')

    if not authenticate_user(username, password_hash):
        response = "Authentication Failed"
        writer.write(encrypt_message(response))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        log_event(f"Authentication failed for {username} from {address}")
        return

    response = "Authentication Successful"
    writer.write(encrypt_message(response))
    await writer.drain()

    clients[username] = writer
    log_event(f"User {username} connected from {address}")
    await broadcast_message(f"{username} has joined the chat!", username)

    try:
        while True:
            encrypted_message = await reader.read(1024)
            if encrypted_message:
                message = decrypt_message(encrypted_message).decode('utf-8')
                action, content = message.split('|', 1)
                if action in ["kick", "broadcast"] and authorize_user(username, action):
                    if action == "kick":
                        username_to_kick = content
                        if kick_user(username_to_kick, username):
                            await broadcast_message(f"{username_to_kick} has been kicked by {username}", username)
                    elif action == "broadcast":
                        await broadcast_message(content, username, action="broadcast")
                elif action == "message":
                    await broadcast_message(f"{username}: {content}", username)
                    log_event(f"Message from {username}: {content}")
                else:
                    log_event(f"Unauthorized action {action} attempted by {username}")
            else:
                break
    except ConnectionResetError:
        log_event(f"Connection lost with {username}")
    except KeyError:
        log_event(f"KeyError with {username}. Might already be removed.")
    finally:
        writer.close()
        await writer.wait_closed()
        if username in clients:
            del clients[username]
            await broadcast_message(f"{username} has left the chat.", username)
            log_event(f"User {username} disconnected from {address}")

async def start_server():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Server listening on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(start_server())

