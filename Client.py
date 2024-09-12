import asyncio
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib

HOST = '127.0.0.1'
PORT = 65432
key = b'1234567890abcdef'

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

async def receive_messages(reader):
    while True:
        try:
            encrypted_message = await reader.read(1024)
            if encrypted_message:
                message = decrypt_message(encrypted_message).decode('utf-8')
                print(message)
                if "You have been kicked out by" in message:
                    print("Disconnecting from the server...")
                    return  # Exit the receive_messages coroutine
            else:
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

async def send_messages(writer):
    while True:
        message = await asyncio.to_thread(input)
        action = "message"
        if message.startswith("/kick "):
            message = message.replace("/kick ", "")
            action = "kick"
        elif message.startswith("/broadcast "):
            message = message.replace("/broadcast ", "")
            action = "broadcast"

        full_message = f"{action}|{message}"
        encrypted_message = encrypt_message(full_message)
        writer.write(encrypted_message)
        await writer.drain()

async def main():
    reader, writer = await asyncio.open_connection(HOST, PORT)
    
    username = await asyncio.to_thread(input, "Enter your username: ")
    password = await asyncio.to_thread(input, "Enter your password: ")
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    credentials = f"{username}|{password_hash}"
    encrypted_credentials = encrypt_message(credentials)
    writer.write(encrypted_credentials)
    await writer.drain()

    encrypted_response = await reader.read(1024)
    response = decrypt_message(encrypted_response).decode('utf-8')
    if response == "Authentication Successful":
        print("Connected to chat server.Enter your message to start chatting with other connected clients.")
        receive_task = asyncio.create_task(receive_messages(reader))
        send_task = asyncio.create_task(send_messages(writer))
        await asyncio.gather(receive_task, send_task)
    else:
        print("Authentication Failed. Please check your credentials.")
        writer.close()

if __name__ == "__main__":
    asyncio.run(main())

