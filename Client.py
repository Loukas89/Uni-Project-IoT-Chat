"""
Enhanced IoT Chat Client
------------------------
Features:
- Connects to the enhanced IoT Chat Server
- AES encrypted framed messages
- Supports chat, admin commands and IoT sensor readings
- Commands:
  /help
  /users
  /devices
  /status
  /whisper username message
  /broadcast message       admin only
  /kick username           admin only
  /sensor metric value     device role mainly, e.g. /sensor temperature 36.5
  /quit
"""

import asyncio
import hashlib
import os
import struct
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BASE_DIR = Path(__file__).resolve().parent
MAX_FRAME_SIZE = 64 * 1024


def load_env_file(path: Path = BASE_DIR / ".env") -> None:
    """Small .env loader so the project does not need python-dotenv."""
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file()

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "65432"))
SHARED_SECRET = os.getenv("SHARED_SECRET", "iot-chat-demo-secret")
AES_KEY = hashlib.sha256(SHARED_SECRET.encode("utf-8")).digest()


HELP_TEXT = """
Available commands:
  /help                         Show this help menu
  /users                        Show connected users
  /devices                      Show connected IoT devices and latest readings
  /status                       Show server status
  /whisper username message     Send a private message
  /broadcast message            Admin only: send message to everyone
  /kick username                Admin only: disconnect a user
  /sensor metric value          Send IoT reading, e.g. /sensor temperature 36.5
  /quit                         Disconnect from server

Anything else is sent as a normal chat message.
""".strip()


def encrypt_message(message: str) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode("utf-8")) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(encrypted_message: bytes) -> str:
    if len(encrypted_message) < 17:
        raise ValueError("Encrypted message is too short.")

    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")


async def send_encrypted(writer: asyncio.StreamWriter, message: str) -> None:
    encrypted = encrypt_message(message)
    writer.write(struct.pack(">I", len(encrypted)) + encrypted)
    await writer.drain()


async def read_encrypted(reader: asyncio.StreamReader) -> str:
    header = await reader.readexactly(4)
    frame_size = struct.unpack(">I", header)[0]

    if frame_size <= 0 or frame_size > MAX_FRAME_SIZE:
        raise ValueError(f"Invalid frame size: {frame_size}")

    encrypted_payload = await reader.readexactly(frame_size)
    return decrypt_message(encrypted_payload)


def format_server_message(raw_message: str) -> str:
    if "|" not in raw_message:
        return raw_message

    message_type, content = raw_message.split("|", 1)
    message_type = message_type.upper()

    if message_type == "CHAT":
        parts = content.split("|", 1)
        if len(parts) == 2:
            sender, message = parts
            return f"[{sender}] {message}"
        return content

    if message_type == "PRIVATE":
        parts = content.split("|", 1)
        if len(parts) == 2:
            sender, message = parts
            return f"[private from {sender}] {message}"
        return content

    if message_type == "BROADCAST":
        parts = content.split("|", 1)
        if len(parts) == 2:
            sender, message = parts
            return f"[broadcast from {sender}] {message}"
        return f"[broadcast] {content}"

    if message_type == "SYSTEM":
        return f"[system] {content}"

    if message_type == "ERROR":
        return f"[error] {content}"

    if message_type == "ALERT":
        return f"[iot alert] {content}"

    if message_type == "AUTH_OK":
        return f"[auth] {content}"

    if message_type == "AUTH_FAIL":
        return f"[auth failed] {content}"

    return raw_message


def parse_user_input(user_input: str) -> str:
    text = user_input.strip()

    if not text:
        return ""

    if text == "/help":
        print(HELP_TEXT)
        return ""

    if text == "/users":
        return "USERS|"

    if text == "/devices":
        return "DEVICES|"

    if text == "/status":
        return "STATUS|"

    if text == "/quit":
        return "QUIT|"

    if text.startswith("/kick "):
        target = text[len("/kick "):].strip()
        return f"KICK|{target}"

    if text.startswith("/broadcast "):
        message = text[len("/broadcast "):].strip()
        return f"BROADCAST|{message}"

    if text.startswith("/whisper "):
        remainder = text[len("/whisper "):].strip()
        parts = remainder.split(" ", 1)
        if len(parts) != 2:
            print("Usage: /whisper username message")
            return ""
        target, message = parts
        return f"WHISPER|{target}|{message}"

    if text.startswith("/sensor "):
        remainder = text[len("/sensor "):].strip()
        parts = remainder.split(" ", 1)
        if len(parts) != 2:
            print("Usage: /sensor metric value")
            return ""
        metric, value = parts
        return f"SENSOR|{metric}|{value}"

    return f"MESSAGE|{text}"


async def receive_messages(reader: asyncio.StreamReader) -> None:
    while True:
        try:
            message = await read_encrypted(reader)
            print(format_server_message(message))

            if message.startswith("SYSTEM|You have been kicked out"):
                print("Disconnected by server.")
                return

        except asyncio.IncompleteReadError:
            print("Disconnected from server.")
            return
        except Exception as exc:
            print(f"Error receiving message: {exc}")
            return


async def send_messages(writer: asyncio.StreamWriter) -> None:
    while True:
        try:
            user_input = await asyncio.to_thread(input, "> ")
            outgoing_message = parse_user_input(user_input)

            if not outgoing_message:
                continue

            await send_encrypted(writer, outgoing_message)

            if outgoing_message == "QUIT|":
                return

        except (KeyboardInterrupt, EOFError):
            await send_encrypted(writer, "QUIT|")
            return
        except Exception as exc:
            print(f"Error sending message: {exc}")
            return


async def authenticate(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
    username = await asyncio.to_thread(input, "Enter your username: ")
    password = await asyncio.to_thread(input, "Enter your password: ")

    await send_encrypted(writer, f"AUTH|{username.strip()}|{password}")
    response = await read_encrypted(reader)

    if response.startswith("AUTH_OK|"):
        parts = response.split("|", 2)
        role = parts[1] if len(parts) > 1 else "unknown"
        print(f"Connected to IoT chat server as {username.strip()} ({role}).")
        print("Type /help to see available commands.")
        return True

    print(format_server_message(response))
    return False


async def main() -> None:
    try:
        reader, writer = await asyncio.open_connection(HOST, PORT)
    except OSError as exc:
        print(f"Could not connect to server at {HOST}:{PORT}. Error: {exc}")
        return

    try:
        authenticated = await authenticate(reader, writer)
        if not authenticated:
            writer.close()
            await writer.wait_closed()
            return

        receive_task = asyncio.create_task(receive_messages(reader))
        send_task = asyncio.create_task(send_messages(writer))

        done, pending = await asyncio.wait(
            {receive_task, send_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        for task in done:
            try:
                await task
            except Exception as exc:
                print(f"Client task ended with error: {exc}")

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
