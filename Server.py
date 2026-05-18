"""
Enhanced IoT Chat Server
------------------------
Features:
- Async client/server chat using asyncio
- AES encrypted framed messages
- Users loaded from users.json
- PBKDF2 password verification with salt
- Role-based access control
- Admin commands: broadcast, kick
- User commands: whisper, users, devices, status
- IoT device telemetry messages and alerting
- Audit logs written to logs/audit.log
- Basic .env configuration support without external dotenv dependency
"""

import asyncio
import datetime as dt
import hashlib
import hmac
import html
import json
import logging
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BASE_DIR = Path(__file__).resolve().parent
MAX_FRAME_SIZE = 64 * 1024  # 64 KB per encrypted message
PBKDF2_ITERATIONS = 200_000


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
USERS_FILE = Path(os.getenv("USERS_FILE", str(BASE_DIR / "users.json")))
LOG_FILE = Path(os.getenv("LOG_FILE", str(BASE_DIR / "logs" / "audit.log")))
DASHBOARD_ENABLED = os.getenv("DASHBOARD_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8080"))

# AES supports 16, 24 or 32 byte keys. A SHA-256 digest gives us a stable 32-byte key
# from a human-readable shared secret.
AES_KEY = hashlib.sha256(SHARED_SECRET.encode("utf-8")).digest()


LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)


@dataclass
class ClientSession:
    username: str
    role: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    address: str
    connected_at: float


clients: Dict[str, ClientSession] = {}
latest_readings: Dict[str, Dict[str, Tuple[str, str]]] = {}
server_started_at = time.time()

ROLE_PERMISSIONS = {
    "admin": {"MESSAGE", "BROADCAST", "KICK", "WHISPER", "USERS", "DEVICES", "STATUS", "SENSOR", "QUIT"},
    "user": {"MESSAGE", "WHISPER", "USERS", "DEVICES", "STATUS", "QUIT"},
    "device": {"SENSOR", "STATUS", "MESSAGE", "QUIT"},
}

SENSOR_THRESHOLDS = {
    "temperature": 35.0,
    "humidity": 80.0,
    "motion": 1.0,
}


def log_event(event: str, level: int = logging.INFO) -> None:
    logging.log(level, event)


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


def load_users() -> dict:
    if not USERS_FILE.exists():
        raise FileNotFoundError(
            f"Users file not found: {USERS_FILE}. Create users.json or copy the provided one."
        )

    with USERS_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("users.json must contain a JSON object.")

    return data


users = load_users()


def verify_password(username: str, password: str) -> bool:
    user_record = users.get(username)
    if not user_record:
        return False

    try:
        salt = bytes.fromhex(user_record["salt"])
        expected_hash = bytes.fromhex(user_record["password_hash"])
    except (KeyError, ValueError):
        log_event(f"Invalid password record for {username}", logging.ERROR)
        return False

    calculated_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        int(user_record.get("iterations", PBKDF2_ITERATIONS)),
    )

    return hmac.compare_digest(calculated_hash, expected_hash)


def get_role(username: str) -> str:
    return users.get(username, {}).get("role", "user")


def is_authorized(username: str, action: str) -> bool:
    role = get_role(username)
    allowed = action in ROLE_PERMISSIONS.get(role, set())
    if not allowed:
        log_event(f"Unauthorized action attempted by {username}: {action}", logging.WARNING)
    return allowed


def timestamp_now() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_uptime(seconds: float) -> str:
    total_seconds = int(seconds)
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}h {minutes}m {seconds}s"


async def send_to_user(username: str, message: str) -> bool:
    session = clients.get(username)
    if not session:
        return False

    try:
        await send_encrypted(session.writer, message)
        return True
    except Exception as exc:
        log_event(f"Failed sending message to {username}: {exc}", logging.ERROR)
        return False


async def broadcast(message: str, exclude_username: Optional[str] = None) -> None:
    disconnected = []
    for username, session in list(clients.items()):
        if username == exclude_username:
            continue
        try:
            await send_encrypted(session.writer, message)
        except Exception as exc:
            log_event(f"Broadcast failed for {username}: {exc}", logging.ERROR)
            disconnected.append(username)

    for username in disconnected:
        clients.pop(username, None)


async def disconnect_user(username: str, reason: str = "Disconnected") -> None:
    session = clients.pop(username, None)
    if not session:
        return

    try:
        await send_encrypted(session.writer, f"SYSTEM|{reason}")
    except Exception:
        pass

    try:
        session.writer.close()
        await session.writer.wait_closed()
    except Exception:
        pass

    log_event(f"User {username} disconnected. Reason: {reason}")


async def kick_user(target_username: str, admin_username: str) -> str:
    if target_username == admin_username:
        return "ERROR|You cannot kick yourself."

    if target_username not in clients:
        log_event(f"Kick failed by {admin_username}. Target not online: {target_username}", logging.WARNING)
        return f"ERROR|User {target_username} is not online."

    await disconnect_user(target_username, f"You have been kicked out by {admin_username}.")
    await broadcast(f"SYSTEM|{target_username} has been kicked by {admin_username}.")
    log_event(f"User {target_username} kicked out by {admin_username}")
    return f"SYSTEM|User {target_username} was kicked successfully."


def online_users_text() -> str:
    if not clients:
        return "No users online."

    rows = []
    for username, session in sorted(clients.items()):
        connected_for = format_uptime(time.time() - session.connected_at)
        rows.append(f"{username} ({session.role}, online {connected_for})")
    return ", ".join(rows)


def online_devices_text() -> str:
    devices = [session for session in clients.values() if session.role == "device"]
    if not devices:
        return "No IoT devices online."

    rows = []
    for session in sorted(devices, key=lambda item: item.username):
        readings = latest_readings.get(session.username, {})
        if readings:
            reading_text = ", ".join(
                f"{metric}={value} at {seen_at}" for metric, (value, seen_at) in readings.items()
            )
        else:
            reading_text = "no readings yet"
        rows.append(f"{session.username}: {reading_text}")
    return " | ".join(rows)


def server_status_text() -> str:
    total_users = len(clients)
    total_devices = sum(1 for session in clients.values() if session.role == "device")
    return (
        f"Server online. Uptime: {format_uptime(time.time() - server_started_at)}. "
        f"Connected clients: {total_users}. IoT devices: {total_devices}."
    )


def read_log_tail(limit: int = 60) -> str:
    if not LOG_FILE.exists():
        return "No audit log entries yet."

    lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-limit:]) if lines else "No audit log entries yet."


def dashboard_html() -> str:
    user_rows = []
    for username, session in sorted(clients.items()):
        user_rows.append(
            "<tr>"
            f"<td>{html.escape(username)}</td>"
            f"<td>{html.escape(session.role)}</td>"
            f"<td>{html.escape(session.address)}</td>"
            f"<td>{html.escape(format_uptime(time.time() - session.connected_at))}</td>"
            "</tr>"
        )

    if not user_rows:
        user_rows.append('<tr><td colspan="4">No clients connected.</td></tr>')

    reading_rows = []
    for device, readings in sorted(latest_readings.items()):
        for metric, (value, seen_at) in sorted(readings.items()):
            reading_rows.append(
                "<tr>"
                f"<td>{html.escape(device)}</td>"
                f"<td>{html.escape(metric)}</td>"
                f"<td>{html.escape(value)}</td>"
                f"<td>{html.escape(seen_at)}</td>"
                "</tr>"
            )

    if not reading_rows:
        reading_rows.append('<tr><td colspan="4">No sensor readings yet.</td></tr>')

    log_text = html.escape(read_log_tail())
    status = html.escape(server_status_text())

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="5">
  <title>IoT Chat Dashboard</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #0f172a; color: #e5e7eb; }}
    h1, h2 {{ color: #93c5fd; }}
    .card {{ background: #111827; border: 1px solid #374151; border-radius: 12px; padding: 1rem; margin-bottom: 1rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #374151; padding: 0.65rem; text-align: left; }}
    th {{ color: #bfdbfe; }}
    pre {{ white-space: pre-wrap; background: #020617; padding: 1rem; border-radius: 10px; overflow: auto; }}
    .muted {{ color: #9ca3af; }}
  </style>
</head>
<body>
  <h1>IoT Chat Dashboard</h1>
  <p class="muted">Auto-refreshes every 5 seconds.</p>
  <div class="card"><strong>Status:</strong> {status}</div>

  <div class="card">
    <h2>Connected Clients</h2>
    <table>
      <thead><tr><th>Username</th><th>Role</th><th>Address</th><th>Connected For</th></tr></thead>
      <tbody>{''.join(user_rows)}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Latest IoT Readings</h2>
    <table>
      <thead><tr><th>Device</th><th>Metric</th><th>Value</th><th>Timestamp</th></tr></thead>
      <tbody>{''.join(reading_rows)}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Audit Log Tail</h2>
    <pre>{log_text}</pre>
  </div>
</body>
</html>"""


async def handle_dashboard_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await reader.readuntil(b"\r\n\r\n")
        body = dashboard_html().encode("utf-8")
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        writer.write(response)
        await writer.drain()
    except Exception as exc:
        log_event(f"Dashboard request failed: {exc}", logging.WARNING)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def handle_sensor_reading(username: str, metric: str, value: str) -> None:
    metric = metric.strip().lower()
    value = value.strip()

    if not metric or not value:
        await send_to_user(username, "ERROR|Sensor command requires a metric and value.")
        return

    latest_readings.setdefault(username, {})[metric] = (value, timestamp_now())
    log_event(f"Sensor reading from {username}: {metric}={value}")

    await send_to_user(username, f"SYSTEM|Sensor reading saved: {metric}={value}")

    threshold = SENSOR_THRESHOLDS.get(metric)
    if threshold is None:
        return

    try:
        numeric_value = float(value)
    except ValueError:
        return

    if numeric_value >= threshold:
        alert = f"ALERT|{username} reported high {metric}: {numeric_value} (threshold {threshold})"
        await broadcast(alert)
        log_event(alert.replace("ALERT|", "Alert: "), logging.WARNING)


async def process_client_message(username: str, message: str) -> None:
    if "|" in message:
        action, content = message.split("|", 1)
    else:
        action, content = "MESSAGE", message

    action = action.strip().upper()

    if not is_authorized(username, action):
        await send_to_user(username, f"ERROR|You are not authorized to use {action}.")
        return

    if action == "MESSAGE":
        content = content.strip()
        if not content:
            await send_to_user(username, "ERROR|Cannot send an empty message.")
            return
        await broadcast(f"CHAT|{username}|{content}", exclude_username=username)
        log_event(f"Message from {username}: {content}")

    elif action == "BROADCAST":
        content = content.strip()
        if not content:
            await send_to_user(username, "ERROR|Broadcast message cannot be empty.")
            return
        await broadcast(f"BROADCAST|{username}|{content}")
        log_event(f"Broadcast from {username}: {content}")

    elif action == "KICK":
        target_username = content.strip()
        if not target_username:
            await send_to_user(username, "ERROR|Usage: /kick username")
            return
        result = await kick_user(target_username, username)
        await send_to_user(username, result)

    elif action == "WHISPER":
        parts = content.split("|", 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            await send_to_user(username, "ERROR|Usage: /whisper username message")
            return
        target_username, private_message = parts[0].strip(), parts[1].strip()
        delivered = await send_to_user(target_username, f"PRIVATE|{username}|{private_message}")
        if delivered:
            await send_to_user(username, f"SYSTEM|Private message sent to {target_username}.")
            log_event(f"Private message from {username} to {target_username}")
        else:
            await send_to_user(username, f"ERROR|User {target_username} is not online.")

    elif action == "USERS":
        await send_to_user(username, f"SYSTEM|Online users: {online_users_text()}")

    elif action == "DEVICES":
        await send_to_user(username, f"SYSTEM|IoT devices: {online_devices_text()}")

    elif action == "STATUS":
        await send_to_user(username, f"SYSTEM|{server_status_text()}")

    elif action == "SENSOR":
        parts = content.split("|", 1)
        if len(parts) != 2:
            await send_to_user(username, "ERROR|Usage: /sensor metric value")
            return
        await handle_sensor_reading(username, parts[0], parts[1])

    elif action == "QUIT":
        await disconnect_user(username, "You disconnected from the server.")

    else:
        await send_to_user(username, f"ERROR|Unknown action: {action}")
        log_event(f"Unknown action from {username}: {action}", logging.WARNING)


async def authenticate_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[str]:
    address = writer.get_extra_info("peername")

    try:
        message = await asyncio.wait_for(read_encrypted(reader), timeout=20)
    except asyncio.TimeoutError:
        await send_encrypted(writer, "AUTH_FAIL|Authentication timed out.")
        return None
    except Exception as exc:
        log_event(f"Failed to read authentication data from {address}: {exc}", logging.WARNING)
        return None

    parts = message.split("|", 2)
    if len(parts) != 3 or parts[0] != "AUTH":
        await send_encrypted(writer, "AUTH_FAIL|Invalid authentication message.")
        log_event(f"Invalid authentication message from {address}", logging.WARNING)
        return None

    _, username, password = parts
    username = username.strip()

    if not username or not verify_password(username, password):
        await send_encrypted(writer, "AUTH_FAIL|Invalid username or password.")
        log_event(f"Failed authentication attempt for {username or 'unknown'} from {address}", logging.WARNING)
        return None

    if username in clients:
        await send_encrypted(writer, "AUTH_FAIL|This user is already connected.")
        log_event(f"Duplicate login blocked for {username} from {address}", logging.WARNING)
        return None

    role = get_role(username)
    await send_encrypted(writer, f"AUTH_OK|{role}|Authentication successful.")
    log_event(f"User {username} authenticated successfully from {address}")
    return username


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    address = str(writer.get_extra_info("peername"))
    username: Optional[str] = None

    try:
        username = await authenticate_connection(reader, writer)
        if username is None:
            writer.close()
            await writer.wait_closed()
            return

        session = ClientSession(
            username=username,
            role=get_role(username),
            reader=reader,
            writer=writer,
            address=address,
            connected_at=time.time(),
        )
        clients[username] = session

        await send_to_user(username, f"SYSTEM|Welcome {username}. Role: {session.role}. Type /help for client commands.")
        await broadcast(f"SYSTEM|{username} joined the chat.", exclude_username=username)
        log_event(f"User {username} connected from {address}")

        while username in clients:
            try:
                message = await read_encrypted(reader)
            except asyncio.IncompleteReadError:
                break
            except ValueError as exc:
                await send_to_user(username, f"ERROR|Invalid message: {exc}")
                log_event(f"Invalid message from {username}: {exc}", logging.WARNING)
                continue

            await process_client_message(username, message)

    except ConnectionResetError:
        if username:
            log_event(f"Connection reset by {username}", logging.WARNING)
    except Exception as exc:
        if username:
            log_event(f"Unexpected error with {username}: {exc}", logging.ERROR)
        else:
            log_event(f"Unexpected error before authentication from {address}: {exc}", logging.ERROR)
    finally:
        if username and username in clients:
            clients.pop(username, None)
            await broadcast(f"SYSTEM|{username} left the chat.", exclude_username=username)
            log_event(f"User {username} disconnected from {address}")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_server() -> None:
    chat_server = await asyncio.start_server(handle_client, HOST, PORT)
    dashboard_server = None

    log_event(f"Server listening on {HOST}:{PORT}")
    log_event(f"Users loaded from {USERS_FILE}")
    log_event(f"Audit log file: {LOG_FILE}")

    serve_tasks = [asyncio.create_task(chat_server.serve_forever())]

    if DASHBOARD_ENABLED:
        try:
            dashboard_server = await asyncio.start_server(handle_dashboard_request, DASHBOARD_HOST, DASHBOARD_PORT)
            log_event(f"Dashboard available at http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
            serve_tasks.append(asyncio.create_task(dashboard_server.serve_forever()))
        except OSError as exc:
            log_event(
                f"Dashboard could not start on {DASHBOARD_HOST}:{DASHBOARD_PORT}: {exc}. "
                "Chat server will continue without dashboard.",
                logging.WARNING,
            )

    try:
        await asyncio.gather(*serve_tasks)
    finally:
        chat_server.close()
        await chat_server.wait_closed()
        if dashboard_server:
            dashboard_server.close()
            await dashboard_server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        log_event("Server stopped by keyboard interrupt.")
