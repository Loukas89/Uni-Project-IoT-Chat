"""
IoT Chat Room GUI
------------------------

This is a single-window GUI for the Enhanced IoT Chat project.
"""

from __future__ import annotations

import hashlib
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
import warnings
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:
    pass

BASE_DIR = Path(__file__).resolve().parent
MAX_FRAME_SIZE = 64 * 1024

DEMO_ACCOUNTS = {
    "sauron (admin)": ("sauron", "sau123"),
    "aragorn (admin)": ("aragorn", "ara123"),
    "frodo (user)": ("frodo", "fro123"),
    "legolas (user)": ("legolas", "leg123"),
    "gandalf (user)": ("gandalf", "gan123"),
    "sensor_01 (device)": ("sensor_01", "sensor123"),
    "sensor_02 (device)": ("sensor_02", "sensor123"),
}

HELP_TEXT = """Available commands:
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

def load_env_file(path: Path = BASE_DIR / ".env") -> None:
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
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8080"))

# Supports both names, because older project files used SECRET_KEY.
SHARED_SECRET = os.getenv("SHARED_SECRET", os.getenv("SECRET_KEY", "iot-chat-demo-secret"))
AES_KEY = hashlib.sha256(SHARED_SECRET.encode("utf-8")).digest()

class ProtocolError(Exception):
    pass

def is_port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    """Return True when a process is listening on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def encrypt_message(message: str) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode("utf-8")) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(encrypted_message: bytes) -> str:
    if len(encrypted_message) < 17:
        raise ProtocolError("Encrypted message is too short.")

    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")

def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size

    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed by server.")
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)

def send_encrypted(sock: socket.socket, message: str) -> None:
    encrypted = encrypt_message(message)
    frame = struct.pack(">I", len(encrypted)) + encrypted
    sock.sendall(frame)

def read_encrypted(sock: socket.socket) -> str:
    header = recv_exact(sock, 4)
    frame_size = struct.unpack(">I", header)[0]

    if frame_size <= 0 or frame_size > MAX_FRAME_SIZE:
        raise ProtocolError(f"Invalid frame size: {frame_size}")

    encrypted_payload = recv_exact(sock, frame_size)
    return decrypt_message(encrypted_payload)

def protocol_display_and_key(raw_message: str) -> tuple[str, str, str]:
    """
    Convert server protocol message to:
    - display text
    - visual tag
    - stable duplicate key

    The duplicate key is based on the protocol content, not the receiver session.
    This is what prevents duplicate lines in a GUI that owns many sessions.
    """
    if "|" not in raw_message:
        display = raw_message.strip()
        return display, "normal", f"raw:{display.lower()}"

    message_type, content = raw_message.split("|", 1)
    message_type = message_type.upper()

    if message_type in ("CHAT", "MESSAGE"):
        parts = content.split("|", 1)
        if len(parts) == 2:
            sender, message = parts
            display = f"[{sender}] {message}"
            return display, "normal", f"chat:{sender}:{message}".lower()
        return content, "normal", f"chat:{content}".lower()

    if message_type == "PRIVATE":
        parts = content.split("|", 1)
        if len(parts) == 2:
            sender, message = parts
            display = f"[private from {sender}] {message}"
            return display, "private", f"private:{sender}:{message}".lower()
        return content, "private", f"private:{content}".lower()

    if message_type == "BROADCAST":
        parts = content.split("|", 1)
        if len(parts) == 2:
            sender, message = parts
            display = f"[broadcast from {sender}] {message}"
            return display, "broadcast", f"broadcast:{sender}:{message}".lower()
        display = f"[broadcast] {content}"
        return display, "broadcast", f"broadcast:{content}".lower()

    if message_type == "SYSTEM":
        display = f"[system] {content}"
        return display, "system", f"system:{content}".lower()

    if message_type == "ERROR":
        display = f"[error] {content}"
        return display, "error", f"error:{content}".lower()

    if message_type == "ALERT":
        display = f"[iot alert] {content}"
        return display, "alert", f"alert:{content}".lower()

    if message_type == "AUTH_OK":
        display = f"[auth] {content}"
        return display, "system", f"auth_ok:{content}".lower()

    if message_type == "AUTH_FAIL":
        display = f"[auth failed] {content}"
        return display, "error", f"auth_fail:{content}".lower()

    display = raw_message.strip()
    return display, "normal", f"unknown:{display}".lower()

def parse_user_input(user_input: str) -> tuple[str, str | None]:
    text = user_input.strip()

    if not text:
        return "", None

    if text == "/help":
        return "", HELP_TEXT

    if text == "/users":
        return "USERS|", None

    if text == "/devices":
        return "DEVICES|", None

    if text == "/status":
        return "STATUS|", None

    if text == "/quit":
        return "QUIT|", None

    if text.startswith("/kick "):
        target = text[len("/kick ") :].strip()
        return f"KICK|{target}", None

    if text.startswith("/broadcast "):
        message = text[len("/broadcast ") :].strip()
        return f"BROADCAST|{message}", None

    if text.startswith("/whisper "):
        remainder = text[len("/whisper ") :].strip()
        parts = remainder.split(" ", 1)
        if len(parts) != 2:
            return "", "Usage: /whisper username message"
        target, message = parts
        return f"WHISPER|{target}|{message}", None

    if text.startswith("/sensor "):
        remainder = text[len("/sensor ") :].strip()
        parts = remainder.split(" ", 1)
        if len(parts) != 2:
            return "", "Usage: /sensor metric value"
        metric, value = parts
        return f"SENSOR|{metric}|{value}", None

    return f"MESSAGE|{text}", None

class ClientSession:
    def __init__(self, app: "ChatRoomGuiModern", username: str, role: str, sock: socket.socket) -> None:
        self.app = app
        self.username = username
        self.role = role
        self.sock: socket.socket | None = sock
        self.socket_lock = threading.Lock()
        self.connected = True
        self.receiver_thread = threading.Thread(target=self.receiver_loop, daemon=True)
        self.receiver_thread.start()

    def receiver_loop(self) -> None:
        while self.connected and self.sock is not None:
            try:
                raw = read_encrypted(self.sock)
                self.app.ui_queue.put(("server_message", self.username, raw))

                if raw.startswith("SYSTEM|You have been kicked out"):
                    self.close_socket_only()
                    self.connected = False
                    self.app.ui_queue.put(("session_closed", self.username, "Kicked by server."))
                    return

            except Exception as exc:
                if self.connected:
                    self.app.ui_queue.put(("session_closed", self.username, str(exc)))
                self.close_socket_only()
                self.connected = False
                return

    def send(self, protocol_message: str) -> None:
        if not self.connected or self.sock is None:
            raise ConnectionError(f"{self.username} is not connected.")

        with self.socket_lock:
            if self.sock is None:
                raise ConnectionError(f"{self.username} socket is closed.")
            send_encrypted(self.sock, protocol_message)

    def close_socket_only(self) -> None:
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        self.sock = None

    def disconnect(self, send_quit: bool = True) -> None:
        if self.connected and send_quit and self.sock is not None:
            try:
                self.send("QUIT|")
            except Exception:
                pass
        self.close_socket_only()
        self.connected = False

class ChatRoomGuiPolished(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        self.title("LTH Chat Room v1.1")
        self.geometry("1360x820")
        self.minsize(1120, 700)

        self.sessions: dict[str, ClientSession] = {}
        self.ui_queue: queue.Queue[tuple] = queue.Queue()

        # Holds stable message keys shown in the chat timeline.
        self.displayed_keys: dict[str, float] = {}

        # Extra safety net: prevents the exact same visible line being appended
        # twice within a very short time window, even if it bypasses append_chat_once.
        self.visible_line_keys: dict[str, float] = {}

        # Prevent accidental double sends from Return/click/event repetition.
        self.last_send_signature = ""
        self.last_send_time = 0.0

        self.server_process: subprocess.Popen | None = None
        self.server_reader_thread: threading.Thread | None = None
        self.server_listening_announced = False
        self.dashboard_announced = False
        self.server_error_announced = False

        self._configure_theme()
        self._build_ui()

        self.after(100, self.process_ui_queue)
        self.after(6000, self.auto_refresh_sidebar)

        # Hidden development shortcut: Cmd/Ctrl+Shift+A connects all demo users.
        self.bind("<Command-Shift-A>", lambda _event: self.connect_all_demo_users())
        self.bind("<Control-Shift-A>", lambda _event: self.connect_all_demo_users())

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # UI setup

    def _configure_theme(self) -> None:
        self.colors = {
            "bg": "#07111f",
            "top": "#0b1220",
            "panel": "#0f172a",
            "panel_2": "#111827",
            "surface": "#020617",
            "border": "#1e293b",
            "text": "#e5e7eb",
            "muted": "#94a3b8",
            "accent": "#38bdf8",
            "accent_2": "#2563eb",
        }

        self.configure(bg=self.colors["bg"])
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=self.colors["bg"])
        style.configure("Top.TFrame", background=self.colors["top"])
        style.configure("Panel.TFrame", background=self.colors["panel"])
        style.configure("Panel2.TFrame", background=self.colors["panel_2"])
        style.configure("Card.TFrame", background=self.colors["panel"], relief="flat")
        style.configure("Sidebar.TFrame", background=self.colors["panel_2"])

        style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["text"])
        style.configure("Panel.TLabel", background=self.colors["panel"], foreground=self.colors["text"])
        style.configure("Panel2.TLabel", background=self.colors["panel_2"], foreground=self.colors["text"])
        style.configure("Title.TLabel", background=self.colors["top"], foreground="#ffffff", font=("Helvetica", 22, "bold"))
        style.configure("Subtitle.TLabel", background=self.colors["top"], foreground=self.colors["muted"], font=("Helvetica", 12))
        style.configure("Section.TLabel", background=self.colors["panel"], foreground="#ffffff", font=("Helvetica", 13, "bold"))
        style.configure("SidebarSection.TLabel", background=self.colors["panel_2"], foreground="#ffffff", font=("Helvetica", 13, "bold"))
        style.configure("Muted.TLabel", background=self.colors["bg"], foreground=self.colors["muted"])
        style.configure("PanelMuted.TLabel", background=self.colors["panel"], foreground=self.colors["muted"])
        style.configure("Panel2Muted.TLabel", background=self.colors["panel_2"], foreground=self.colors["muted"])
        style.configure("Status.TLabel", background=self.colors["top"], foreground=self.colors["accent"], font=("Helvetica", 11, "bold"))

        style.configure("TButton", padding=(10, 7), font=("Helvetica", 11))
        style.configure("Primary.TButton", padding=(12, 8), font=("Helvetica", 11, "bold"))
        style.configure("Ghost.TButton", padding=(10, 7), font=("Helvetica", 11))
        style.configure("Danger.TButton", padding=(10, 7), font=("Helvetica", 11, "bold"))

        style.configure(
            "TCombobox",
            padding=6,
            fieldbackground=self.colors["surface"],
            background=self.colors["surface"],
            foreground=self.colors["text"],
            arrowcolor=self.colors["accent"],
        )
        style.map("TCombobox", fieldbackground=[("readonly", self.colors["surface"])])

        style.configure(
            "TEntry",
            padding=7,
            fieldbackground=self.colors["surface"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
            insertcolor=self.colors["text"],
        )

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = ttk.Frame(self, style="Top.TFrame", padding=(22, 18, 22, 16))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        title_box = ttk.Frame(header, style="Top.TFrame")
        title_box.grid(row=0, column=0, sticky="w")
        ttk.Label(title_box, text="Welcome Ladies and Gentlemen", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            title_box,
            text="Connect and enjoy the LTH Experience!",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(3, 0))

        server_controls = ttk.Frame(header, style="Top.TFrame")
        server_controls.grid(row=0, column=1, sticky="e")
        ttk.Button(server_controls, text="Start Server", style="Primary.TButton", command=self.start_local_server).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Button(server_controls, text="Stop Server", style="Ghost.TButton", command=self.stop_local_server).grid(
            row=0, column=1, padx=(0, 12)
        )
        self.server_status_var = tk.StringVar(value=f"Server: {HOST}:{PORT}")
        ttk.Label(server_controls, textvariable=self.server_status_var, style="Status.TLabel").grid(row=0, column=2)

        main = ttk.Frame(self, style="TFrame", padding=(18, 18, 18, 18))
        main.grid(row=1, column=0, sticky="nsew")
        main.columnconfigure(0, weight=4)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        left = ttk.Frame(main, style="Card.TFrame", padding=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(2, weight=1)

        right = ttk.Frame(main, style="Sidebar.TFrame", padding=16)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        right.rowconfigure(3, weight=1)

        self._build_connection_panel(left)
        self._build_chat_panel(left)
        self._build_right_sidebar(right)

        self.status_bar_var = tk.StringVar(value="Ready")
        status = ttk.Label(self, textvariable=self.status_bar_var, style="Muted.TLabel", anchor="w")
        status.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 8))

    def _build_connection_panel(self, parent: ttk.Frame) -> None:
        panel = ttk.Frame(parent, style="Panel.TFrame", padding=14)
        panel.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        panel.columnconfigure(1, weight=1)
        panel.columnconfigure(2, weight=1)
        panel.columnconfigure(3, weight=1)

        ttk.Label(panel, text="Connect user", style="Section.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 14))

        self.demo_var = tk.StringVar(value="sauron (admin)")
        demo_box = ttk.Combobox(
            panel,
            textvariable=self.demo_var,
            values=tuple(DEMO_ACCOUNTS.keys()),
            state="readonly",
            width=22,
        )
        demo_box.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        demo_box.bind("<<ComboboxSelected>>", lambda _event: self.fill_demo_account())

        self.username_var = tk.StringVar()
        ttk.Entry(panel, textvariable=self.username_var, width=18).grid(row=0, column=2, sticky="ew", padx=(0, 10))

        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(panel, textvariable=self.password_var, show="*", width=18)
        password_entry.grid(row=0, column=3, sticky="ew", padx=(0, 10))
        password_entry.bind("<Return>", lambda _event: self.connect_selected_user())

        ttk.Button(panel, text="Connect", style="Primary.TButton", command=self.connect_selected_user).grid(row=0, column=4)

        self.fill_demo_account()

    def _build_chat_panel(self, parent: ttk.Frame) -> None:
        chat_frame = ttk.Frame(parent, style="Panel.TFrame", padding=14)
        chat_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        chat_frame.columnconfigure(2, weight=1)

        ttk.Label(chat_frame, text="Conversation", style="Section.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 16))

        ttk.Label(chat_frame, text="Send as", style="PanelMuted.TLabel").grid(row=0, column=1, sticky="e", padx=(0, 8))
        self.send_as_var = tk.StringVar()
        self.send_as_combo = ttk.Combobox(chat_frame, textvariable=self.send_as_var, state="readonly", width=18)
        self.send_as_combo.grid(row=0, column=2, sticky="w", padx=(0, 14))

        ttk.Button(chat_frame, text="Help", style="Ghost.TButton", command=lambda: self.append_chat(HELP_TEXT, "system")).grid(
            row=0, column=3
        )

        self.chat_box = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            state="disabled",
            bg=self.colors["surface"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Menlo", 13),
            padx=18,
            pady=16,
        )
        self.chat_box.grid(row=2, column=0, sticky="nsew")

        self.chat_box.tag_configure("time", foreground="#64748b", font=("Menlo", 11))
        self.chat_box.tag_configure("normal", foreground="#e5e7eb", spacing3=6)
        self.chat_box.tag_configure("system", foreground="#7dd3fc", spacing3=6)
        self.chat_box.tag_configure("error", foreground="#fca5a5", spacing3=6)
        self.chat_box.tag_configure("alert", foreground="#fde68a", font=("Menlo", 13, "bold"), spacing3=8)
        self.chat_box.tag_configure("private", foreground="#c4b5fd", spacing3=6)
        self.chat_box.tag_configure("broadcast", foreground="#86efac", font=("Menlo", 13, "bold"), spacing3=8)
        self.chat_box.tag_configure("server", foreground="#94a3b8", spacing3=6)

        input_row = ttk.Frame(parent, style="Panel.TFrame", padding=14)
        input_row.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        input_row.columnconfigure(0, weight=1)

        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(input_row, textvariable=self.message_var, font=("Helvetica", 13))
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10), ipady=4)
        self.message_entry.bind("<Return>", lambda _event: self.send_chat_message())

        ttk.Button(input_row, text="Send Message", style="Primary.TButton", command=self.send_chat_message).grid(row=0, column=1)

        self.append_chat("Chat ready. Start the server, connect a user, then select who sends each message.", "system")

    def _build_right_sidebar(self, parent: ttk.Frame) -> None:
        users_header = ttk.Frame(parent, style="Sidebar.TFrame")
        users_header.grid(row=0, column=0, sticky="ew")
        users_header.columnconfigure(0, weight=1)
        ttk.Label(users_header, text="Online users", style="SidebarSection.TLabel").grid(row=0, column=0, sticky="w")
        self.online_count_var = tk.StringVar(value="0")
        ttk.Label(users_header, textvariable=self.online_count_var, style="Panel2Muted.TLabel").grid(row=0, column=1, sticky="e")

        self.users_listbox = tk.Listbox(
            parent,
            height=9,
            bg=self.colors["surface"],
            fg=self.colors["text"],
            selectbackground=self.colors["accent_2"],
            selectforeground="#ffffff",
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            font=("Menlo", 12),
            activestyle="none",
        )
        self.users_listbox.grid(row=1, column=0, sticky="nsew", pady=(8, 10))

        devices_header = ttk.Frame(parent, style="Sidebar.TFrame")
        devices_header.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        devices_header.columnconfigure(0, weight=1)
        ttk.Label(devices_header, text="IoT devices", style="SidebarSection.TLabel").grid(row=0, column=0, sticky="w")
        self.device_count_var = tk.StringVar(value="0")
        ttk.Label(devices_header, textvariable=self.device_count_var, style="Panel2Muted.TLabel").grid(row=0, column=1, sticky="e")

        self.devices_listbox = tk.Listbox(
            parent,
            height=9,
            bg=self.colors["surface"],
            fg=self.colors["text"],
            selectbackground=self.colors["accent_2"],
            selectforeground="#ffffff",
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            font=("Menlo", 12),
            activestyle="none",
        )
        self.devices_listbox.grid(row=3, column=0, sticky="nsew", pady=(8, 10))

        tools = ttk.Frame(parent, style="Panel2.TFrame", padding=12)
        tools.grid(row=4, column=0, sticky="ew", pady=(14, 0))
        tools.columnconfigure(0, weight=1)

        ttk.Label(tools, text="Control panel", style="Panel2.TLabel", font=("Helvetica", 13, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(tools, text="Admin actions and IoT readings", style="Panel2Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 8))

        self.broadcast_var = tk.StringVar(value="Admin broadcast message")
        ttk.Entry(tools, textvariable=self.broadcast_var).grid(row=2, column=0, sticky="ew", pady=(4, 5))
        ttk.Button(tools, text="Broadcast", style="Primary.TButton", command=self.broadcast_from_selected).grid(
            row=3, column=0, sticky="ew", pady=(0, 10)
        )

        self.kick_var = tk.StringVar(value="frodo")
        ttk.Entry(tools, textvariable=self.kick_var).grid(row=4, column=0, sticky="ew", pady=(4, 5))
        ttk.Button(tools, text="Kick selected name", style="Danger.TButton", command=self.kick_from_selected).grid(
            row=5, column=0, sticky="ew", pady=(0, 12)
        )

        ttk.Label(tools, text="Sensor reading", style="Panel2Muted.TLabel").grid(row=6, column=0, sticky="w")
        self.metric_var = tk.StringVar(value="temperature")
        ttk.Combobox(
            tools,
            textvariable=self.metric_var,
            values=("temperature", "humidity", "motion", "light"),
            state="readonly",
        ).grid(row=7, column=0, sticky="ew", pady=(5, 5))
        self.sensor_value_var = tk.StringVar(value="36.5")
        ttk.Entry(tools, textvariable=self.sensor_value_var).grid(row=8, column=0, sticky="ew", pady=(0, 5))
        ttk.Button(tools, text="Send sensor reading", style="Primary.TButton", command=self.sensor_from_selected).grid(
            row=9, column=0, sticky="ew", pady=(0, 12)
        )

    # Server controls

    def start_local_server(self) -> None:
        if self.server_process is not None and self.server_process.poll() is None:
            messagebox.showinfo("Server", "Server is already running from this GUI.")
            return

        if is_port_open(HOST, PORT):
            self.server_status_var.set(f"Server: already running on {HOST}:{PORT}")
            # Do not spam the chat. This is an operational status, not a conversation event.
            return

        server_path = BASE_DIR / "Server.py"
        if not server_path.exists():
            messagebox.showerror("Server", "Server.py was not found in this folder.")
            return

        try:
            server_env = os.environ.copy()
            server_env["PYTHONWARNINGS"] = "ignore"
            self.server_process = subprocess.Popen(
                [sys.executable, str(server_path)],
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=server_env,
            )
            self.server_status_var.set("Server: starting...")
            self.append_chat("[server] Starting local server...", "server")
            self.server_reader_thread = threading.Thread(target=self.read_server_output, daemon=True)
            self.server_reader_thread.start()
        except Exception as exc:
            messagebox.showerror("Server", f"Could not start server: {exc}")

    def read_server_output(self) -> None:
        process = self.server_process
        if process is None or process.stdout is None:
            return

        for line in process.stdout:
            self.ui_queue.put(("server_output", line.rstrip()))

        code = process.poll()
        self.ui_queue.put(("server_output", f"Server process stopped with code {code}."))

    def stop_local_server(self) -> None:
        self.disconnect_all_sessions()

        if self.server_process is not None and self.server_process.poll() is None:
            self.server_process.terminate()
            self.server_process = None
            self.server_status_var.set("Server: stopped")
            self.server_listening_announced = False
            self.dashboard_announced = False
            self.server_error_announced = False
            self.append_chat("[server] Server stopped.", "server")
            return

        self.server_status_var.set("Server: no GUI-owned server")
        messagebox.showinfo(
            "Server",
            "This GUI did not start the current server. If a server is still running, stop it from the terminal that started it.",
        )

    def handle_server_output_line(self, line: str) -> None:
        lower = line.lower()

        if "server listening on" in lower:
            self.server_error_announced = False
            self.server_status_var.set(f"Server: running on {HOST}:{PORT}")
            if not self.server_listening_announced:
                self.server_listening_announced = True
                self.append_chat(f"[server] Server started on {HOST}:{PORT}.", "server")
            return

        if "dashboard available at" in lower:
            if not self.dashboard_announced:
                self.dashboard_announced = True
                self.append_chat(f"Dashboard available at http://{DASHBOARD_HOST}:{DASHBOARD_PORT}", "server")
            return

        if "address already in use" in lower:
            if not self.server_error_announced:
                self.server_error_announced = True
                self.append_chat("[server] Port is already in use. A server is probably already running.", "error")
            return

        if "traceback" in lower or "error while attempting" in lower:
            if not self.server_error_announced:
                self.server_error_announced = True
                self.append_chat("[server] Server error. Check the VS Code terminal for details.", "error")
            return

        if "server process stopped" in lower:
            self.server_status_var.set("Server: stopped")
            self.server_listening_announced = False
            self.dashboard_announced = False
            self.server_error_announced = False
            return

        return

    # Connection management

    def fill_demo_account(self) -> None:
        selected = self.demo_var.get()
        username, password = DEMO_ACCOUNTS.get(selected, ("", ""))
        self.username_var.set(username)
        self.password_var.set(password)

    def connect_selected_user(self) -> None:
        username = self.username_var.get().strip()
        password = self.password_var.get()
        if not username or not password:
            messagebox.showerror("Connect user", "Username and password are required.")
            return
        self.connect_user(username, password)

    def connect_all_demo_users(self) -> None:
        for username, password in DEMO_ACCOUNTS.values():
            if username not in self.sessions:
                self.connect_user(username, password, show_errors=False)

        self.refresh_sender_combo()
        self.refresh_user_list_from_sessions()
        self.send_silent_refresh()

    def connect_user(self, username: str, password: str, show_errors: bool = True) -> bool:
        if username in self.sessions and self.sessions[username].connected:
            if show_errors:
                messagebox.showwarning("Already connected", f"{username} is already connected in this GUI.")
            return False

        try:
            sock = socket.create_connection((HOST, PORT), timeout=6)
            sock.settimeout(None)
            send_encrypted(sock, f"AUTH|{username}|{password}")
            response = read_encrypted(sock)
        except Exception as exc:
            try:
                sock.close()  # type: ignore[name-defined]
            except Exception:
                pass
            if show_errors:
                messagebox.showerror("Connection failed", str(exc))
            else:
                self.append_chat(f"[error] Could not connect {username}: {exc}", "error")
            return False

        if not response.startswith("AUTH_OK|"):
            try:
                sock.close()
            except Exception:
                pass
            display, _, _ = protocol_display_and_key(response)
            if show_errors:
                messagebox.showerror("Authentication failed", display)
            else:
                self.append_chat(f"[error] Could not connect {username}: {display}", "error")
            return False

        parts = response.split("|", 2)
        role = parts[1] if len(parts) > 1 else "unknown"

        self.sessions[username] = ClientSession(self, username=username, role=role, sock=sock)
        self.refresh_sender_combo()
        self.refresh_user_list_from_sessions()
        self.send_silent_refresh()
        return True

    def refresh_sender_combo(self) -> None:
        usernames = sorted([username for username, session in self.sessions.items() if session.connected])
        self.send_as_combo.configure(values=usernames)

        if usernames and self.send_as_var.get() not in usernames:
            self.send_as_var.set(usernames[0])
        elif not usernames:
            self.send_as_var.set("")

        selected = self.send_as_var.get() or "none"
        self.status_bar_var.set(f"Connected users: {len(usernames)} · Send as: {selected}")

    def refresh_user_list_from_sessions(self) -> None:
        self.users_listbox.delete(0, tk.END)
        connected_count = 0
        for username, session in sorted(self.sessions.items()):
            if session.connected:
                connected_count += 1
                self.users_listbox.insert(tk.END, f"● {username}  ·  {session.role}")

        self.online_count_var.set(str(connected_count))

    def disconnect_selected_session(self) -> None:
        username = self.send_as_var.get().strip()
        if not username:
            messagebox.showwarning("Disconnect", "No selected connected user.")
            return

        session = self.sessions.get(username)
        if not session:
            return

        session.disconnect(send_quit=True)
        self.sessions.pop(username, None)
        self.append_chat(f"[system] {username} disconnected.", "system")
        self.refresh_sender_combo()
        self.refresh_user_list_from_sessions()

    def disconnect_all_sessions(self) -> None:
        for username, session in list(self.sessions.items()):
            session.disconnect(send_quit=True)
        self.sessions.clear()
        self.refresh_sender_combo()
        self.refresh_user_list_from_sessions()
        self.devices_listbox.delete(0, tk.END)
        self.device_count_var.set("0")

    # Sending

    def get_selected_session(self) -> ClientSession | None:
        username = self.send_as_var.get().strip()
        if not username:
            messagebox.showwarning("Send message", "Connect a user first, then choose 'Send as'.")
            return None

        session = self.sessions.get(username)
        if not session or not session.connected:
            messagebox.showwarning("Send message", f"{username} is not connected.")
            return None

        return session

    def send_chat_message(self) -> None:
        text = self.message_var.get().strip()
        if not text:
            return

        sender = self.send_as_var.get().strip()
        now = time.time()
        signature = f"{sender}:{text}".lower()

        # Some systems can trigger the send handler twice very quickly
        # through Return/click focus behaviour. Ignore immediate repeats.
        if signature == self.last_send_signature and now - self.last_send_time < 1.0:
            return

        self.last_send_signature = signature
        self.last_send_time = now

        # Clear before sending so a second UI event cannot resend the same text.
        self.message_var.set("")
        self.send_text_from_selected(text)

    def send_command_from_selected(self, command: str) -> None:
        self.send_text_from_selected(command)

    def send_text_from_selected(self, text: str) -> None:
        session = self.get_selected_session()
        if session is None:
            return

        protocol_message, local_message = parse_user_input(text)

        if local_message:
            self.append_chat(local_message, "system")
            return

        if not protocol_message:
            return

        try:
            session.send(protocol_message)

            # Normal chat messages from users inside this GUI are displayed
            # immediately here. Any server copies from the same internal sender
            # are ignored in handle_server_message().
            if protocol_message.startswith("MESSAGE|"):
                display = f"[{session.username}] {text}"
                self.append_chat_once(display, "normal", f"chat:{session.username}:{text}".lower())

            if protocol_message == "QUIT|":
                self.sessions.pop(session.username, None)
                session.disconnect(send_quit=False)
                self.refresh_sender_combo()
                self.refresh_user_list_from_sessions()

        except Exception as exc:
            self.append_chat(f"[error] Could not send as {session.username}: {exc}", "error")

    def broadcast_from_selected(self) -> None:
        message = self.broadcast_var.get().strip()
        if message:
            self.send_text_from_selected(f"/broadcast {message}")

    def kick_from_selected(self) -> None:
        target = self.kick_var.get().strip()
        if target:
            self.send_text_from_selected(f"/kick {target}")

    def sensor_from_selected(self) -> None:
        metric = self.metric_var.get().strip()
        value = self.sensor_value_var.get().strip()
        if metric and value:
            self.send_text_from_selected(f"/sensor {metric} {value}")

    def send_silent_refresh(self) -> None:
        for session in self.sessions.values():
            if session.connected:
                try:
                    session.send("USERS|")
                    session.send("DEVICES|")
                except Exception:
                    pass
                return

    def auto_refresh_sidebar(self) -> None:
        if self.sessions:
            self.send_silent_refresh()
        self.after(6000, self.auto_refresh_sidebar)

    # Incoming processing

    def process_ui_queue(self) -> None:
        try:
            while True:
                item = self.ui_queue.get_nowait()
                event_type = item[0]

                if event_type == "server_message":
                    _, receiver_username, raw = item
                    self.handle_server_message(receiver_username, raw)

                elif event_type == "session_closed":
                    _, username, reason = item
                    self.handle_session_closed(username, reason)

                elif event_type == "server_output":
                    _, line = item
                    if line:
                        self.handle_server_output_line(line)

        except queue.Empty:
            pass

        self.after(100, self.process_ui_queue)

    def handle_server_message(self, receiver_username: str, raw: str) -> None:
        display, tag, key = protocol_display_and_key(raw)

        # Sidebar-only updates.
        if raw.startswith("SYSTEM|Online users:"):
            self.update_online_users_from_message(raw)
            return

        if raw.startswith("SYSTEM|IoT devices:"):
            self.update_devices_from_message(raw)
            return

        # Critical duplicate fix:
        # In this single GUI, many users are connected internally. When one of
        # those users sends a normal chat message, the server returns that same
        # message through the other internal sessions. We show internal chat
        # messages locally on send, so server copies from internal senders are
        # always ignored.
        if raw.startswith("CHAT|"):
            parts = raw.split("|", 2)
            if len(parts) >= 3:
                sender = parts[1]
                if sender in self.sessions:
                    return

        # Defensive support for alternative protocol naming.
        if raw.startswith("MESSAGE|"):
            parts = raw.split("|", 2)
            if len(parts) >= 3:
                sender = parts[1]
                if sender in self.sessions:
                    return

        if not self.should_show_in_chat(raw, display):
            return

        self.append_chat_once(display, tag, key)

    def should_show_in_chat(self, raw: str, display: str) -> bool:
        if raw.startswith(("CHAT|", "PRIVATE|", "BROADCAST|", "ALERT|", "ERROR|")):
            return True

        if raw.startswith("AUTH_OK|"):
            return False

        if raw.startswith("SYSTEM|"):
            lower = display.lower()

            hidden_phrases = (
                "welcome ",
                "server status:",
                "online users:",
                "iot devices:",
                "no iot devices online",
                "type /help",
            )
            if any(phrase in lower for phrase in hidden_phrases):
                return False

            visible_phrases = (
                "joined the chat",
                "left the chat",
                "has been kicked",
                "was kicked successfully",
                "you have been kicked",
            )
            return any(phrase in lower for phrase in visible_phrases)

        return False

    def handle_session_closed(self, username: str, reason: str) -> None:
        session = self.sessions.pop(username, None)
        if session:
            session.disconnect(send_quit=False)

        if "Connection closed by server" not in reason:
            self.append_chat(f"[system] {username} disconnected: {reason}", "system")
        else:
            self.append_chat(f"[system] {username} disconnected.", "system")

        self.refresh_sender_combo()
        self.refresh_user_list_from_sessions()

    def append_chat_once(self, text: str, tag: str, key: str) -> None:
        now = time.time()
        normalized_key = " ".join(key.strip().split()).lower()

        for old_key, timestamp in list(self.displayed_keys.items()):
            if now - timestamp > 30:
                self.displayed_keys.pop(old_key, None)

        if normalized_key in self.displayed_keys:
            return

        self.displayed_keys[normalized_key] = now
        self.append_chat(text, tag)

    def append_chat(self, text: str, tag: str = "normal") -> None:
        self.chat_box.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S")
        now = time.time()

        # Remove old visible-line fingerprints.
        for old_key, old_time in list(self.visible_line_keys.items()):
            if now - old_time > 10.0:
                self.visible_line_keys.pop(old_key, None)

        inserted_anything = False

        for line in text.splitlines() or [""]:
            visible_key = f"{tag}:{' '.join(line.strip().split()).lower()}"

            # Final duplicate shield. This catches duplicate lines even if they
            # come from two different receiver threads almost at the same time.
            if visible_key in self.visible_line_keys:
                continue

            self.visible_line_keys[visible_key] = now
            self.chat_box.insert(tk.END, f"{timestamp}  ", "time")
            self.chat_box.insert(tk.END, line + "\n", tag)
            inserted_anything = True

        self.chat_box.configure(state="disabled")
        if inserted_anything:
            self.chat_box.see(tk.END)

    # Sidebar parsing

    def update_online_users_from_message(self, raw: str) -> None:
        content = raw.split("|", 1)[1]
        prefix = "Online users:"
        if prefix not in content:
            return

        payload = content.split(prefix, 1)[1].strip()
        if not payload or payload.lower().startswith("none"):
            self.users_listbox.delete(0, tk.END)
            self.online_count_var.set("0")
            return

        entries = [entry.strip() for entry in payload.split("),")]
        cleaned: list[str] = []
        for entry in entries:
            if entry and not entry.endswith(")"):
                entry += ")"
            if entry:
                cleaned.append(entry)

        self.users_listbox.delete(0, tk.END)
        for entry in cleaned:
            self.users_listbox.insert(tk.END, f"● {entry}")
        self.online_count_var.set(str(len(cleaned)))

    def update_devices_from_message(self, raw: str) -> None:
        content = raw.split("|", 1)[1]
        prefix = "IoT devices:"
        if prefix not in content:
            return

        payload = content.split(prefix, 1)[1].strip()
        self.devices_listbox.delete(0, tk.END)

        if not payload or payload.lower().startswith("none"):
            self.device_count_var.set("0")
            return

        entries = [entry.strip() for entry in payload.split(",")]
        device_count = 0
        for entry in entries:
            if entry:
                device_count += 1
                self.devices_listbox.insert(tk.END, f"◆ {entry}")
        self.device_count_var.set(str(device_count))

    def on_close(self) -> None:
        self.disconnect_all_sessions()

        if self.server_process is not None and self.server_process.poll() is None:
            try:
                self.server_process.terminate()
            except Exception:
                pass

        self.destroy()

if __name__ == "__main__":
    app = ChatRoomGuiPolished()
    app.mainloop()
