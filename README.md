# Enhanced IoT Chat System

A secure asynchronous client-server chat application in Python, upgraded into a small IoT communication prototype. The project supports encrypted messaging, role-based access control, external user management, IoT sensor readings, audit logging and a lightweight browser dashboard for monitoring connected clients and device telemetry.

This version is an enhanced implementation of the original coursework chat project. The aim is to demonstrate networking, authentication, authorization, encryption, audit logging and IoT-style communication in one compact Python project.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Main Features](#main-features)
- [Technologies Used](#technologies-used)
- [Project Structure](#project-structure)
- [How the System Works](#how-the-system-works)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Project](#running-the-project)
- [Demo Accounts](#demo-accounts)
- [Available Commands](#available-commands)
- [IoT Functionality](#iot-functionality)
- [Dashboard](#dashboard)
- [Security Features](#security-features)
- [Audit Logging](#audit-logging)
- [Example Demo Scenario](#example-demo-scenario)
- [How to Add a New User](#how-to-add-a-new-user)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Academic Notes](#academic-notes)

---

## Project Overview

The Enhanced IoT Chat System is a Python-based application where multiple clients connect to a central server and exchange encrypted messages. The server manages authentication, connected users, IoT devices, private messages, admin commands and sensor readings.

The system can be used as a prototype for secure IoT communication. For example, a normal user can send chat messages, an admin can monitor or manage users, and a simulated IoT device can send telemetry such as temperature, humidity or motion readings.

The project runs locally by default using:

```text
Host: 127.0.0.1
Port: 65432
Dashboard: http://127.0.0.1:8080
```

---

## Main Features

| Feature | Description |
|---|---|
| Asynchronous server | Uses `asyncio` to handle multiple clients at the same time. |
| Encrypted communication | Messages are encrypted using AES before being sent over the network. |
| Message framing | Each encrypted message is sent with a length prefix to avoid TCP read issues. |
| External users file | User accounts are stored in `users.json` instead of being hardcoded in the server. |
| Salted password hashing | Passwords use PBKDF2 with salt instead of plain SHA-256. |
| Role-based access control | Different permissions exist for `admin`, `user` and `device` roles. |
| Admin commands | Admins can broadcast messages and kick connected users. |
| Private messages | Users can send direct messages with `/whisper`. |
| IoT telemetry | Device accounts can send sensor readings with `/sensor`. |
| IoT alerts | The server broadcasts alerts when readings exceed configured thresholds. |
| Audit log file | Important events are saved in `logs/audit.log`. |
| Web dashboard | A small browser dashboard displays connected clients, sensor readings and logs. |
| `.env` configuration | Host, port, shared secret and dashboard settings can be configured externally. |

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Main programming language. |
| `asyncio` | Asynchronous networking and concurrent client handling. |
| `cryptography` | AES encryption and decryption. |
| `hashlib` | PBKDF2 password hashing and AES key derivation. |
| `hmac` | Secure comparison of password hashes. |
| `json` | External user database through `users.json`. |
| `logging` | Audit logging to file and console. |
| HTML/CSS | Lightweight built-in monitoring dashboard. |

---

## Project Structure

```text
Enhanced-IoT-Chat/
│
├── Server.py              # Main asynchronous encrypted server
├── Client.py              # Terminal-based encrypted chat client
├── users.json             # External user database with roles and password hashes
├── requirements.txt       # Python dependencies
├── .env.example           # Example environment configuration file
├── README.md              # Full project documentation
├── README_RUN.md          # Short quick-run guide
│
└── logs/                  # Created automatically when the server runs
    └── audit.log          # Audit log file
```

---

## How the System Works

The system follows a client-server architecture.

1. The server starts and listens for incoming TCP connections.
2. A client connects to the server.
3. The client sends login credentials using an encrypted message.
4. The server verifies the username and password using the data stored in `users.json`.
5. If authentication is successful, the server registers the client as online.
6. The client can send chat messages, commands or IoT sensor readings.
7. The server checks whether the user is authorized to perform the requested action.
8. The server processes the action and sends encrypted responses to the appropriate clients.
9. Important events are written to the audit log.
10. The dashboard displays live information about clients, devices, readings and logs.

---

## Installation

### 1. Clone or download the project

If the project is uploaded to GitHub, clone it with:

```bash
git clone https://github.com/your-username/your-repository-name.git
cd your-repository-name
```

Or, if you have the project as a folder, open a terminal inside the project directory.

### 2. Create a virtual environment

macOS/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

Windows PowerShell:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

The current dependency list is:

```text
cryptography>=42.0.0
```

---

## Configuration

The project includes an example environment file:

```text
.env.example
```

To create your local configuration file:

```bash
cp .env.example .env
```

Default configuration:

```env
HOST=127.0.0.1
PORT=65432
SHARED_SECRET=iot-chat-demo-secret
USERS_FILE=users.json
LOG_FILE=logs/audit.log
DASHBOARD_ENABLED=true
DASHBOARD_HOST=127.0.0.1
DASHBOARD_PORT=8080
```

### Important configuration notes

The server and all clients must use the same:

```text
HOST
PORT
SHARED_SECRET
```

The `SHARED_SECRET` is used to derive the AES encryption key. If the server and client use different secrets, messages cannot be decrypted correctly.

For local testing, keep:

```env
HOST=127.0.0.1
```

For testing across different devices on the same network, the server can listen on:

```env
HOST=0.0.0.0
```

Then clients should use the server machine's local IP address instead of `127.0.0.1`.

---

## Running the Project

### 1. Start the server

Open the first terminal:

```bash
python Server.py
```

Expected output:

```text
IoT Chat Server listening on 127.0.0.1:65432
Dashboard available at http://127.0.0.1:8080
```

### 2. Start a client

Open a second terminal:

```bash
python Client.py
```

The client will ask for login details:

```text
Enter your username:
Enter your password:
```

After successful login, you can type messages or commands.

### 3. Start multiple clients

To test the chat properly, open more terminals and run:

```bash
python Client.py
```

Log in with different demo accounts.

---

## Demo Accounts

The project includes demo accounts inside `users.json`.

| Username | Password | Role | Description |
|---|---|---|---|
| `sauron` | `sau123` | `admin` | Admin account with broadcast and kick permissions. |
| `aragorn` | `ara123` | `admin` | Second admin account. |
| `legolas` | `leg123` | `user` | Normal chat user. |
| `gandalf` | `gan123` | `user` | Normal chat user. |
| `frodo` | `fro123` | `user` | Normal chat user. |
| `sensor_01` | `sensor123` | `device` | Simulated IoT device. |
| `sensor_02` | `sensor123` | `device` | Simulated IoT device. |

### Roles

| Role | Permissions |
|---|---|
| `admin` | Chat messages, private messages, users list, devices list, server status, broadcast, kick, sensor readings, quit. |
| `user` | Chat messages, private messages, users list, devices list, server status, quit. |
| `device` | Sensor readings, status, basic messages, quit. |

---

## Available Commands

The client supports the following commands.

| Command | Role | Description |
|---|---|---|
| `/help` | All | Shows the command menu. |
| `/users` | Admin/User | Displays connected users. |
| `/devices` | Admin/User | Displays connected IoT devices and latest readings. |
| `/status` | All | Shows server status and uptime. |
| `/whisper username message` | Admin/User | Sends a private message to a specific user. |
| `/broadcast message` | Admin only | Sends a message to all connected clients. |
| `/kick username` | Admin only | Disconnects a selected user from the server. |
| `/sensor metric value` | Admin/Device | Sends an IoT sensor reading. |
| `/quit` | All | Disconnects from the server. |

Any other text is sent as a normal chat message.

Example normal message:

```text
Hello everyone
```

Example private message:

```text
/whisper frodo Hello Frodo, this is a private message.
```

Example admin broadcast:

```text
/broadcast Server maintenance in 5 minutes.
```

Example kick command:

```text
/kick frodo
```

---

## IoT Functionality

The enhanced version adds simulated IoT behavior. Device accounts such as `sensor_01` and `sensor_02` can send sensor readings to the server.

Example:

```text
/sensor temperature 36.5
```

The server stores the latest reading for that device. If the value exceeds a configured threshold, the server broadcasts an IoT alert.

Default thresholds in `Server.py`:

```python
SENSOR_THRESHOLDS = {
    "temperature": 35.0,
    "humidity": 80.0,
    "motion": 1.0,
}
```

Example readings:

```text
/sensor temperature 24.5
/sensor humidity 72
/sensor motion 1
```

Example alert:

```text
[iot alert] sensor_01 reported high temperature: 36.5 (threshold 35.0)
```

This makes the project more relevant to an IoT scenario, because the clients are not only human chat users. Some clients can act as connected devices that report telemetry to a central server.

---

## Dashboard

The server includes a lightweight browser dashboard.

When the server is running, open:

```text
http://127.0.0.1:8080
```

The dashboard displays:

- Server status
- Connected clients
- User roles
- Client connection duration
- Latest IoT readings
- Audit log tail

The page auto-refreshes every 5 seconds.

This is not a full graphical chat interface. It is a monitoring dashboard that helps demonstrate the state of the system during testing or presentation.

---

## Security Features

### 1. AES encryption

Messages are encrypted before being transmitted between client and server.

The project uses:

```text
AES encryption in CFB mode
Random IV per message
Shared secret based key derivation
```

The AES key is derived from the `SHARED_SECRET` value using SHA-256, which produces a valid 32-byte AES key.

### 2. Message framing

TCP is stream-based, meaning one `read()` does not always equal one full message. To avoid broken or partial messages, this project sends each encrypted message with a 4-byte length prefix.

Message structure:

```text
[4-byte message length][encrypted payload]
```

This makes message handling more reliable.

### 3. PBKDF2 password hashing

User passwords are not stored as plain text. Each account in `users.json` stores:

```text
role
salt
password_hash
iterations
```

The password verification process uses PBKDF2 with SHA-256 and 200,000 iterations.

### 4. Role-based authorization

The server checks whether a user has permission before executing commands such as:

```text
BROADCAST
KICK
SENSOR
USERS
DEVICES
STATUS
```

Unauthorized actions are rejected and logged.

### 5. Audit logging

Security-relevant events are written to a log file, including:

- Successful logins
- Failed login attempts
- User connections
- User disconnections
- Chat messages
- Private messages
- Broadcasts
- Kick actions
- Unauthorized actions
- IoT sensor alerts

---

## Audit Logging

The server writes logs to:

```text
logs/audit.log
```

Example log entries:

```text
2026-05-18 20:15:10 | INFO | User frodo authenticated successfully
2026-05-18 20:15:25 | INFO | User frodo connected from 127.0.0.1:53012
2026-05-18 20:16:02 | INFO | Sensor reading from sensor_01: temperature=36.5
2026-05-18 20:16:02 | WARNING | Alert: sensor_01 reported high temperature: 36.5 (threshold 35.0)
```

The dashboard also displays the latest log entries.

---

## Example Demo Scenario

This is a simple scenario that can be used for a coursework demo or presentation.

### Terminal 1: Start the server

```bash
python Server.py
```

### Terminal 2: Login as admin

```bash
python Client.py
```

Credentials:

```text
Username: sauron
Password: sau123
```

Run:

```text
/status
/users
/devices
```

### Terminal 3: Login as normal user

```bash
python Client.py
```

Credentials:

```text
Username: frodo
Password: fro123
```

Send a message:

```text
Hello, I am connected to the IoT chat server.
```

### Terminal 4: Login as IoT device

```bash
python Client.py
```

Credentials:

```text
Username: sensor_01
Password: sensor123
```

Send a safe reading:

```text
/sensor temperature 24.5
```

Send a high reading:

```text
/sensor temperature 36.5
```

The server should broadcast an IoT alert.

### Browser dashboard

Open:

```text
http://127.0.0.1:8080
```

Check the connected clients, sensor readings and audit log.

---

## How to Add a New User

Users are stored in `users.json`. Each user needs:

- role
- salt
- password hash
- iteration count

Use the following Python snippet to generate a new password record:

```python
import os
import hashlib

password = "newpassword123"
salt = os.urandom(16)
iterations = 200000

password_hash = hashlib.pbkdf2_hmac(
    "sha256",
    password.encode("utf-8"),
    salt,
    iterations,
)

print("salt:", salt.hex())
print("password_hash:", password_hash.hex())
print("iterations:", iterations)
```

Then add the new user to `users.json`:

```json
"new_user": {
  "role": "user",
  "salt": "generated_salt_here",
  "password_hash": "generated_hash_here",
  "iterations": 200000
}
```

Valid roles are:

```text
admin
user
device
```

---

## Troubleshooting

### Problem: `ModuleNotFoundError: No module named 'cryptography'`

Install dependencies:

```bash
pip install -r requirements.txt
```

### Problem: `Could not connect to server`

Make sure the server is running first:

```bash
python Server.py
```

Also check that the client and server use the same host and port.

### Problem: Authentication fails

Check that you are using one of the demo accounts correctly.

Example:

```text
Username: frodo
Password: fro123
```

Also check that `users.json` exists in the same folder as `Server.py`, unless a different path is set in `.env`.

### Problem: Messages cannot be decrypted

Make sure the server and client use the same `SHARED_SECRET` in `.env`.

### Problem: Dashboard does not open

Check that the server is running and that dashboard mode is enabled:

```env
DASHBOARD_ENABLED=true
DASHBOARD_HOST=127.0.0.1
DASHBOARD_PORT=8080
```

Then open:

```text
http://127.0.0.1:8080
```

### Problem: Port already in use

Change the port in `.env`:

```env
PORT=65433
DASHBOARD_PORT=8081
```

Restart the server and clients.

---

## Limitations

This project is designed as an educational prototype. It demonstrates important concepts, but it is not production-ready.

Current limitations include:

- The encryption uses a shared secret, not a full TLS certificate-based setup.
- The dashboard is read-only and basic.
- Users are stored in a JSON file instead of a database.
- There is no graphical chat interface yet.
- There is no MQTT support, which is commonly used in real IoT systems.
- Sensor data is kept in memory and not persisted to a database.
- There are no automated unit tests yet.

---

## Future Improvements

Possible future improvements include:

1. **Full GUI client**
   - Add a Tkinter, PyQt or web-based chat interface.

2. **TLS support**
   - Replace the custom shared-secret encryption approach with TLS.

3. **Database integration**
   - Store users, logs and sensor readings in SQLite or PostgreSQL.

4. **MQTT integration**
   - Add MQTT support to make the system closer to real IoT architecture.

5. **Device registration**
   - Add a secure process for registering new IoT devices.

6. **Persistent telemetry storage**
   - Save sensor readings to a database for later analysis.

7. **Charts in dashboard**
   - Display temperature, humidity and motion data visually.

8. **Automated tests**
   - Add unit tests for authentication, authorization, encryption and command handling.

9. **Docker support**
   - Add a Dockerfile and docker-compose setup for easier deployment.

10. **Improved admin panel**
   - Add dashboard buttons for kicking users, viewing devices and managing logs.

---

## Academic Notes

This project demonstrates several important computer science and cybersecurity concepts:

- Client-server architecture
- Asynchronous programming
- Socket-based communication
- Symmetric encryption
- Password hashing
- Authentication and authorization
- Role-based access control
- Audit logging
- IoT telemetry simulation
- Secure command handling
- Basic monitoring dashboard

For a coursework report, the project can be described as a secure IoT communication prototype where users and simulated IoT devices exchange encrypted messages through a central server. The server acts as the trusted communication hub, handling authentication, permissions, message routing, device telemetry and security monitoring.

---

## Author

Developed as an enhanced academic IoT Chat project by Loukas Theos.

