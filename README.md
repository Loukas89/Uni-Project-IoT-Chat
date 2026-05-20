# IoT Chat

A secure Python-based IoT chat system with encrypted client-server communication, role-based access control, simulated IoT devices, audit logging, and a polished graphical chat room interface.

This project started as a terminal-based secure chat application and has been extended into a more complete IoT communication prototype. It now supports multiple users, admin actions, IoT sensor messages, encrypted communication, and a unified GUI where all connected users can participate in the same shared conversation.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Main Features](#main-features)
- [Latest GUI Update](#latest-gui-update)
- [Technologies Used](#technologies-used)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [How to Run After Forking the Project](#how-to-run-after-forking-the-project)
- [Option 1: Run with the GUI](#option-1-run-with-the-gui)
- [Option 2: Run with Terminal Clients](#option-2-run-with-terminal-clients)
- [Demo Accounts](#demo-accounts)
- [GUI Usage Guide](#gui-usage-guide)
- [Available Chat Commands](#available-chat-commands)
- [IoT Device Functionality](#iot-device-functionality)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Audit Logging](#audit-logging)
- [Troubleshooting](#troubleshooting)
- [Development Notes](#development-not-notes)
- [Future Improvements](#future-improvements)

---

## Project Overview

Enhanced IoT Chat is a Python client-server application designed to demonstrate secure communication between multiple users and IoT-style devices.

The system includes:

- A central asynchronous server.
- Encrypted communication between server and clients.
- User authentication.
- Role-based permissions.
- Admin commands.
- Simulated IoT devices and sensor readings.
- Audit logs.
- A polished graphical interface for shared chat room communication.

The project can be used as a learning project for Python networking, socket programming, asynchronous server design, basic cryptography integration, user authentication, IoT-style device messaging, and GUI development with Tkinter.

---

## Main Features

### Secure Communication

Messages between clients and the server are encrypted using AES-based encryption. The application also uses framed messages so that complete encrypted packets are read correctly over TCP.

### Authentication

Users authenticate with a username and password. User credentials are stored in `users.json` using salted password hashes.

### Role-Based Access Control

| Role     | Description                                                    |
| -------- | -------------------------------------------------------------- |
| `admin`  | Can chat, broadcast messages, kick users, and monitor devices. |
| `user`   | Can participate in normal chat communication.                  |
| `device` | Represents an IoT device and can send sensor readings.         |

### Admin Tools

Admin users can:

- Send broadcast messages.
- Kick connected users.
- View connected users.
- Monitor connected IoT devices.

### IoT Device Simulation

IoT devices can connect as clients and send sensor readings such as temperature, humidity, motion, and light. If a reading exceeds a configured threshold, the server can generate an IoT alert.

---

## Latest GUI Update

The latest version includes a polished unified GUI file:

```text
ChatRoomGUI.py
```

This GUI provides:

- One central chat room.
- One shared conversation area.
- A right sidebar for online users.
- A right sidebar for IoT devices.
- A connection area for users.
- A `Send as` selector.
- Admin tools for broadcast and kick.
- IoT tools for sensor readings.
- Duplicate-message handling.
- Cleaner chat flow without unnecessary debug logs.
- Removed visible clutter buttons such as refresh, disconnect, status, fill, and connect-all controls.

The hidden development shortcut for connecting all demo users is still available:

```text
Cmd + Shift + A
```

or:

```text
Ctrl + Shift + A
```

---

## Technologies Used

| Technology   | Purpose                      |
| ------------ | ---------------------------- |
| Python       | Main programming language    |
| asyncio      | Asynchronous server handling |
| sockets      | Client-server communication  |
| cryptography | AES encryption               |
| hashlib      | Password hashing support     |
| JSON         | User account storage         |
| Tkinter      | GUI application              |
| Git/GitHub   | Version control and hosting  |

---

## Project Structure

```text
Uni-Project-IoT-Chat/
│
├── Server.py
├── Client.py
├── ChatRoomGUI.py
├── users.json
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
│
└── logs/
    └── audit.log
```

| File               | Description                                           |
| ------------------ | ----------------------------------------------------- |
| `Server.py`        | Main secure chat server.                              |
| `Client.py`        | Terminal-based client.                                |
| `ChatRoomGUI.py`   | Polished unified GUI chat room.                       |
| `users.json`       | Stores demo users, roles, salts, and password hashes. |
| `requirements.txt` | Python dependencies.                                  |
| `.env.example`     | Example configuration file.                           |
| `.env`             | Local configuration file, not committed to GitHub.    |
| `logs/audit.log`   | Audit log file generated when the server runs.        |

---

## Requirements

Before running the project, make sure you have:

- Python 3.10 or newer.
- Git.
- pip.
- Tkinter support.

On most macOS Python installations, Tkinter is already included. If the GUI does not open, check your Python installation.

---

## How to Run After Forking the Project

### 1. Clone the repository

If you forked the project, replace `<your-username>` with your GitHub username:

```bash
git clone https://github.com/<your-username>/Uni-Project-IoT-Chat.git
```

Or clone the original repository:

```bash
git clone https://github.com/Loukas89/Uni-Project-IoT-Chat.git
```

### 2. Move into the project folder

```bash
cd Uni-Project-IoT-Chat
```

### 3. Create a virtual environment

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

macOS/Linux:

```bash
python3 -m pip install -r requirements.txt
```

Windows:

```powershell
python -m pip install -r requirements.txt
```

### 5. Create the local `.env` file

macOS/Linux:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

### 6. Check `.env`

A typical `.env` file should look like this:

```env
HOST=127.0.0.1
PORT=65432
DASHBOARD_HOST=127.0.0.1
DASHBOARD_PORT=8080
SECRET_KEY=change_this_32_byte_secret_key
USERS_FILE=users.json
LOG_FILE=logs/audit.log
```

Some versions may use `SHARED_SECRET` instead of `SECRET_KEY`:

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

Use the variable name expected by your current `Server.py` and `ChatRoomGUI.py`.

---

## Option 1: Run with the GUI

The recommended way to run the project is through the GUI.

```bash
python3 ChatRoomGUI.py
```

On Windows:

```powershell
python ChatRoomGUI.py
```

Inside the GUI:

1. Click `Start Server`.
2. Select or type a user.
3. Click `Connect`.
4. Choose a sender from `Send as`.
5. Type a message.
6. Click `Send Message`.

If you want to connect all demo users for testing, use:

```text
Cmd + Shift + A
```

or:

```text
Ctrl + Shift + A
```

---

## Option 2: Run with Terminal Clients

You can also run the terminal-based version.

### Terminal 1

```bash
python3 Server.py
```

Keep this terminal open.

### Terminal 2

```bash
python3 Client.py
```

Login with:

```text
Username: sauron
Password: sau123
```

### Terminal 3

```bash
python3 Client.py
```

Login with:

```text
Username: frodo
Password: fro123
```

Now the clients can exchange messages through the server.

---

## Demo Accounts

| Username    | Password    | Role   |
| ----------- | ----------- | ------ |
| `sauron`    | `sau123`    | admin  |
| `aragorn`   | `ara123`    | admin  |
| `frodo`     | `fro123`    | user   |
| `legolas`   | `leg123`    | user   |
| `gandalf`   | `gan123`    | user   |
| `sensor_01` | `sensor123` | device |
| `sensor_02` | `sensor123` | device |

These accounts are intended for local testing and development.

---

## GUI Usage Guide

### Top Bar

| Control       | Purpose                                        |
| ------------- | ---------------------------------------------- |
| Start Server  | Starts the local server.                       |
| Stop Server   | Stops the server if it was started by the GUI. |
| Server status | Shows the current server status.               |

### Connect User Area

| Control               | Purpose                                |
| --------------------- | -------------------------------------- |
| Demo account dropdown | Selects a demo account.                |
| Username field        | Shows or allows manual username entry. |
| Password field        | Shows or allows manual password entry. |
| Connect               | Connects the selected user.            |

### Chat Area

The central chat area shows:

- User messages.
- Join and leave events.
- Broadcast messages.
- IoT alerts.
- Important server lifecycle messages.

It intentionally hides noisy debug information such as authentication logs, auto-refresh messages, and repeated server status messages.

### Send As Selector

The `Send as` dropdown determines which connected user sends the next message.

Example:

1. Select `sauron`.
2. Type `Hello everyone`.
3. Click `Send Message`.

The message appears as:

```text
[sauron] Hello everyone
```

### Right Sidebar

| Section       | Purpose                                          |
| ------------- | ------------------------------------------------ |
| Online users  | Shows currently connected users.                 |
| IoT devices   | Shows connected IoT devices and latest readings. |
| Control panel | Provides broadcast, kick, and sensor tools.      |

---

## Available Chat Commands

| Command                     | Description                                    |
| --------------------------- | ---------------------------------------------- |
| `/help`                     | Shows the help menu.                           |
| `/users`                    | Requests online users.                         |
| `/devices`                  | Requests connected IoT devices.                |
| `/status`                   | Requests server status.                        |
| `/whisper username message` | Sends a private message.                       |
| `/broadcast message`        | Admin only: broadcasts a message to all users. |
| `/kick username`            | Admin only: disconnects a user.                |
| `/sensor metric value`      | Sends an IoT sensor reading.                   |
| `/quit`                     | Disconnects the current client.                |

In the GUI, most common features are available through buttons and panels.

---

## IoT Device Functionality

Devices connect with role:

```text
device
```

Example device accounts:

```text
sensor_01
sensor_02
```

A device can send readings through a command:

```text
/sensor temperature 36.5
```

or through the GUI sensor panel:

1. Select `sensor_01` from `Send as`.
2. Choose `temperature`.
3. Enter a value such as `36.5`.
4. Click `Send sensor reading`.

If the value exceeds the server threshold, the chat displays an IoT alert.

---

## Configuration

The project uses `.env` for local configuration.

### `.env.example`

This file is committed to GitHub and acts as a template.

### `.env`

This file should be created locally and should not be committed to GitHub.

It is ignored by `.gitignore`.

---

## Security Features

This project includes several educational security features:

- Encrypted client-server communication.
- Password hashing.
- Salted credentials in `users.json`.
- Role-based permissions.
- Admin-only commands.
- Audit logging.
- Local environment configuration.

This is still an educational prototype and should not be treated as a production security system without further hardening.

---

## Audit Logging

When the server runs, audit logs are written to:

```text
logs/audit.log
```

The logs help track:

- Successful login.
- Failed login.
- User connection.
- User disconnection.
- Messages.
- Admin actions.
- IoT alerts.

---

## Troubleshooting

### Port already in use

If port `65432` is already in use:

```bash
lsof -i :65432
```

Then kill the process:

```bash
kill -9 <PID>
```

Example:

```bash
kill -9 69004
```

Check the dashboard port too:

```bash
lsof -i :8080
```

### GUI says server already running

This means something is already listening on the configured server port. You can either continue using the running server, stop the old server process, or change `PORT` in `.env`.

### Authentication fails

Check that:

- The username is correct.
- The password is correct.
- `users.json` exists.
- The server and GUI use the same secret key configuration.

### Tkinter GUI does not open

Check Tkinter:

```bash
python3 -m tkinter
```

If a small test window opens, Tkinter is installed.

### Missing `cryptography`

Install requirements again:

```bash
python3 -m pip install -r requirements.txt
```

### Cryptography warnings

Some versions of the `cryptography` package may show deprecation warnings for CFB mode. These warnings do not stop the program from running.

Future improvement: migrate from AES-CFB to AES-GCM.

---

## Development Notes

The current GUI provides a cleaner interface than earlier versions:

- One window.
- One central chat area.
- Multiple connected users.
- Shared conversation flow.
- Right-side monitoring for users and devices.
- Reduced button clutter.
- Hidden developer shortcut for connecting all accounts.

The following visible buttons were intentionally removed:

```text
Refresh users
Refresh devices
Disconnect selected sender
Disconnect all
Users
Devices
Status
Fill
Connect All
```

The app still refreshes users/devices internally.

---

## Future Improvements

Possible future improvements:

- Replace AES-CFB with AES-GCM.
- Add SQLite storage for users, messages, audit logs, and sensor readings.
- Add user registration.
- Add message history.
- Add timestamps in persistent storage.
- Add device heartbeat monitoring.
- Improve role-based GUI controls.
- Disable admin tools when selected sender is not an admin.
- Disable sensor tools when selected sender is not a device.
- Add MQTT support for real IoT integration.
- Package the GUI as a desktop application.

---

## Disclaimer

This project is an educational prototype. It demonstrates networking, encryption, authentication, GUI design, and IoT-style messaging concepts. It is not intended to be deployed as a production security system without further hardening, testing, and security review.

---

## Author

Developed by Loukas Theos as part of an IoT Chat learning/project workflow.
