# Enhanced IoT Chat Project

This is an improved version of the original IoT Chat coursework project.

## Files

- `Server.py`: enhanced async encrypted server
- `Client.py`: enhanced async encrypted client
- `users.json`: external user database with salted PBKDF2 password hashes
- `.env.example`: optional configuration template
- `requirements.txt`: Python dependency list

## Install

```bash
pip install -r requirements.txt
```

## Optional configuration

```bash
cp .env.example .env
```

Make sure the server and all clients use the same `SHARED_SECRET`.

## Run

Terminal 1:

```bash
python Server.py
```

Terminal 2 or more:

```bash
python Client.py
```

## Dashboard

When the server is running, open this in your browser:

```text
http://127.0.0.1:8080
```

The dashboard shows connected clients, IoT readings and the audit log tail. It auto-refreshes every 5 seconds.

## Demo accounts

| Username | Password | Role |
|---|---|---|
| sauron | sau123 | admin |
| aragorn | ara123 | admin |
| legolas | leg123 | user |
| gandalf | gan123 | user |
| frodo | fro123 | user |
| sensor_01 | sensor123 | device |
| sensor_02 | sensor123 | device |

## Commands

```text
/help
/users
/devices
/status
/whisper username message
/broadcast message
/kick username
/sensor temperature 36.5
/quit
```

## Example IoT demo

Login as `sensor_01` and run:

```text
/sensor temperature 36.5
```

The server stores the reading and sends an alert because the temperature is above the configured threshold.
