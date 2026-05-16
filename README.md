# MESSAGE_GRID

A real-time encrypted chat app I built as a fun personal project. Terminal-aesthetic, end-to-end encrypted messages, PIN-protected rooms — built with Flask, WebSockets, and Fernet encryption.

> *Built this so my girlfriend and I could have our own private space to chat. We barely use it now, but building it was genuinely fun.*

---

## What it does

- Register / login with hashed credentials
- Create or join **private rooms** protected by a PIN
- Send and receive messages **in real-time** via WebSockets
- All messages are **encrypted at rest** in the database using Fernet symmetric encryption
- Encryption keys **rotate every 24 hours** per room
- Owner can permanently delete a room; members can leave quietly
- Works on both desktop and mobile (responsive layout)
- MQTT bridge included for external message routing

---

## Tech Stack

| Layer | Tool |
|---|---|
| Backend | Flask + Flask-SocketIO |
| Database | PostgreSQL (via SQLAlchemy + psycopg2) |
| Encryption | Python `cryptography` — Fernet |
| Real-time | WebSockets (Socket.IO) |
| MQTT Bridge | paho-mqtt |
| Frontend | Vanilla HTML/CSS/JS — VT323 terminal font |
| Deployment | Gunicorn + gevent (Heroku-ready via Procfile) |

---

## How the encryption works

This was the most interesting part to build.

```
User sends message
    -> Server picks active RoomKey (rotates every 24h)
    -> Message JSON is encrypted with that RoomKey (Fernet)
    -> Encrypted blob is stored in DB
    -> The RoomKey itself is encrypted using a MASTER_KEY from env
    -> Only the server (with MASTER_KEY) can decrypt the room key
    -> Only the room key can decrypt the messages
```

So even if someone dumps the database, they get encrypted blobs and encrypted keys. Without the `MASTER_KEY` env variable, nothing is readable.

---

## Project Structure

```
Message_APP/
├── app.py              # All backend logic: routes, models, SocketIO, MQTT
├── templates/
│   └── chat.html       # Entire frontend: HTML + CSS + JS in one file
├── requirements.txt
├── Procfile            # Gunicorn config for deployment
└── .gitignore
```

---

## Setup

### 1. Clone and install dependencies

```bash
git clone https://github.com/Krishna4311/Message_APP.git
cd Message_APP
pip install -r requirements.txt
```

### 2. Set up environment variables

Create a `.env` file in the root:

```
SECRET_KEY=your_flask_secret_key
DATABASE_URL=postgresql://user:password@host:port/dbname
MASTER_KEY=your_fernet_master_key
BROKER_URL=your_mqtt_broker_url   # optional
MQTT_USER=your_mqtt_user          # optional
MQTT_PASS=your_mqtt_password      # optional
```

To generate a valid Fernet master key:
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

### 3. Run locally

```bash
python app.py
```

App runs at `http://localhost:5000`

### 4. Deploy (Heroku or similar)

The `Procfile` is already configured:
```
web: gunicorn -k gevent -w 1 app:app
```
Just set your env vars in the platform dashboard and push.

---

## API Endpoints

| Method | Route | Description |
|---|---|---|
| POST | `/api/register` | Create a new account (rate-limited: 5/hour) |
| POST | `/api/login` | Login and create session (rate-limited: 10/min) |
| GET | `/api/rooms` | Get all rooms the current user belongs to |
| POST | `/api/create_room` | Create a new room with a name and PIN |
| POST | `/api/join_room` | Join an existing room using name + PIN |
| DELETE | `/api/delete_room/<id>` | Owner deletes room; member leaves room |
| GET | `/api/history/<room_id>` | Fetch last 50 messages (decrypted, chronological) |

### Socket.IO Events

| Event | Direction | Description |
|---|---|---|
| `join` | Client → Server | Join a socket room |
| `send_message` | Client → Server | Send a message (spam-checked: 0.1s cooldown) |
| `new_message` | Server → Client | Broadcast decrypted message to room |
| `room_deleted` | Server → All | Notify when a room is deleted |

---

## Security choices I made

- Passwords are hashed with Werkzeug's `generate_password_hash` before storing
- Room keys are encrypted with a master key — keys are never stored in plaintext
- Keys rotate every 24 hours per room
- Rate limiting on register (5/hr) and login (10/min) to prevent brute-force
- Per-user spam throttle on `send_message` (100ms cooldown)
- Rooms require a PIN to join — not just a room name

---

## Things I'd improve

- [ ] PIN is stored in plaintext in the DB — should be hashed like passwords
- [ ] No read receipts or typing indicators
- [ ] No image/file sharing support
- [ ] MQTT `on_message` handler is currently a no-op (`pass`)
- [ ] Frontend is a single large HTML file — could be split out

---

## License

MIT — do whatever you want with it.
