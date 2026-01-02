from gevent import monkey
monkey.patch_all()

import os
import json
import uuid # Add to imports
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, join_room, emit
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import paho.mqtt.client as mqtt
from dotenv import load_dotenv
import psycopg2
# --- SECURITY IMPORT ---
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- CONFIG ---
load_dotenv()
BROKER = os.getenv("BROKER_URL")
MQTT_USER = os.getenv("MQTT_USER")
MQTT_PASS = os.getenv("MQTT_PASS")

# Load the Master Key
MASTER_KEY = os.getenv("MASTER_KEY")
if not MASTER_KEY:
    raise ValueError("No MASTER_KEY found in environment!")

master_cipher = Fernet(MASTER_KEY)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "ghost_secret")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///message_system.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='gevent', cors_allowed_origins="*")

# --- SECURITY: RATE LIMITER ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://" 
)

# Add this near your other global variables
user_last_message_time = {}

# --- DATABASE MODELS ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    # SECURITY FIX: Store Hash, not Plain Password
    password_hash = db.Column(db.String(256), nullable=False)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    pin = db.Column(db.String(20)) # <--- NEW COLUMN
    created_by = db.Column(db.Integer, nullable=False)

class RoomKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    key_value = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, nullable=False)
    sender = db.Column(db.String(50), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    key_id = db.Column(db.Integer, db.ForeignKey('room_key.id'), nullable=False)

    def to_dict(self):
        try:
            key_record = db.session.get(RoomKey, self.key_id)
            if not key_record:
                return {"sender": "System", "message": "[Key Lost]", "time": ""}
            
            # --- UPDATE START ---
            # Decrypt the stored Room Key using the Master Key
            try:
                raw_room_key = master_cipher.decrypt(key_record.key_value.encode()).decode()
            except:
                return {"sender": "System", "message": "[Key Corrupted]", "time": ""}
            
            cipher = Fernet(raw_room_key)
            # --- UPDATE END ---

            decrypted_json_str = cipher.decrypt(self.encrypted_content.encode()).decode()
            packet = json.loads(decrypted_json_str)
            
            return {
                "sender": self.sender,
                "message": packet.get("message"),
                "time": self.timestamp.strftime("%I:%M %p"),
                "date": self.timestamp.strftime("%Y-%m-%d")
            }
        except Exception as e:
            return {"sender": "System", "message": "[Decryption Error]", "time": ""}

with app.app_context():
    db.create_all()

# --- HELPER: KEY ROTATION ---
def get_or_create_active_key(room_id):
    latest_key = RoomKey.query.filter_by(room_id=room_id).order_by(RoomKey.created_at.desc()).first()
    now = datetime.utcnow()
    
    # Create new key if none exists or expired
    if not latest_key or (now - latest_key.created_at > timedelta(hours=24)):
        # 1. Generate the raw room key (This unlocks the messages)
        raw_key_str = Fernet.generate_key().decode()
        
        # 2. ENCRYPT this key using the MASTER_KEY (This protects the key itself)
        encrypted_key_str = master_cipher.encrypt(raw_key_str.encode()).decode()
        
        new_key = RoomKey(room_id=room_id, key_value=encrypted_key_str, created_at=now)
        db.session.add(new_key)
        db.session.commit()
        
        # Return the RAW key to the app so it can use it right now
        # We attach it as a temporary attribute (not saved to DB)
        new_key.temp_raw_value = raw_key_str
        return new_key

    # If key exists, we must DECRYPT it to use it
    try:
        decrypted_key = master_cipher.decrypt(latest_key.key_value.encode()).decode()
        latest_key.temp_raw_value = decrypted_key
        return latest_key
    except Exception as e:
        print(f"CRITICAL: Key Decryption Failed for Room {room_id}")
        return None

# --- MQTT HANDLERS ---
def on_connect(client, userdata, flags, rc, props=None):
    if rc == 0:
        print("[MQTT] Connected. Listening...")
        client.subscribe("ghost/room/+", qos=1)

def on_message(client, userdata, msg):
    pass 

# --- WEB ROUTES ---
@app.route('/')
def index():
    return render_template('chat.html')

# --- SECURITY: REGISTER & LOGIN (psycopg2) ---
@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per hour") # Prevent bot account creation spam
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and Password required"}), 400

    # 1. Hash the password in Python
    hashed_password = generate_password_hash(password)

    try:
        # Connect to DB (use DATABASE_URL from .env)
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()

        # 2. Save the Python-generated hash directly as a string
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            (username, hashed_password)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "User created"}), 201

    except psycopg2.IntegrityError:
        return jsonify({"error": "User already exists"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Missing JSON data"}), 400

    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    conn = None
    try:
        # Connect to DB
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()

        # 1. Fetch the hash
        cur.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
        user_row = cur.fetchone()
        cur.close()
        
        # 2. Verify
        if user_row:
            user_id, stored_hash = user_row
            if check_password_hash(stored_hash, password):
                session['user_id'] = user_id
                session['username'] = username
                return jsonify({"user_id": user_id, "username": username})

        return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        print("Login error:", e) # It is safe to print system errors, just not user data
        return jsonify({"error": "Server Error"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/rooms', methods=['GET'])
def get_rooms():
    user_id = session.get('user_id')
    if not user_id: return jsonify({"error": "Unauthorized"}), 401

    memberships = RoomMember.query.filter_by(user_id=user_id).all()
    result = []
    for m in memberships:
        r = db.session.get(Room, m.room_id)
        if r:
            result.append({"id": r.id, "name": r.name, "created_by": r.created_by})
    return jsonify(result)

@app.route('/api/create_room', methods=['POST'])
def create_room():
    user_id = session.get('user_id')
    if not user_id: return jsonify({"error": "Unauthorized"}), 401
    
    # Check User exists
    user = db.session.get(User, user_id)
    if not user: return jsonify({"error": "User error"}), 401

    data = request.json
    name = data.get('name')
    pin = data.get('pin') # <--- GET PIN

    if not name or not pin:
        return jsonify({"error": "Room Name and PIN are required"}), 400
    
    # Save with PIN
    new_room = Room(name=name, pin=pin, created_by=user_id)
    db.session.add(new_room)
    db.session.commit()

    # Just ensuring you don't delete the key logic!
    # --- UPDATE START ---
    raw_first_key = Fernet.generate_key().decode()
    # Encrypt with Master Key
    encrypted_first_key = master_cipher.encrypt(raw_first_key.encode()).decode()
    
    key_record = RoomKey(room_id=new_room.id, key_value=encrypted_first_key)
    # --- UPDATE END ---
    db.session.add(key_record)

    member = RoomMember(room_id=new_room.id, user_id=user_id)
    db.session.add(member)
    db.session.commit()

    return jsonify({"room_id": new_room.id, "name": name})

@app.route('/api/join_room', methods=['POST'])
def join_room_api():
    user_id = session.get('user_id')
    if not user_id: return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    room_name = data.get('room_name')
    input_pin = data.get('pin') # <--- GET INPUT PIN

    room = Room.query.filter_by(name=room_name).first()
    if not room: return jsonify({"error": "Room not found"}), 404

    # SECURITY CHECK
    if room.pin != input_pin:
        return jsonify({"error": "Incorrect Room PIN"}), 403

    # If PIN matches, proceed to add member
    existing = RoomMember.query.filter_by(room_id=room.id, user_id=user_id).first()
    if not existing:
        new_mem = RoomMember(room_id=room.id, user_id=user_id)
        db.session.add(new_mem)
        db.session.commit()

    return jsonify({"success": True, "room_id": room.id, "name": room.name})

@app.route('/api/delete_room/<int:room_id>', methods=['DELETE'])
def delete_room(room_id):
    user_id = session.get('user_id')
    if not user_id: 
        return jsonify({"error": "Unauthorized"}), 401
    
    room = db.session.get(Room, room_id)
    if not room: 
        return jsonify({"error": "Room not found"}), 404
    
    # CASE 1: The OWNER is deleting the room (Hard Delete)
    if room.created_by == user_id:
        try:
            # 1. Delete all messages in the room
            Message.query.filter_by(room_id=room_id).delete()
            # 2. Delete all memberships (kick everyone out)
            RoomMember.query.filter_by(room_id=room_id).delete()
            # 3. Delete keys
            RoomKey.query.filter_by(room_id=room_id).delete()
            # 4. Delete the room itself
            db.session.delete(room)
            db.session.commit()
            
            # Notify everyone connected via WebSockets
            socketio.emit('room_deleted', {'room_id': room_id}) 
            
            return jsonify({"success": True, "mode": "deleted", "message": "Room permanently deleted"})
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    # CASE 2: A MEMBER is leaving the room (Soft Delete)
    else:
        member = RoomMember.query.filter_by(room_id=room_id, user_id=user_id).first()
        if member:
            db.session.delete(member)
            db.session.commit()
            return jsonify({"success": True, "mode": "left", "message": "You left the room"})
        else:
            return jsonify({"error": "You are not a member of this room"}), 400

@app.route('/api/history/<int:room_id>')
def get_history(room_id):
    messages = Message.query.filter_by(room_id=room_id).limit(50).all()
    return jsonify([msg.to_dict() for msg in messages])

@socketio.on('join')
def on_join(data):
    join_room(data['room_id'])

@socketio.on('send_message')
def handle_send(data):
    # 1. SPAM CHECK
    user_id = session.get('user_id')
    if not user_id: return

    now = datetime.utcnow()
    last_time = user_last_message_time.get(user_id)

    # If last message was less than 1 second ago, IGNORE it.
    if last_time and (now - last_time).total_seconds() < 0.1:
        return 

    user_last_message_time[user_id] = now
    
    room_id = int(data['room_id'])
    sender = data['sender']
    msg_text = data['message']
    
    active_key_record = get_or_create_active_key(room_id)
    cipher = Fernet(active_key_record.temp_raw_value)
    
    packet = {
        "id": str(uuid.uuid4()),  # <--- UNIQUE ID
        "room_id": room_id,      # <--- ADD THIS LINE !!!
        "sender": sender,
        "message": msg_text,
        "time": datetime.now().strftime("%I:%M %p"),
        "date": datetime.now().strftime("%Y-%m-%d")
    }
    encrypted_bytes = cipher.encrypt(json.dumps(packet).encode())
    encrypted_str = encrypted_bytes.decode()
    
    new_msg = Message(
        room_id=room_id, 
        sender=sender, 
        encrypted_content=encrypted_str,
        key_id=active_key_record.id
    )
    db.session.add(new_msg)
    db.session.commit()
    
    socketio.emit('new_message', packet, room=room_id)
    
    if mqtt_client:
        mqtt_client.publish(f"ghost/room/{room_id}", encrypted_bytes, qos=1)

mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqtt_client.username_pw_set(MQTT_USER, MQTT_PASS)
mqtt_client.tls_set()
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message

def start_app():
    if BROKER:
        try:
            mqtt_client.connect(BROKER, 8883, 60)
            mqtt_client.loop_start()
            print("MQTT Bridge Started.")
        except Exception as e:
            print(f"MQTT Connection Failed: {e}")
    else:
        print("MQTT broker not configured.")

    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    start_app()