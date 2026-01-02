from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# 1. USERS TABLE
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    # In a real app, never store plain passwords. Use a hash.
    # For this phase, we keep it simple.
    
# 2. ROOMS TABLE (Groups & DMs)
class Room(db.Model):
    __tablename__ = 'rooms'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True) # "Project Team", or None for DMs
    is_group = db.Column(db.Boolean, default=False)
    
# 3. ROOM MEMBERS (Who is in which room)
class RoomMember(db.Model):
    __tablename__ = 'room_members'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# 4. MESSAGES TABLE
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False) # We will encrypt this in Phase 4
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "sender_id": self.sender_id,
            "content": self.content,
            "timestamp": self.timestamp.strftime('%H:%M')
        }