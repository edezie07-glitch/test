import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from functools import wraps

# Initialize Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Database
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///hpz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# Socket.IO - CRITICAL: Use 'gevent' when using GeventWebSocketWorker
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    cors_credentials=True,
    async_mode='gevent',  # MUST match gunicorn worker
    logger=True,
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25
)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)
    bio = db.Column(db.String(500), default='')
    avatar_url = db.Column(db.String(500))
    status = db.Column(db.String(100), default='Available')
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Friendship(db.Model):
    __tablename__ = 'friendships'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    to_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Initialize DB
with app.app_context():
    try:
        db.create_all()
        print("✅ Database tables created")
    except Exception as e:
        print(f"⚠️ DB init: {e}")

# Auth decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return render_template('login.html')

@app.route('/chat')
@login_required
def chat_page():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('index'))
    return render_template('chat.html', user=user, user_id=user.id)

@app.route('/health')
def health():
    try:
        count = User.query.count()
        return jsonify({'status': 'ok', 'users': count})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

# Auth
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username taken'}), 400
        
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        
        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()
        
        session['user_id'] = user.id
        session['username'] = user.username
        
        return jsonify({'success': True, 'redirect': '/chat'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        identifier = data.get('identifier', '').strip()
        password = data.get('password', '')
        
        user = User.query.filter_by(username=identifier).first()
        
        if not user or not user.check_password(password):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        session['user_id'] = user.id
        session['username'] = user.username
        
        return jsonify({'success': True, 'redirect': '/chat'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# Users
@app.route('/api/users/search')
@login_required
def search_users():
    try:
        query = request.args.get('q', '').strip()
        user_id = session['user_id']
        
        if not query:
            return jsonify({'success': True, 'results': [], 'count': 0})
        
        users = User.query.filter(
            User.id != user_id,
            User.username.ilike(f'%{query}%')
        ).limit(20).all()
        
        results = []
        for user in users:
            profile = UserProfile.query.filter_by(user_id=user.id).first()
            results.append({
                'id': user.id,
                'username': user.username,
                'avatar': profile.avatar_url if profile and profile.avatar_url else f"https://ui-avatars.com/api/?name={user.username}&background=0088cc&color=fff&size=96",
                'is_online': False,
                'last_seen': 'Offline',
                'is_friend': False,
                'relationship': 'none'
            })
        
        return jsonify({'success': True, 'results': results, 'count': len(results)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Profile
@app.route('/api/profile')
@login_required
def get_profile():
    try:
        user = User.query.get(session['user_id'])
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        
        if not profile:
            profile = UserProfile(user_id=user.id)
            db.session.add(profile)
            db.session.commit()
        
        return jsonify({
            'success': True,
            'profile': {
                'bio': profile.bio,
                'status': profile.status,
                'avatar_url': profile.avatar_url
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    try:
        data = request.get_json()
        profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
        
        if 'bio' in data:
            profile.bio = data['bio'][:500]
        if 'status' in data:
            profile.status = data['status'][:100]
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Friends
@app.route('/api/friends')
@login_required
def get_friends():
    return jsonify({'success': True, 'friends': []})

@app.route('/api/friends/requests')
@login_required
def get_friend_requests():
    return jsonify({'success': True, 'received': [], 'sent': []})

@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    return jsonify({'success': True})

@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend():
    return jsonify({'success': True})

@app.route('/api/friends/reject', methods=['POST'])
@login_required
def reject_friend():
    return jsonify({'success': True})

# Messages
@app.route('/api/messages/<chat_id>')
@login_required
def get_messages(chat_id):
    try:
        messages = ChatMessage.query.filter_by(chat_id=chat_id).order_by(
            ChatMessage.created_at.desc()
        ).limit(50).all()
        
        messages.reverse()
        
        result = []
        for m in messages:
            user = User.query.get(m.sender_id)
            result.append({
                'id': m.id,
                'chat_id': m.chat_id,
                'sender_id': m.sender_id,
                'sender_username': user.username if user else 'Unknown',
                'content': m.content,
                'message_type': m.message_type,
                'created_at': m.created_at.isoformat()
            })
        
        return jsonify({'success': True, 'messages': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    username = session.get('username')
    
    print(f"🔌 Connection: user_id={user_id}, username={username}")
    
    if user_id:
        join_room(f'user_{user_id}')
        join_room('global')
        print(f"✅ {username} connected")
        emit('connected', {'user_id': user_id})
    else:
        print("⚠️ Connection without session")
    
    return True

@socketio.on('disconnect')
def handle_disconnect():
    print(f"❌ User disconnected")

@socketio.on('join')
def handle_join(data):
    chat_id = data.get('chatId')
    if chat_id:
        join_room(chat_id)
        print(f"👥 Joined: {chat_id}")

@socketio.on('send_message')
def handle_send_message(data):
    user_id = session.get('user_id')
    username = session.get('username')
    
    print(f"📥 Message from {username} (ID: {user_id})")
    print(f"   Data: {data}")
    
    if not user_id:
        print("❌ No user_id - not authenticated")
        emit('error', {'message': 'Not authenticated'})
        return
    
    try:
        chat_id = data.get('chatId')
        content = data.get('content', '')
        
        # Save to database
        message = ChatMessage(
            chat_id=chat_id,
            sender_id=user_id,
            content=content,
            message_type=data.get('type', 'text')
        )
        db.session.add(message)
        db.session.commit()
        db.session.refresh(message)
        
        # Prepare response
        message_dict = {
            'id': message.id,
            'chatId': chat_id,
            'sender_id': user_id,
            'sender_username': username,
            'content': content,
            'message_type': message.message_type,
            'created_at': message.created_at.isoformat()
        }
        
        # Broadcast
        if chat_id == 'global':
            socketio.emit('new_message', message_dict, room='global')
            print(f"📤 Sent to global")
        else:
            socketio.emit('new_message', message_dict, room=chat_id)
            print(f"📤 Sent to {chat_id}")
        
        print(f"✅ Message saved: {message.id}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        emit('error', {'message': str(e)})

@socketio.on('typing_start')
def handle_typing_start(data):
    username = session.get('username')
    chat_id = data.get('chatId')
    if username and chat_id:
        socketio.emit('typing_start', {'username': username, 'chatId': chat_id}, 
                     room=chat_id, include_self=False)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    username = session.get('username')
    chat_id = data.get('chatId')
    if username and chat_id:
        socketio.emit('typing_stop', {'username': username, 'chatId': chat_id}, 
                     room=chat_id, include_self=False)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Starting on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
