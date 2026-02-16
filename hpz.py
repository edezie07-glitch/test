import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

# ========== FLASK APP ==========
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-12345')

# ========== DATABASE ==========
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///hpz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# ========== SOCKET.IO - SIMPLE CONFIG ==========
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    cors_credentials=True,
    async_mode='gevent',  # Changed to gevent - works with Python 3.14
    logger=True,
    engineio_logger=True
)

print("✅ Using async_mode='gevent'")

# ========== MODELS ==========
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    sender = db.relationship('User', foreign_keys=[sender_id])

# ========== INIT DB ==========
with app.app_context():
    db.create_all()
    print("✅ Database initialized")

# ========== ROUTES ==========
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/chat')
    return render_template('login.html')

@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect('/chat')
    return render_template('register.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect('/')
    user = User.query.get(session['user_id'])
    return render_template('chat.html', user=user, user_id=user.id)

@app.route('/api/auth/register', methods=['POST'])
def register():
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
    db.session.commit()
    
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({'success': True, 'redirect': '/chat'})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data.get('identifier', '').strip()
    password = data.get('password', '')
    
    user = User.query.filter_by(username=identifier).first()
    if not user or not user.check_password(password):
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({'success': True, 'redirect': '/chat'})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/messages')
def get_messages():
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    
    messages = Message.query.order_by(Message.created_at.desc()).limit(50).all()
    messages.reverse()
    
    result = [{
        'id': m.id,
        'sender_id': m.sender_id,
        'sender_username': m.sender.username,
        'content': m.content,
        'created_at': m.created_at.isoformat()
    } for m in messages]
    
    return jsonify({'success': True, 'messages': result})

# ========== SOCKET.IO EVENTS ==========
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    username = session.get('username')
    
    print(f"\n{'='*50}")
    print(f"🔌 CONNECT: {username} (ID: {user_id})")
    print(f"   Session: {dict(session)}")
    print(f"   Socket SID: {request.sid}")
    
    if user_id:
        join_room('global_chat')
        print(f"✅ Joined 'global_chat' room")
        
        # Tell everyone this user connected
        socketio.emit('user_joined', {
            'username': username,
            'user_id': user_id
        })
        print(f"📤 Emitted user_joined")
    else:
        print(f"❌ No user_id in session!")
    
    print(f"{'='*50}\n")
    return True

@socketio.on('send_message')
def handle_send_message(data):
    user_id = session.get('user_id')
    username = session.get('username')
    content = data.get('content', '').strip()
    
    print(f"\n{'='*50}")
    print(f"📥 MESSAGE FROM: {username} (ID: {user_id})")
    print(f"   Content: {content}")
    print(f"   Socket SID: {request.sid}")
    
    if not user_id:
        print(f"❌ ERROR: No user_id!")
        emit('error', {'message': 'Not authenticated'})
        return
    
    if not content:
        print(f"❌ ERROR: Empty content!")
        return
    
    # Save to database
    msg = Message(sender_id=user_id, content=content)
    db.session.add(msg)
    db.session.commit()
    
    # Create response
    message_data = {
        'id': msg.id,
        'sender_id': user_id,
        'sender_username': username,
        'content': content,
        'created_at': msg.created_at.isoformat()
    }
    
    print(f"💾 Saved to database: Message #{msg.id}")
    print(f"📤 Broadcasting to 'global_chat' room...")
    
    # CRITICAL: With gevent, use skip_sid to avoid sending to sender twice
    socketio.emit('new_message', message_data, 
                  to='global_chat',
                  skip_sid=request.sid)  # Don't send to sender (they already have it)
    
    # Send to sender separately to ensure they get it
    socketio.emit('new_message', message_data, to=request.sid)
    
    print(f"✅ Message broadcast complete!")
    print(f"{'='*50}\n")

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username', 'Unknown')
    print(f"❌ DISCONNECT: {username}\n")

# ========== DEBUG ==========
@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'users': User.query.count()})

# ========== RUN ==========
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"\n{'='*50}")
    print(f"🚀 SIMPLE MESSENGER STARTING")
    print(f"   Port: {port}")
    print(f"   Async mode: eventlet")
    print(f"{'='*50}\n")
    socketio.run(app, host='0.0.0.0', port=port)
