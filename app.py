from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash, Response, stream_with_context
import sqlite3
import uuid
import os
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import threading
import time
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
from flask_mail import Mail, Message
import random
import string
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import Column, Integer, String, Text, DateTime
import psutil
import resource

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Add these configurations for persistent sessions
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)  # Sessions last for 31 days
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_TYPE'] = 'filesystem'

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

oauth = OAuth(app)
app.secret_key = os.getenv("SECRET_KEY")

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('email')
app.config['MAIL_PASSWORD'] = os.getenv('app_password')
mail = Mail(app)

google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

DATABASE_FILE = "database.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def cleanup_expired_files():
    while True:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            DELETE FROM code_snippets 
            WHERE user_id IS NULL 
            AND created_at < datetime('now', '-100 days')
        """)
        
        cur.execute("""
            DELETE FROM code_snippets 
            WHERE user_id IS NOT NULL 
            AND created_at < datetime('now', '-100 days')
        """)
        
        conn.commit()
        conn.close()
        time.sleep(60)  

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_files, daemon=True)
cleanup_thread.start()

# Create custom Admin Index View with authentication
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        # Check if user is logged in and has admin email
        return current_user.is_authenticated and current_user.email == os.getenv('email')
    
    def inaccessible_callback(self, name, **kwargs):
        # Redirect to login page if user doesn't have access
        return redirect(url_for('login'))

# Initialize Flask-Admin with our custom view
admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', index_view=MyAdminIndexView())

# Add User model to admin panel
class UserModelView(ModelView):
    column_list = ('id', 'name', 'email')
    form_columns = ('name', 'email', 'password')
    column_searchable_list = ('name', 'email')
    column_filters = ('name', 'email')

# Add CodeSnippet model to admin panel
class CodeSnippetModelView(ModelView):
    column_list = ('id', 'code', 'user_id', 'created_at')
    form_columns = ('code', 'user_id')
    column_searchable_list = ('code',)
    column_filters = ('created_at', 'user_id')

# Initialize database models
class UserModel:
    def __init__(self, id, name, email, password):
        self.id = id
        self.name = name
        self.email = email
        self.password = password

class CodeSnippetModel:
    def __init__(self, id, code, user_id, created_at):
        self.id = id
        self.code = code
        self.user_id = user_id
        self.created_at = created_at

# Add views to admin panel
engine = create_engine(f'sqlite:///{DATABASE_FILE}')
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String)
    password = Column(String)

class CodeSnippet(Base):
    __tablename__ = 'code_snippets'
    id = Column(String, primary_key=True)
    code = Column(Text().with_variant(Text(length=2**24), 'mysql'))  # 16MB text
    user_id = Column(Integer)
    created_at = Column(DateTime)

admin.add_view(UserModelView(User, db_session))
admin.add_view(CodeSnippetModelView(CodeSnippet, db_session))

class User(UserMixin):
    def __init__(self, id, name, email=None):
        self.id = id
        self.name = name
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if row:
        return User(row[0], row[1], row[2])
    return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/codes")
@login_required
def user_codes():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM code_snippets WHERE user_id = ?", (current_user.id,))
    user_files = [row["id"] for row in cur.fetchall()]
    conn.close()

    return render_template("codes.html", user_files=user_files)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

@app.route("/send-otp", methods=["POST"])
def send_otp():
    email = request.form.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    # Check if email already exists
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cur.fetchone():
        conn.close()
        return jsonify({"error": "Email already exists"}), 400
    conn.close()

    otp = generate_otp()
    session['registration_otp'] = otp
    session['registration_email'] = email
    session['otp_timestamp'] = datetime.utcnow().timestamp()
    
    msg = Message(
        'Your OTP for Registration',
        sender=os.getenv('email'),
        recipients=[email]
    )
    msg.body = f'Your OTP for registration is: {otp}'
    
    try:
        mail.send(msg)
        return jsonify({"message": "OTP sent successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Failed to send OTP"}), 500

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        submitted_otp = request.form.get("otp")
        
        stored_otp = session.get('registration_otp')
        stored_email = session.get('registration_email')
        otp_timestamp = session.get('otp_timestamp')
        
        # Check if OTP is valid and not expired (10 minutes validity)
        current_time = datetime.utcnow().timestamp()
        if not stored_otp or not otp_timestamp or (current_time - otp_timestamp) > 600:
            flash("OTP has expired. Please request a new one.", "danger")
            return redirect(url_for("register"))
            
        if email != stored_email:
            flash("Email doesn't match the one OTP was sent to.", "danger")
            return redirect(url_for("register"))
            
        if submitted_otp != stored_otp:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for("register"))
            
        # If OTP verification successful, proceed with registration
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            cur.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                       (name, email, hashed_password))
            conn.commit()
            
            # Clear the session variables
            session.pop('registration_otp', None)
            session.pop('registration_email', None)
            session.pop('otp_timestamp', None)
            
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists", "danger")
            return redirect(url_for("register"))
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password, name, email FROM users WHERE email = ?", 
                   (email,))
        user = cur.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user["password"], password):
            # Make the session permanent before logging in
            session.permanent = True
            login_user(User(user["id"], user["name"], user["email"]), remember=True)
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    
    email = user_info.get("email")
    name = user_info.get("name", email)
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Check if user exists by email
    cur.execute("SELECT id, name FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    
    if not user:
        # Create new user if they don't exist
        password = bcrypt.generate_password_hash(str(uuid.uuid4())).decode("utf-8")
        cur.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                   (name, email, password))
        conn.commit()
        cur.execute("SELECT id, name FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
    
    conn.close()
    
    # Make the session permanent before logging in
    session.permanent = True
    login_user(User(user["id"], user["name"], email), remember=True)
    return redirect(url_for('index'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/new")
def create_new_file():
    unique_id = str(uuid.uuid4())[:8]
    return redirect(url_for("editor", file_id=unique_id))

@app.route("/editor/<file_id>", methods=["GET", "POST"])
def editor(file_id):
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            code = data['code']
            
            # Process in chunks if data is large
            if len(code) > 1000000:  # 1MB
                def save_chunks():
                    conn = get_db_connection()
                    cur = conn.cursor()
                    chunk_size = 500000  # 500KB chunks
                    for i in range(0, len(code), chunk_size):
                        chunk = code[i:i+chunk_size]
                        if i == 0:
                            cur.execute("""
                                INSERT INTO code_snippets (id, code, user_id, created_at) 
                                VALUES (?, ?, ?, datetime('now'))
                            """, (file_id, chunk, current_user.id if current_user.is_authenticated else None))
                        else:
                            cur.execute("""
                                UPDATE code_snippets 
                                SET code = code || ? 
                                WHERE id = ?
                            """, (chunk, file_id))
                        conn.commit()
                    conn.close()
                
                # Use streaming response for large files
                return Response(stream_with_context(save_chunks()), content_type='application/json')
            else:
                # Normal processing for smaller files
                conn = get_db_connection()
                cur = conn.cursor()
                user_id = current_user.id if current_user.is_authenticated else None
                cur.execute("""
                    INSERT OR REPLACE INTO code_snippets (id, code, user_id, created_at) 
                    VALUES (?, ?, ?, datetime('now'))
                """, (file_id, code, user_id))
                conn.commit()
                conn.close()
                return jsonify({"message": "Code saved successfully"}), 200

    # Get file extension from URL or content
    file_extension = request.args.get('lang') or file_id.split('.')[-1].lower()
    
    # Map extensions to Monaco language IDs
    language_map = {
        'py': 'python',
        'js': 'javascript',
        'html': 'html',
        'css': 'css',
        'json': 'json',
        'php': 'php',
        'c': 'c',
        'cpp': 'cpp',
        'cs': 'csharp',
        'go': 'go',
        'rb': 'ruby',
        'ts': 'typescript',
        'kt': 'kotlin',
        'swift': 'swift',
        'java': 'java',
        'txt': 'plaintext'
    }
    
    language = language_map.get(file_extension, 'plaintext')
    
    # Stream large files for reading
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Get file size
    cur.execute("SELECT LENGTH(code) as size FROM code_snippets WHERE id = ?", (file_id,))
    row = cur.fetchone()
    size = row["size"] if row else 0
    
    if size > 1000000:  # Stream if > 1MB
        def generate():
            chunk_size = 500000
            offset = 0
            while True:
                cur.execute("SELECT SUBSTR(code, ?, ?) as chunk FROM code_snippets WHERE id = ?", 
                          (offset + 1, chunk_size, file_id))
                chunk = cur.fetchone()["chunk"]
                if not chunk:
                    break
                yield chunk
                offset += chunk_size
            conn.close()
        
        return Response(stream_with_context(generate()), content_type='text/plain')
    else:
        # Normal read for smaller files
        cur.execute("SELECT code FROM code_snippets WHERE id = ?", (file_id,))
        row = cur.fetchone()
        conn.close()
        code = row["code"] if row else ""
        return render_template("editor.html", file_id=file_id, code=code, size=size, language=language)

# Add pagination endpoint for large files
@app.route("/editor/<file_id>/chunk/<int:chunk>")
def get_chunk(file_id, chunk):
    conn = get_db_connection()
    cur = conn.cursor()
    chunk_size = 500000
    offset = chunk * chunk_size
    cur.execute("SELECT SUBSTR(code, ?, ?) as chunk FROM code_snippets WHERE id = ?", 
               (offset + 1, chunk_size, file_id))
    data = cur.fetchone()
    conn.close()
    return jsonify({
        'chunk': data["chunk"] if data else None,
        'next_chunk': chunk + 1 if data and len(data["chunk"]) == chunk_size else None
    })

# Add memory monitoring endpoint
@app.route('/memory')
def memory_usage():
    process = psutil.Process(os.getpid())
    return jsonify({
        'memory': process.memory_info().rss,
        'cpu': process.cpu_percent()
    })

@app.route("/delete/<file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Verify the file belongs to the current user
    cur.execute("SELECT user_id FROM code_snippets WHERE id = ?", (file_id,))
    file = cur.fetchone()
    
    if not file or file["user_id"] != current_user.id:
        conn.close()
        return jsonify({"error": "File not found or unauthorized"}), 404
    
    try:
        cur.execute("DELETE FROM code_snippets WHERE id = ?", (file_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "File deleted successfully"}), 200
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)