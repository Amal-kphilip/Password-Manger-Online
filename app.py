import os
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.orm import Session
from authlib.integrations.flask_client import OAuth
import database as db

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'a_default_local_secret_key')

# OAuth Configuration (Unchanged)
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
)

# Database Session Management (Unchanged)
@app.before_request
def before_request():
    g.db = db.SessionLocal()

@app.teardown_request
def teardown_request(exception=None):
    db_session = g.pop('db', None)
    if db_session is not None:
        db_session.close()

# Decorator (Unchanged)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Auth Routes (Updated) ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip() # Use .strip() to remove whitespace
        password = request.form['password']
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('register'))
        
        # CHANGED: Check if username (or an email matching it) is already taken
        existing_user = g.db.query(db.User).filter(db.User.username == username).first()
        if existing_user:
            flash('Username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        new_user = db.User(username=username, password_hash=generate_password_hash(password))
        g.db.add(new_user)
        g.db.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login/local', methods=['POST'])
def local_login():
    username = request.form['username']
    password = request.form['password']
    # This query correctly finds local accounts only
    user = g.db.query(db.User).filter(db.User.username == username, db.User.google_id == None).first()

    if user and check_password_hash(user.password_hash, password):
        user.last_login = datetime.utcnow()
        g.db.commit()
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('index'))
    else:
        flash('Incorrect username or password.', 'danger')
        return redirect(url_for('login'))

@app.route('/google/login')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def google_callback():
    token = google.authorize_access_token()
    userinfo = token.get('userinfo')
    
    if userinfo:
        google_id = userinfo['sub']
        email = userinfo['email']
        
        user = g.db.query(db.User).filter(db.User.google_id == google_id).first()

        if not user:
            # CHANGED: Check if the Google email is already taken by a local username
            existing_local_user = g.db.query(db.User).filter(db.User.username == email, db.User.google_id == None).first()
            if existing_local_user:
                flash('This email is already registered to a local account. Please log in with your username and password.', 'danger')
                return redirect(url_for('login'))
            
            # If no conflict, create a new Google-linked user
            user = db.User(username=email, google_id=google_id)
            g.db.add(user)
        
        user.last_login = datetime.utcnow()
        g.db.commit()

        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('index'))

    flash('Google login failed. Please try again.', 'danger')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Main Password Manager Routes (Unchanged) ---
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    user_id = session['user_id']
    if request.method == 'POST':
        name = request.form['name']
        url = request.form['url']
        username = request.form['username']
        password = request.form['password']
        if url and not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        if not name or not url or not username or not password:
            flash('All fields are required!', 'danger')
        else:
            encrypted_pass = db.encrypt_password(password)
            new_entry = db.PasswordEntry(name=name, url=url, username=username, encrypted_password=encrypted_pass, user_id=user_id)
            g.db.add(new_entry)
            g.db.commit()
            flash('Password added successfully!', 'success')
        return redirect(url_for('index'))
    user = g.db.query(db.User).filter(db.User.id == user_id).first()
    decrypted_passwords = [{'id': p.id, 'name': p.name, 'url': p.url, 'username': p.username, 'password': db.decrypt_password(p.encrypted_password)} for p in user.passwords]
    return render_template('index.html', passwords=decrypted_passwords, user=user)

@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit(entry_id):
    user_id = session['user_id']
    entry = g.db.query(db.PasswordEntry).filter(db.PasswordEntry.id == entry_id, db.PasswordEntry.user_id == user_id).first()
    if not entry:
        return redirect(url_for('index'))
    if request.method == 'POST':
        entry.name = request.form['name']
        entry.url = request.form['url']
        entry.username = request.form['username']
        entry.encrypted_password = db.encrypt_password(request.form['password'])
        if entry.url and not entry.url.startswith(('http://', 'https://')):
            entry.url = 'https://' + entry.url
        g.db.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('index'))
    decrypted_entry = {'id': entry.id, 'name': entry.name, 'url': entry.url, 'username': entry.username, 'password': db.decrypt_password(entry.encrypted_password)}
    return render_template('edit.html', entry=decrypted_entry)

@app.route('/delete/<int:entry_id>')
@login_required
def delete(entry_id):
    entry = g.db.query(db.PasswordEntry).filter(db.PasswordEntry.id == entry_id, db.PasswordEntry.user_id == session['user_id']).first()
    if entry:
        g.db.delete(entry)
        g.db.commit()
        flash('Password deleted successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.init_db()
    app.run(debug=True, port=5000)
else:
    with app.app_context():
        db.init_db()