import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import check_password_hash
from sqlalchemy.orm import Session
import database as db

app = Flask(__name__)
# Get the secret key from an environment variable
app.secret_key = os.environ.get('SECRET_KEY', 'a_default_local_secret_key')

# --- Database Session Management ---
@app.before_request
def before_request():
    g.db = db.SessionLocal()

@app.teardown_request
def teardown_request(exception=None):
    db_session = g.pop('db', None)
    if db_session is not None:
        db_session.close()

# --- Decorator and Auth Routes ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('register'))
        
        existing_user = g.db.query(db.User).filter(db.User.username == username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        new_user = db.User(username=username, password_hash=db.generate_password_hash(password))
        g.db.add(new_user)
        g.db.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = g.db.query(db.User).filter(db.User.username == username).first()

        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))
        else:
            flash('Incorrect username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Main Password Manager Routes ---
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
    return render_template('index.html', passwords=decrypted_passwords)

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
    # This part is now only for local development
    print("Running in local development mode...")
    db.init_db()
    app.run(debug=True)
else:
    # This part is for production on Render
    with app.app_context():
        db.init_db()