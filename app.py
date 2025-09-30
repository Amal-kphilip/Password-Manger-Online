from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash
import database as db

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_for_sessions'

# --- Decorator and Auth Routes (Unchanged) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    # This function is unchanged
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('register'))
        if db.create_user(username, password):
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose a different one.', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # This function is unchanged
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            flash('Incorrect username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Main Password Manager Routes (Updated) ---
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    user_id = session['user_id']
    if request.method == 'POST':
        name = request.form['name']
        url = request.form['url']
        username = request.form['username']
        password = request.form['password']
        
        # NEW: Automatically add https:// if missing
        if url and not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if not name or not url or not username or not password:
            flash('All fields are required!', 'danger')
        else:
            db.add_password(name, url, username, password, user_id)
            flash('Password added successfully!', 'success')
        return redirect(url_for('index'))

    passwords = db.get_all_passwords(user_id)
    return render_template('index.html', passwords=passwords)

# NEW: Route for editing a password entry
@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit(entry_id):
    user_id = session['user_id']
    entry = db.get_password_by_id(entry_id, user_id)
    if not entry:
        # If entry doesn't exist or doesn't belong to the user, redirect
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name']
        url = request.form['url']
        username = request.form['username']
        password = request.form['password']

        # NEW: Automatically add https:// if missing
        if url and not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if not name or not url or not username or not password:
            flash('All fields are required!', 'danger')
        else:
            db.update_password(entry_id, name, url, username, password, user_id)
            flash('Password updated successfully!', 'success')
            return redirect(url_for('index'))
    
    return render_template('edit.html', entry=entry)


@app.route('/delete/<int:entry_id>')
@login_required
def delete(entry_id):
    db.delete_password(entry_id, session['user_id'])
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.init_db()
    app.run(debug=True)