from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from cryptography.fernet import Fernet
from flask_bcrypt import Bcrypt
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'jpg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect('whistlevault.db')
    conn.row_factory = sqlite3.Row
    return conn

fixed_key = b'3pfNFWhMxDTqKrXS3GZTEQFK3bD_klgjtLHs_op-9vo='
cipher = Fernet(fixed_key)

# Check if user is admin
def is_admin(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_admin FROM users WHERE user_id = ?", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user and user['is_admin'] == 1

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT user_id FROM users WHERE username = ? OR email = ?", (username, email))
            if cur.fetchone():
                flash("Username or email already taken!", "danger")
            else:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cur.execute("INSERT INTO users (username, email, hashed_password, is_admin) VALUES (?, ?, ?, 0)", 
                            (username, email, hashed_password))
                conn.commit()
                flash("Signup successful! Please log in.", "success")
                return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f"Error: {str(e)}", "danger")
        finally:
            cur.close()
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_type = request.form.get('login_type', 'user')
        username = request.form['username']
        password = request.form['password']
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT user_id, hashed_password, is_admin FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
            if user and bcrypt.check_password_hash(user['hashed_password'], password):
                session['user_id'] = user['user_id']
                session['is_admin'] = user['is_admin']
                if login_type == 'admin' and not user['is_admin']:
                    flash("You are not an admin!", "danger")
                    session.pop('user_id', None)
                    session.pop('is_admin', None)
                elif login_type == 'user' and user['is_admin']:
                    flash("Admins must log in via the Admin tab!", "danger")
                    session.pop('user_id', None)
                    session.pop('is_admin', None)
                else:
                    flash("Logged in successfully!", "success")
                    return redirect(url_for('admin_dashboard' if user['is_admin'] else 'home'))
            else:
                flash("Invalid credentials!", "danger")
        except sqlite3.Error as e:
            flash(f"Error: {str(e)}", "danger")
        finally:
            cur.close()
            conn.close()
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        return redirect(url_for('login', login_type='admin'))
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT s.title, c.name AS category, s.views "
            "FROM secrets s JOIN categories c ON s.category_id = c.category_id "
            "ORDER BY s.views DESC LIMIT 10"
        )
        top_secrets = [dict(row) for row in cur.fetchall()]
        return render_template('index.html', top_secrets=top_secrets)
    except sqlite3.Error:
        return render_template('index.html', top_secrets=[])
    finally:
        cur.close()
        conn.close()

@app.route('/submit', methods=['GET', 'POST'])
def submit_secret():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin'):
        flash("Admins cannot submit secrets!", "danger")
        return redirect(url_for('admin_dashboard'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT category_id, name FROM categories WHERE is_custom = 0")
        categories = cur.fetchall()
    except sqlite3.Error as e:
        flash(f"Error fetching categories: {str(e)}", "danger")
        return render_template('submit.html', categories=[])
    finally:
        cur.close()
        conn.close()

    if request.method == 'POST':
        title = request.form['title']
        secret = request.form.get('secret', '')
        photo = request.files.get('photo')
        category_id = request.form['category']
        priority = request.form['priority']
        custom_category = request.form.get('custom_category', '') if category_id == '8' else None

        if not title:
            flash("Title is required!", "danger")
            return render_template('submit.html', categories=categories)

        encrypted_text = cipher.encrypt(secret.encode('utf-8')) if secret else None
        photo_path = None
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_path = os.path.join('uploads', filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO secrets (user_id, secret_text, title, category_id, priority, custom_category) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (session['user_id'], encrypted_text, title, category_id, priority, custom_category)
            )
            secret_id = cur.lastrowid
            if photo_path:
                cur.execute("INSERT INTO secret_photos (secret_id, photo_path) VALUES (?, ?)", 
                            (secret_id, photo_path))
            conn.commit()
            flash("Secret submitted successfully!", "success")
            return redirect(url_for('home'))
        except sqlite3.Error as e:
            flash(f"Database error: {str(e)}", "danger")
        finally:
            cur.close()
            conn.close()
    
    return render_template('submit.html', categories=categories)

@app.route('/view_secrets')
def view_secrets():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    user_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT s.secret_id, s.title, s.secret_text, s.upload_date, c.name AS category, s.priority, s.custom_category, s.views "
            "FROM secrets s JOIN categories c ON s.category_id = c.category_id WHERE s.user_id = ?",
            (user_id,)
        )
        own_secrets = cur.fetchall()
        cur.execute(
            "SELECT s.secret_id, s.title, s.secret_text, s.upload_date, c.name AS category, s.priority, s.custom_category, s.views "
            "FROM secrets s JOIN shares sh ON s.secret_id = sh.secret_id JOIN categories c ON s.category_id = c.category_id "
            "WHERE sh.recipient_id = ?",
            (user_id,)
        )
        shared_secrets = cur.fetchall()
        cur.execute("SELECT secret_id, photo_path FROM secret_photos")
        photos = {row['secret_id']: row['photo_path'] for row in cur.fetchall()}
        for secret in own_secrets + shared_secrets:
            cur.execute("INSERT INTO secret_logs (secret_id, user_id) VALUES (?, ?)", (secret['secret_id'], user_id))
        conn.commit()
        
        decrypted_secrets = []
        for secret in own_secrets + shared_secrets:
            secret_text = cipher.decrypt(secret['secret_text']).decode('utf-8') if secret['secret_text'] else ''
            decrypted_secrets.append({
                'secret_id': secret['secret_id'],
                'title': secret['title'],
                'secret': secret_text,
                'upload_date': secret['upload_date'],
                'category': secret['custom_category'] or secret['category'],
                'priority': secret['priority'],
                'photo_path': photos.get(secret['secret_id']),
                'views': secret['views'],
                'owned': secret in own_secrets
            })
        return render_template('view_secrets.html', secrets=decrypted_secrets)
    except sqlite3.Error as e:
        flash(f"Error: {str(e)}", "danger")
        return render_template('view_secrets.html', secrets=[])
    finally:
        cur.close()
        conn.close()

@app.route('/view_all')
def view_all():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    user_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT s.secret_id, s.title, s.secret_text, s.upload_date, c.name AS category, s.priority, s.custom_category, s.views "
            "FROM secrets s JOIN categories c ON s.category_id = c.category_id ORDER BY s.upload_date DESC"
        )
        secrets = cur.fetchall()
        cur.execute("SELECT secret_id, photo_path FROM secret_photos")
        photos = {row['secret_id']: row['photo_path'] for row in cur.fetchall()}
        for secret in secrets:
            cur.execute("INSERT INTO secret_logs (secret_id, user_id) VALUES (?, ?)", (secret['secret_id'], user_id))
        conn.commit()
        
        decrypted_secrets = []
        for secret in secrets:
            secret_text = cipher.decrypt(secret['secret_text']).decode('utf-8') if secret['secret_text'] else ''
            decrypted_secrets.append({
                'secret_id': secret['secret_id'],
                'title': secret['title'],
                'secret': secret_text,
                'upload_date': secret['upload_date'],
                'category': secret['custom_category'] or secret['category'],
                'priority': secret['priority'],
                'photo_path': photos.get(secret['secret_id']),
                'views': secret['views']
            })
        return render_template('view_all.html', secrets=decrypted_secrets)
    except sqlite3.Error as e:
        flash(f"Error: {str(e)}", "danger")
        return render_template('view_all.html', secrets=[])
    finally:
        cur.close()
        conn.close()

@app.route('/delete/<int:secret_id>', methods=['POST'])
def delete_secret(secret_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    user_id = session['user_id']
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM secrets WHERE secret_id = ? AND user_id = ?", (secret_id, user_id))
        conn.commit()
        flash("Secret deleted successfully!", "success")
    except sqlite3.Error as e:
        flash(f"Error: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('view_secrets'))

@app.route('/share/<int:secret_id>', methods=['GET', 'POST'])
def share_secret(secret_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        recipient_username = request.form['recipient_username']
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT user_id FROM users WHERE username = ?", (recipient_username,))
            recipient = cur.fetchone()
            if recipient:
                cur.execute("INSERT INTO shares (secret_id, recipient_id) VALUES (?, ?)", (secret_id, recipient['user_id']))
                conn.commit()
                flash("Secret shared successfully!", "success")
            else:
                flash("Recipient not found!", "danger")
            return redirect(url_for('view_secrets'))
        except sqlite3.Error as e:
            flash(f"Error: {str(e)}", "danger")
        finally:
            cur.close()
            conn.close()
    return render_template('share.html', secret_id=secret_id)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT username, email, created_at, profile_picture FROM users WHERE user_id = ?", (user_id,))
        user = cur.fetchone()
        
        if request.method == 'POST':
            if 'remove_picture' in request.form:
                cur.execute("SELECT profile_picture FROM users WHERE user_id = ?", (user_id,))
                current_pic = cur.fetchone()[0]
                if current_pic:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(current_pic)))
                    except OSError:
                        pass
                    cur.execute("UPDATE users SET profile_picture = NULL WHERE user_id = ?", (user_id,))
                    conn.commit()
                    flash("Profile picture removed successfully!", "success")
                    return redirect(url_for('profile'))
                else:
                    flash("No profile picture to remove", "info")
                    return redirect(url_for('profile'))

            profile_pic = request.files.get('profile_picture')
            if profile_pic and profile_pic.filename != '' and allowed_file(profile_pic.filename):
                if user['profile_picture']:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(user['profile_picture'])))
                    except OSError:
                        pass
                filename = secure_filename(profile_pic.filename)
                profile_pic_path = os.path.join('uploads', filename)
                profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cur.execute("UPDATE users SET profile_picture = ? WHERE user_id = ?", (profile_pic_path, user_id))
                conn.commit()
                flash("Profile picture updated!", "success")
                return redirect(url_for('profile'))
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"Database error: {str(e)}", "danger")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()
    
    return render_template('profile.html', user=dict(user))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        flash("Admin access required!", "danger")
        return redirect(url_for('admin_login'))
    user_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT s.secret_id, s.title, s.secret_text, s.upload_date, c.name AS category, s.priority, s.custom_category, s.views, u.username AS owner "
            "FROM secrets s JOIN categories c ON s.category_id = c.category_id JOIN users u ON s.user_id = u.user_id"
        )
        secrets = cur.fetchall()
        cur.execute("SELECT secret_id, photo_path FROM secret_photos")
        photos = {row['secret_id']: row['photo_path'] for row in cur.fetchall()}
        for secret in secrets:
            cur.execute("INSERT INTO secret_logs (secret_id, user_id) VALUES (?, ?)", (secret['secret_id'], user_id))
        conn.commit()
        
        decrypted_secrets = []
        for secret in secrets:
            secret_text = cipher.decrypt(secret['secret_text']).decode('utf-8') if secret['secret_text'] else ''
            decrypted_secrets.append({
                'secret_id': secret['secret_id'],
                'title': secret['title'],
                'secret': secret_text,
                'upload_date': secret['upload_date'],
                'category': secret['custom_category'] or secret['category'],
                'priority': secret['priority'],
                'photo_path': photos.get(secret['secret_id']),
                'views': secret['views'],
                'owner': secret['owner']
            })
        
        if request.method == 'POST':
            secret_id = request.form.get('delete_secret_id')
            if secret_id:
                cur.execute("DELETE FROM secrets WHERE secret_id = ?", (secret_id,))
                conn.commit()
                flash("Secret deleted successfully!", "success")
                return redirect(url_for('admin_dashboard'))
            # Add share logic if needed (similar to share_secret)
    except sqlite3.Error as e:
        flash(f"Error: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()
    
    return render_template('admin_dashboard.html', secrets=decrypted_secrets)

@app.route('/admin_profile', methods=['GET', 'POST'])
def admin_profile():
    if 'user_id' not in session or not session.get('is_admin'):
        flash("Admin access required!", "danger")
        return redirect(url_for('admin_login'))
    user_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT username, email, created_at, profile_picture FROM users WHERE user_id = ?", (user_id,))
        user = cur.fetchone()
        
        if request.method == 'POST':
            if 'remove_picture' in request.form:
                cur.execute("SELECT profile_picture FROM users WHERE user_id = ?", (user_id,))
                current_pic = cur.fetchone()[0]
                if current_pic:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(current_pic)))
                    except OSError:
                        pass
                    cur.execute("UPDATE users SET profile_picture = NULL WHERE user_id = ?", (user_id,))
                    conn.commit()
                    flash("Profile picture removed successfully!", "success")
                    return redirect(url_for('admin_profile'))
                else:
                    flash("No profile picture to remove", "info")
                    return redirect(url_for('admin_profile'))

            profile_pic = request.files.get('profile_picture')
            if profile_pic and profile_pic.filename != '' and allowed_file(profile_pic.filename):
                if user['profile_picture']:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(user['profile_picture'])))
                    except OSError:
                        pass
                filename = secure_filename(profile_pic.filename)
                profile_pic_path = os.path.join('uploads', filename)
                profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cur.execute("UPDATE users SET profile_picture = ? WHERE user_id = ?", (profile_pic_path, user_id))
                conn.commit()
                flash("Profile picture updated!", "success")
                return redirect(url_for('admin_profile'))
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"Database error: {str(e)}", "danger")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()
    
    return render_template('admin_profile.html', user=dict(user))

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin'):
        flash("Admins cannot delete their accounts!", "danger")
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        user_id = session['user_id']
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            conn.commit()
            session.pop('user_id', None)
            session.pop('is_admin', None)
            flash("Account deleted successfully!", "success")
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f"Error: {str(e)}", "danger")
        finally:
            cur.close()
            conn.close()
    return render_template('delete_account.html')

@app.route('/view_secret/<int:secret_id>')
def view_secret(secret_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    user_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT s.secret_id, s.title, s.secret_text, s.upload_date, c.name AS category, s.priority, s.custom_category, s.views, s.user_id AS owner_id "
            "FROM secrets s JOIN categories c ON s.category_id = c.category_id WHERE s.secret_id = ?",
            (secret_id,)
        )
        secret = cur.fetchone()
        if not secret:
            flash("Secret not found!", "danger")
            return redirect(url_for('view_all'))
        
        cur.execute("SELECT photo_path FROM secret_photos WHERE secret_id = ?", (secret_id,))
        photo = cur.fetchone()
        cur.execute("INSERT INTO secret_logs (secret_id, user_id) VALUES (?, ?)", (secret_id, user_id))
        conn.commit()
        
        secret_text = cipher.decrypt(secret['secret_text']).decode('utf-8') if secret['secret_text'] else ''
        secret_data = {
            'secret_id': secret['secret_id'],
            'title': secret['title'],
            'secret': secret_text,
            'upload_date': secret['upload_date'],
            'category': secret['custom_category'] or secret['category'],
            'priority': secret['priority'],
            'photo_path': photo['photo_path'] if photo else None,
            'views': secret['views'],
            'owned': secret['owner_id'] == user_id
        }
        return render_template('view_secret.html', secret=secret_data)
    except sqlite3.Error as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('view_all'))
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)