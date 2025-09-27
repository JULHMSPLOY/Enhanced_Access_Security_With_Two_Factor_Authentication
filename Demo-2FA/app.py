from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect, generate_csrf
import sqlite3
import secrets
import string
import random

# สร้าง instance ของ Flask application
app = Flask(__name__) 

# สร้าง secret key สำหรับ session และ CSRF (สร้างค่า SECRET_KEY ใหม่ทุกครั้ง)
app.secret_key = secrets.token_hex(16)
csrf = CSRFProtect(app)

#กำหนดฐานข้อมูล
DATABASE = 'roblox_users.db'

#สร้างฐานข้อมูลและตารางผู้ใช้
def init_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )
    ''')
    
    # สร้างผู้ใช้ทดสอบ
    test_users = [
        ('testuser', 'test@roblox.com', 'test123')
    ]

    for username, email, password in test_users:
        try:
            password_hash = generate_password_hash(password)
            cursor.execute('''
            INSERT OR IGNORE INTO users (username, email, password_hash) 
                VALUES (?, ?, ?)
                ''', (username, email, password_hash))
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()
    conn.close()

#ค้นหาผู้ใช้จาก username หรือ email
def get_user_by_username_or_email(identifier):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT id, username, email, password_hash, last_login 
    FROM users 
    WHERE (username = ? OR email = ?) AND is_active = 1
    ''', (identifier, identifier))

    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'password_hash': user[3],
            'last_login': user[4]
        }
        
    return None

# ค้นหาผู้ใช้จาก token
def get_user_by_reset_token(token):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, username, email FROM users
        WHERE reset_token = ? AND reset_token_expiry > CURRENT_TIMESTAMP
    ''', (token,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {'id': user[0], 'username': user[1], 'email': user[2]}
    return None

# อัพเดทเวลาล็อกอินล่าสุด
def update_last_login(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
    ''', (user_id,))
    
    conn.commit()
    conn.close()

# หน้าล็อกอิน
@app.route('/')
def index():
    # หน้าหลัก - ถ้าล็อกอินแล้วไปหน้า dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')
    
@app.route('/login', methods = ['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    # หน้าล็อกอิน
    if request.method == 'POST':
        identifier = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember') == 'on'
            
        # ตรวจสอบข้อมูล
        if not identifier or not password:
            flash('Please enter a username and password', 'error')
            return render_template('login.html')
            
        # ค้นหาผู้ใช้
        user = get_user_by_username_or_email(identifier)
        
        if  user and check_password_hash(user['password_hash'], password):
            # ล็อกอินสำเร็จ
            session.clear() # เคลียร์ session เก่าก่อนล็อกอิน
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']

            # ตั้งค่า session ถาวร
            if remember_me:
                session.permanet = True
                app.permanent_session_lifetime = timedelta(days = 30)
            
            # อัพเดทเวลาล็อกอิน
            update_last_login(user['id'])
            
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username or password', 'error')
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'info')
        return redirect(url_for('login'))
    
    user_info = {
        'username': session.get('username'),
        'email': session.get('email')
    }
    return render_template('dashboard.html', user=user_info)


@app.route('/logout')
def logout():
    # ออกจากระบบ
    session.clear()
    flash('Logged out successfully', 'info')  
    return redirect(url_for('login'))    

@app.route('/register', methods = ['GET', 'POST'])
def register():
    # หน้าสมัครสมาชิก
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # ตรวจสอบช้อมูล
        errors = []
        
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long')
            
        if not email or '@' not in email:
            errors.append('Please enter a valid email')
            
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters long')
            
        if password != confirm_password:
            errors.append('Passwords do not match')
            
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')
        
        # ตรวจสอบว่ามี username หรือ email ซ้ำไหม
        existing_user = get_user_by_username_or_email(username)
        existing_email = get_user_by_username_or_email(email)
        
        if existing_user or existing_email:
            flash('This username or email already exists', 'error')
            return render_template('register.html')
        
        # สร้างบัญชี
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            password_hash = generate_password_hash(password)
            cursor.execute('''
            INSERT INTO users (username, email, password_hash) 
            VALUES (?, ?, ?)
            ''', (username, email, password_hash))
            
            conn.commit()
            conn.close()
            
            flash('Registration successful, Please log in', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash('An error occurred during registration', 'error')
            return render_template('register.html')
        
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user:
            # สร้าง token และกำหนดเวลาหมดอายุ
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=1)
            
            cursor.execute('''
                UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?
            ''', (token, expires_at, user[0]))
            conn.commit()
            
            # ในโค้ดจริงจะส่งอีเมล แต่ที่นี่จะแสดงลิงก์
            reset_link = url_for('reset_password', token=token, _external=True)
            flash(f'A password reset link has been created (in a real app, it would be sent via email: {reset_link}', 'success')
        else:
            flash('This email was not found in the system', 'error')
            
        conn.close()
        return redirect(url_for('forgot_password'))
        
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = get_user_by_reset_token(token)
    if not user:
        flash('Invalid or expired password reset link', 'error')
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('reset_password.html', token=token)
            
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        new_password_hash = generate_password_hash(password)
        cursor.execute('''
            UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?
        ''', (new_password_hash, user['id']))
        conn.commit()
        conn.close()
        
        flash('Password reset successful, Please log in with your new password', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/api/users')
def api_users():
    # API สำหรับดูรายชื่อผู้ใช้ (สำหรับ admin)
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT username, email, created_at, last_login 
    FROM users 
    WHERE is_active = 1
    ORDER BY created_at DESC
    ''')

    users = []
    for row in cursor.fetchall():
        users.append({
            'username': row[0],
            'email': row[1],
            'created_at': row[2],
            'last_login': row[3]
        })
        
    conn.close()
    return jsonify(users)

if __name__ == '__main__':
    print("🚀 Robood Server...")
    init_database()
    app.run(debug=True)
    