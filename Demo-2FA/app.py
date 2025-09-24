from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta
import secrets

# สร้าง instance ของ Flask application
app = Flask(__name__) 

# สร้าง secret key สำหรับ session (สร้างค่า SECRET_KEY ใหม่ทุกครั้ง)
app.secret_key = secrets.token_hex(16)

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
    print()

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
    # หน้าล็อกอิน
    if request.method == 'POST':
        #รับข้อมูลจาก AJAX
        if request.is_json:
            data = request.get_json()
            identifier = data.get('username', '').strip()
            password = data.get('password', '')
            remember_me = data.get('remember', False)
        else:
            # รับข้อมูลจาก form submit
            identifier = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            remember_me = request.form.get('remember') == 'on'
            
        # ตรวจสอบข้อมูล
        if not identifier or not password:
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message':'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน'
                }), 400
            else:
                flash('กรุณากรอกชื่อผู้ใช้และรหัสผ่าน', 'error')
                return render_template('login.html')
            
        # ค้นหาผู้ใช้
        user = get_user_by_username_or_email(identifier)
        
        if  user and check_password_hash(user['password_hash'], password):
            # ล็อกอินสำเร็จ
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            
            # ตั้งค่า session ถาวร
            if remember_me:
                session.permanet = True
                app.permanent_session_lifetime = timedelta(days = 30)
            
            # อัพเดทเวลาล็อกอิน
            update_last_login(user['id'])
            
            # login เสร็จให้ redirect ไปหน้า dashboard เลย
            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': 'เข้าสู่ระบบสำเร็จ!',
                    'redirect': url_for('dashboard')
                })
            else:
                flash('เข้าสู่ระบบสำเร็จ!', 'success')
                return redirect(url_for('dashboard'))
            
        else:
            #ล็อกอินไม่สำเร็จ
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
                }), 401
            else:
                flash('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'error')
                return render_template('login.html')
            
    # GET request
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    # เช็คว่ามี session ไหม
    if 'user_id' in session:
        user_info = {
            'username': session.get('username'),
            'email': session.get('email'),
            'login_time': datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        }
    else:
        user_info = None   # <-- ถ้าไม่ล็อกอิน ให้เป็น None

    return render_template('dashboard.html', user = user_info)

@app.route('/logout')
def logout():
    # ออกจากระบบ
    session.clear()
    flash('ออกจากระบบเรียบร้อยแล้ว', 'info')  
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
            errors.append('ชื่อผู้ใช้ต้องมีอย่างน้อย 3 ตัวอักษร')
            
        if not email or '@' not in email:
            errors.append('กรุณากรอกอีเมลที่ถูกต้อง')
            
        if not password or len(password) < 6:
            errors.append('รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร')
            
        if password != confirm_password:
            errors.append('รหัสผ่านไม่ตรงกัน')
            
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')
        
        # ตรวจสอบว่ามี username หรือ email ซ้ำไหม
        existing_user = get_user_by_username_or_email(username)
        existing_email = get_user_by_username_or_email(email)
        
        if existing_user or existing_email:
            flash('ชื่อผู้ใช้หรืออีเมลนี้มีอยู่แล้ว', 'error')
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
            
            flash('สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash('เกิดข้อผิดพลาดในการสมัครสมาชิก', 'error')
            return render_template('register.html')
        
    return render_template('register.html')

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
    print("🚀 Roblox Login Server...")
    app.run(debug=True)
    