from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv
import os
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_wtf import CSRFProtect, FlaskForm
import html

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('COOKIE_SECRET_KEY')
csrf = CSRFProtect(app)

# Configuración de la sesión
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Solo HTTPS
    SESSION_COOKIE_HTTPONLY=True,  
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7)
)

def get_db_connection():
    conn = psycopg2.connect(
        dbname=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        host=os.getenv('DB_HOST'),
        port=os.getenv('DB_PORT')
    )
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        try:
            cur.execute("""
                SELECT roles.name as role_name 
                FROM users 
                JOIN roles ON users.role_id = roles.id 
                WHERE users.id = %s
            """, (session['user_id'],))
            user = cur.fetchone()
            
            if not user or user['role_name'] != 'admin':
                flash('Acceso denegado: se requieren privilegios de administrador')
                return redirect(url_for('dashboard'))
                
            return f(*args, **kwargs)
        finally:
            cur.close()
            conn.close()
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = FlaskForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = html.escape(request.form['email'].strip())
        password = request.form['password']
        role_type = request.form['role']

        # Validar correo y contraseña
        if not email or not password or len(password) < 2:
            flash('Correo inválido o contraseña demasiado corta')
            return redirect(url_for('register'))

        # Hash de la contraseña
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            # Verificar si el usuario ya existe
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cur.fetchone() is not None:
                flash('El correo electrónico ya está registrado')
                return redirect(url_for('register'))

            # Obtener el ID del rol
            cur.execute("SELECT id FROM roles WHERE name = %s", (role_type,))
            role_id = cur.fetchone()[0]

            # Crear nuevo usuario
            cur.execute("""
                INSERT INTO users (email, password_hash, role_id)
                VALUES (%s, %s, %s)
            """, (email, password_hash.decode('utf-8'), role_id))
            
            conn.commit()
            flash('¡Registro exitoso! Por favor inicia sesión.')
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            flash('Error en el registro: ' + str(e))
            return redirect(url_for('register'))
        finally:
            cur.close()
            conn.close()
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = FlaskForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = html.escape(request.form['email'].strip())
        password = request.form['password']
        auth_type = request.form.get('auth_type', 'session')

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        try:
            cur.execute("""
                SELECT users.*, roles.name as role_name 
                FROM users 
                JOIN roles ON users.role_id = roles.id 
                WHERE users.email = %s
            """, (email,))
            user = cur.fetchone()

            # Verificar si han pasado 5 minutos desde el último intento fallido
            if user and user['is_locked'] and user['last_failed_login']:
                tiempo_transcurrido = datetime.utcnow() - user['last_failed_login']
                if tiempo_transcurrido.total_seconds() >= 300:  # 300 segundos = 5 minutos
                    # Desbloquear usuario y resetear intentos
                    cur.execute("""
                        UPDATE users 
                        SET is_locked = FALSE,
                            failed_login_attempts = 0,
                            last_failed_login = NULL
                        WHERE id = %s
                    """, (user['id'],))
                    conn.commit()
                    user['is_locked'] = False
                    user['failed_login_attempts'] = 0

            if user and not user['is_locked'] and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                if auth_type == 'jwt':
                    token = jwt.encode({
                        'user_id': user['id'],
                        'email': user['email'],
                        'exp': datetime.utcnow() + timedelta(hours=24)
                    }, os.getenv('JWT_SECRET_KEY'), algorithm='HS256')
                    
                    # Obtener lista de usuarios si es admin
                    all_users = None
                    if user['role_name'] == 'admin':
                        cur.execute("""
                            SELECT 
                                users.id,
                                users.email,
                                users.created_at,
                                users.is_locked,
                                users.failed_login_attempts,
                                roles.name as role_name
                            FROM users 
                            JOIN roles ON users.role_id = roles.id 
                            ORDER BY users.created_at DESC
                        """)
                        all_users = cur.fetchall()
                    
                    return render_template('dashboard.html', 
                                        user=user, 
                                        token=token,
                                        all_users=all_users)
                else:
                    session.permanent = True
                    session['user_id'] = user['id']
                    
                    # Resetear intentos fallidos
                    cur.execute("""
                        UPDATE users 
                        SET failed_login_attempts = 0, 
                            last_failed_login = NULL 
                        WHERE id = %s
                    """, (user['id'],))
                    conn.commit()
                    
                    flash('Inicio de sesión exitoso')
                    return redirect(url_for('dashboard'))

            # Incrementar intentos fallidos solo si el usuario existe y la contraseña es incorrecta
            if user:
                cur.execute("""
                    UPDATE users 
                    SET failed_login_attempts = failed_login_attempts + 1,
                        last_failed_login = CURRENT_TIMESTAMP,
                        is_locked = CASE 
                            WHEN failed_login_attempts >= 3 THEN TRUE 
                            ELSE FALSE 
                        END
                    WHERE id = %s
                """, (user['id'],))
                conn.commit()
                
                if user['failed_login_attempts'] >= 2:  # Ya tenía 2 intentos, este es el tercero
                    flash('Cuenta bloqueada por múltiples intentos fallidos. Intente nuevamente en 5 minutos.')
                else:
                    flash(f'Credenciales inválidas. Intentos restantes: {3 - (user["failed_login_attempts"] + 1)}')
            else:
                flash('Credenciales inválidas')
            
            return redirect(url_for('login'))
        
        finally:
            cur.close()
            conn.close()
    
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    form = FlaskForm()  # Para el token CSRF en el formulario de eliminar
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
    try:
        # Obtener información del usuario actual
        cur.execute("""
            SELECT users.*, roles.name as role_name 
            FROM users 
            JOIN roles ON users.role_id = roles.id 
            WHERE users.id = %s
        """, (session['user_id'],))
        user = cur.fetchone()
        
        if not user:
            session.clear()
            return redirect(url_for('login'))

        # Si es administrador, obtener lista de usuarios
        all_users = None
        if user['role_name'] == 'admin':
            cur.execute("""
                SELECT 
                    users.id,
                    users.email,
                    users.created_at,
                    users.is_locked,
                    users.failed_login_attempts,
                    roles.name as role_name
                FROM users 
                JOIN roles ON users.role_id = roles.id 
                ORDER BY users.created_at DESC
            """)
            all_users = cur.fetchall()
            
        return render_template('dashboard.html', user=user, all_users=all_users, form=form)
    finally:
        cur.close()
        conn.close()

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    form = FlaskForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        try:
            # Verificar que el usuario a eliminar existe y no es el admin actual
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user_to_delete = cur.fetchone()
            
            if not user_to_delete:
                flash('Usuario no encontrado')
                return redirect(url_for('dashboard'))
            
            if user_to_delete['id'] == session['user_id']:
                flash('No puedes eliminar tu propia cuenta')
                return redirect(url_for('dashboard'))
            
            # Eliminar el usuario
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            
            flash('Usuario eliminado correctamente')
        except Exception as e:
            conn.rollback()
            flash('Error al eliminar usuario: ' + str(e))
        finally:
            cur.close()
            conn.close()
            
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')
