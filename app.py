import os
import re
import hmac
import secrets
import sqlite3
import logging
from flask import Flask, request, render_template_string, redirect, session, abort
from werkzeug.security import check_password_hash

app = Flask(__name__)

# CORRECCION (A05/A07): clave secreta para firmar la sesion y cookie endurecida
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('app')

USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{1,30}$')
MAX_BIO = 200


def db_query(query, params=()):
    """CORRECCION (A03): consultas parametrizadas; los datos nunca se concatenan al SQL."""
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, params)
    result = cursor.fetchall()
    conn.commit()
    conn.close()
    return result


def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


def csrf_valido():
    enviado = request.form.get('csrf_token', '')
    return bool(session.get('csrf_token')) and hmac.compare_digest(enviado, session['csrf_token'])


@app.after_request
def cabeceras_seguridad(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    resp.headers['Cache-Control'] = 'no-store'
    return resp


LOGIN_HTML = '''
    <h2>Login del Sistema Académico</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{{ token }}">
        Usuario: <input type="text" name="username" maxlength="30" required><br>
        Password: <input type="password" name="password" maxlength="128" required><br>
        <input type="submit" value="Ingresar">
    </form>
    {% if error %}<p>{{ error }}</p>{% endif %}
'''

DASHBOARD_HTML = '''
    <h1>Panel de {{ username }}</h1>
    <p><b>Rol:</b> {{ rol }}</p>
    <p><b>Biografía:</b> {{ bio }}</p>
    <hr>
    <h3>Actualizar Biografía</h3>
    <form action="/update_bio" method="POST">
        <input type="hidden" name="csrf_token" value="{{ token }}">
        <input type="text" name="nueva_bio" maxlength="200" placeholder="Escribe algo...">
        <input type="submit" value="Guardar Cambios">
    </form>
    <br>
    <form action="/logout" method="POST">
        <input type="hidden" name="csrf_token" value="{{ token }}">
        <input type="submit" value="Cerrar Sesión">
    </form>
'''


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username', '').strip()
        pw = request.form.get('password', '')
        # CORRECCION (A03): validacion de entrada (lista blanca) antes de tocar la base de datos
        if not USERNAME_RE.match(user) or not (0 < len(pw) <= 128):
            log.warning("Login rechazado por formato invalido")
            return render_template_string(LOGIN_HTML, token=csrf_token(), error='Credenciales inválidas.'), 401

        filas = db_query("SELECT * FROM usuarios WHERE username = ?", (user,))
        if filas and check_password_hash(filas[0]['password'], pw):
            session.clear()
            session['user'] = filas[0]['username']   # sesion firmada por el servidor, no editable por el cliente
            csrf_token()
            log.info("Login correcto: %s", user)
            return redirect('/dashboard')
        log.warning("Login fallido para '%s'", user)
        return render_template_string(LOGIN_HTML, token=csrf_token(), error='Credenciales inválidas.'), 401

    return render_template_string(LOGIN_HTML, token=csrf_token(), error=None)


@app.route('/dashboard')
def dashboard():
    username = session.get('user')
    if not username:
        return redirect('/login')
    filas = db_query("SELECT * FROM usuarios WHERE username = ?", (username,))
    if not filas:
        session.clear()
        return redirect('/login')
    datos = filas[0]
    # CORRECCION (A03): los datos se pasan como variables; Jinja2 escapa el HTML y no evalua {{ }} del usuario
    return render_template_string(DASHBOARD_HTML, username=datos['username'], rol=datos['rol'],
                                  bio=datos['bio'], token=csrf_token())


@app.route('/update_bio', methods=['POST'])
def update_bio():
    username = session.get('user')
    if not username:
        return redirect('/login')
    # CORRECCION (A01): token anti-CSRF obligatorio
    if not csrf_valido():
        log.warning("CSRF invalido en /update_bio (usuario %s)", username)
        abort(403)
    nueva_bio = request.form.get('nueva_bio', '')
    # Sanitizacion: sin caracteres de control y con largo maximo
    nueva_bio = ''.join(c for c in nueva_bio if c.isprintable()).strip()[:MAX_BIO]
    db_query("UPDATE usuarios SET bio = ? WHERE username = ?", (nueva_bio, username))
    return redirect('/dashboard')


@app.route('/logout', methods=['POST'])
def logout():
    if csrf_valido():
        session.clear()
    return redirect('/login')


@app.route('/')
def home():
    return redirect('/login')


if __name__ == '__main__':
    # CORRECCION (A05): sin debug=True
    app.run(host='127.0.0.1', port=5000)
