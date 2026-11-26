"""
Pruebas de seguridad automatizadas (EV3 - OCY1102)
Se ejecutan contra la aplicacion desplegada en un contenedor de prueba.
Cada prueba ataca una vulnerabilidad conocida: si el ataque funciona, la prueba FALLA
(la aplicacion es vulnerable); si la aplicacion lo bloquea, la prueba PASA.
"""
import os
import re
import requests

BASE = os.environ.get("APP_URL", "http://127.0.0.1:5000")
USER, PASSWORD = "alumno", "12345"


def token_csrf(html):
    """Devuelve el token CSRF del formulario si la aplicacion lo incluye (si no, cadena vacia)."""
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def login_valido():
    """Inicia sesion con credenciales legitimas y devuelve la sesion HTTP."""
    s = requests.Session()
    pagina = s.get(f"{BASE}/login", timeout=10).text
    datos = {"username": USER, "password": PASSWORD, "csrf_token": token_csrf(pagina)}
    s.post(f"{BASE}/login", data=datos, allow_redirects=False, timeout=10)
    return s


def cambiar_bio(s, texto):
    dash = s.get(f"{BASE}/dashboard", timeout=10).text
    s.post(f"{BASE}/update_bio", data={"nueva_bio": texto, "csrf_token": token_csrf(dash)},
           timeout=10, allow_redirects=True)
    return s.get(f"{BASE}/dashboard", timeout=10).text


def test_login_funciona_con_credenciales_validas():
    """Control: un usuario legitimo debe poder entrar (evita falsos positivos)."""
    s = login_valido()
    assert "Panel de alumno" in s.get(f"{BASE}/dashboard", timeout=10).text


def test_sqli_en_login_no_permite_saltar_la_clave():
    """SQL Injection (OWASP A03): ' OR '1'='1 no debe autenticar."""
    s = requests.Session()
    pagina = s.get(f"{BASE}/login", timeout=10).text
    datos = {"username": "admin", "password": "' OR '1'='1", "csrf_token": token_csrf(pagina)}
    r = s.post(f"{BASE}/login", data=datos, allow_redirects=False, timeout=10)
    assert not (r.status_code == 302 and "dashboard" in r.headers.get("Location", ""))
    assert "Panel de admin" not in s.get(f"{BASE}/dashboard", timeout=10).text


def test_cookie_de_sesion_no_se_puede_falsificar():
    """Autenticacion rota (OWASP A07/A01): enviar user_session=admin sin iniciar sesion no debe dar acceso."""
    r = requests.get(f"{BASE}/dashboard", cookies={"user_session": "admin"},
                     allow_redirects=False, timeout=10)
    assert "Panel de admin" not in r.text


def test_xss_la_biografia_se_muestra_escapada():
    """XSS almacenado (OWASP A03): el HTML ingresado no debe aparecer sin escapar."""
    html = cambiar_bio(login_valido(), "<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in html


def test_ssti_las_expresiones_de_plantilla_no_se_evaluan():
    """Inyeccion de plantillas (OWASP A03): {{7*7}} debe mostrarse como texto, no como 49."""
    html = cambiar_bio(login_valido(), "{{7*7}}zz")
    assert "49zz" not in html


def test_csrf_update_bio_exige_token():
    """CSRF (OWASP A01): una peticion sin token y desde otro origen no debe modificar datos."""
    s = login_valido()
    s.post(f"{BASE}/update_bio", data={"nueva_bio": "CSRF_PWNED"},
           headers={"Origin": "http://sitio-malicioso.example"}, timeout=10)
    assert "CSRF_PWNED" not in s.get(f"{BASE}/dashboard", timeout=10).text


def test_cookie_de_sesion_tiene_httponly_y_samesite():
    """Configuracion insegura (OWASP A05): la cookie debe llevar HttpOnly y SameSite."""
    s = requests.Session()
    pagina = s.get(f"{BASE}/login", timeout=10).text
    datos = {"username": USER, "password": PASSWORD, "csrf_token": token_csrf(pagina)}
    r = s.post(f"{BASE}/login", data=datos, allow_redirects=False, timeout=10)
    cookies = " ".join(r.raw.headers.getlist("Set-Cookie")).lower()
    assert "httponly" in cookies and "samesite" in cookies


def test_cabeceras_de_seguridad_presentes():
    """Configuracion insegura (OWASP A05): deben existir cabeceras basicas de proteccion."""
    h = requests.get(f"{BASE}/login", timeout=10).headers
    assert h.get("X-Content-Type-Options", "").lower() == "nosniff"
    assert "X-Frame-Options" in h or "Content-Security-Policy" in h
