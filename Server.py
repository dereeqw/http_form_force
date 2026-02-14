#!/usr/bin/env python3
"""
VulnAuth - Vulnerable Login Server for Security Testing
Servidor INTENCIONALMENTE vulnerable para pruebas educativas
"""

from flask import Flask, request, redirect, render_template_string, session, make_response
import secrets
import os
import argparse
import ipaddress
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'insecure-key-for-testing')

# Credenciales vulnerables
VALID_USER = os.environ.get('LAB_USERNAME', 'admin')
VALID_PASS = os.environ.get('LAB_PASSWORD', 'changeme123')

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurePortal - Login</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .login-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
            width: 100%;
            max-width: 400px;
            animation: slideUp 0.5s ease-out;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .login-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px 30px;
            text-align: center;
            color: white;
        }
        
        .logo {
            width: 80px;
            height: 80px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }
        
        .logo svg {
            width: 40px;
            height: 40px;
            fill: white;
        }
        
        h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .subtitle {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .login-body {
            padding: 40px 30px;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            color: #333;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 15px;
            transition: all 0.3s;
            font-family: 'Poppins', sans-serif;
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Poppins', sans-serif;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
        }
        
        .btn-login:active {
            transform: translateY(0);
        }
        
        .error-box {
            background: #fee;
            border-left: 4px solid #f44336;
            color: #c62828;
            padding: 12px 16px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 14px;
            animation: shake 0.3s;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 12px;
            border-top: 1px solid #f0f0f0;
        }
        
        @media (max-width: 480px) {
            .login-body {
                padding: 30px 20px;
            }
            
            h1 {
                font-size: 24px;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <div class="logo">
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
                </svg>
            </div>
            <h1>SecurePortal</h1>
            <p class="subtitle">Sistema de Autenticación</p>
        </div>
        
        <div class="login-body">
            <form method="post" action="/login">
                <input type="hidden" name="csrf_token" value="{{ csrf }}">
                
                <div class="form-group">
                    <label for="username">Usuario</label>
                    <input type="text" id="username" name="username" placeholder="Ingresa tu usuario" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Contraseña</label>
                    <input type="password" id="password" name="password" placeholder="Ingresa tu contraseña" required>
                </div>
                
                <button type="submit" class="btn-login">Iniciar Sesión</button>
                
                {% if error %}
                <div class="error-box">
                    {{ error }}
                </div>
                {% endif %}
            </form>
        </div>
        
        <div class="footer">
            Laboratorio de Seguridad - Solo para uso educativo
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - SecurePortal</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Poppins', sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        h1 {
            color: #667eea;
            font-size: 32px;
        }
        
        .logout-btn {
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .logout-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
        }
        
        .success-box {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .success-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #4caf50, #8bc34a);
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
        }
        
        .success-icon svg {
            width: 40px;
            height: 40px;
            stroke: white;
            stroke-width: 3;
        }
        
        .success-box h2 {
            color: #4caf50;
            margin-bottom: 15px;
        }
        
        .success-box p {
            color: #666;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Panel de Control</h1>
            <a href="/logout" class="logout-btn">Cerrar Sesión</a>
        </div>
        
        <div class="success-box">
            <div class="success-icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>
                </svg>
            </div>
            <h2>✅ Acceso Concedido</h2>
            <p>Has iniciado sesión correctamente en el sistema.</p>
            <p style="margin-top: 15px;"><strong>Usuario autenticado:</strong> {{ username }}</p>
        </div>
    </div>
</body>
</html>
"""

def generate_self_signed_cert():
    """
    Genera un certificado SSL autofirmado y una clave privada
    """
    print(" [*] Generando certificado SSL autofirmado...")
    
    # Generar clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Crear certificado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VulnAuth Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Guardar certificado
    cert_path = "cert.pem"
    key_path = "key.pem"
    
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f" [+] Certificado generado: {cert_path}")
    print(f" [+] Clave privada generada: {key_path}")
    
    return cert_path, key_path

@app.route("/", methods=["GET"])
def index():
    csrf = secrets.token_hex(16)
    session["csrf"] = csrf
    return render_template_string(LOGIN_TEMPLATE, csrf=csrf, error=None)

@app.route("/login", methods=["POST"])
def login():
    # SIN delay - para que tu herramienta funcione rápido
    
    # CSRF básico (tu herramienta lo maneja)
    csrf = request.form.get("csrf_token")
    if not csrf or csrf != session.get("csrf"):
        return "Invalid request", 403
    
    user = request.form.get("username", "").strip()
    pwd = request.form.get("password", "")
    
    if user == VALID_USER and pwd == VALID_PASS:
        session["auth"] = True
        session["username"] = user
        return redirect("/dashboard")
    
    # ERROR SIMPLE - sin palabras que activen tu detector
    csrf = secrets.token_hex(16)
    session["csrf"] = csrf
    return render_template_string(
        LOGIN_TEMPLATE,
        csrf=csrf,
        error="Usuario o contraseña incorrectos"
    ), 401

@app.route("/dashboard")
def dashboard():
    if not session.get("auth"):
        return redirect("/")
    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=session.get("username", "Usuario")
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

def main():
    parser = argparse.ArgumentParser(
        description="VulnAuth - Vulnerable Login Server para pruebas de seguridad"
    )
    parser.add_argument(
        "--ssl",
        action="store_true",
        help="Habilita HTTPS con certificado autofirmado"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Puerto del servidor (default: 8080)"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host del servidor (default: 0.0.0.0)"
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print(" [*] VULNAUTH - VULNERABLE LOGIN SERVER")
    print("=" * 70)
    print(f" [+] Usuario: {VALID_USER}")
    print(f" [+] Password: {VALID_PASS}")
    print()
    print(" [i] Personalizar credenciales:")
    print("     LAB_USERNAME=custom LAB_PASSWORD=custom python VulnAuth.py")
    print("=" * 70)
    
    if args.ssl:
        cert_path, key_path = generate_self_signed_cert()
        protocol = "https"
        ssl_context = (cert_path, key_path)
        print(f" [+] Servidor HTTPS: https://127.0.0.1:{args.port}")
        print(f" [+] SSL habilitado con certificado autofirmado")
        print(f" [!] Nota: Tu navegador mostrará una advertencia de seguridad")
        print(f"     (esto es normal con certificados autofirmados)")
    else:
        protocol = "http"
        ssl_context = None
        print(f" [+] Servidor HTTP: http://127.0.0.1:{args.port}")
    
    print("=" * 70)
    print()
    
    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=False,
            ssl_context=ssl_context
        )
    except KeyboardInterrupt:
        print("\n\n [*] Servidor detenido")
        if args.ssl and os.path.exists("cert.pem") and os.path.exists("key.pem"):
            os.remove("cert.pem")
            os.remove("key.pem")
            print(" [+] Certificados temporales eliminados")

if __name__ == "__main__":
    main()
