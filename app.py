import os
import json
from dotenv import load_dotenv # Carga las variables de .env
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, flash, session
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import google.generativeai as genai
from math import radians, cos, sin, asin, sqrt
import uuid
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth

# --- Configuración ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mi-clave-secreta-de-desarrollo-12345'
UPLOAD_FOLDER = 'uploads' 
STATIC_UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads') 
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reportes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Lee las llaves desde .env (que Render lee como Variables de Entorno)
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
oauth = OAuth(app) 

try:
    GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')
    genai.configure(api_key=GOOGLE_API_KEY)
except Exception as e:
    print(f"Error configurando la API de Google: {e}")

# --- Configuración de OAuth ---
oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
)

# --- Modelos de Usuario y Reporte ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=True)
    reportes = db.relationship('Reporte', backref='author', lazy=True)

class Reporte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fecha_reporte = db.Column(db.DateTime, default=datetime.utcnow)
    estado = db.Column(db.String(50), nullable=False, default="Encontrado")
    latitud = db.Column(db.Float, nullable=True)
    longitud = db.Column(db.Float, nullable=True)
    descripcion = db.Column(db.String(500), nullable=True)
    fecha_foto = db.Column(db.String(100), nullable=True)
    modelo_celular = db.Column(db.String(200), nullable=True)
    imagen_url = db.Column(db.String(100), nullable=True) 
    ia_es_mascota = db.Column(db.String(10), nullable=True)
    ia_especie = db.Column(db.String(50), nullable=True)
    ia_raza = db.Column(db.String(100), nullable=True)
    ia_color_principal = db.Column(db.String(50), nullable=True)
    ia_collar = db.Column(db.String(50), nullable=True)
    ia_fuente = db.Column(db.String(50), nullable=True, default="N/A")

# --- Funciones de Login ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) # Arreglo de LegacyWarning
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'
login_manager.login_message = 'Debes iniciar sesión para completar tu reporte.'

# --- Rutas de Autenticación ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Ese email ya está registrado. Por favor, inicia sesión.', 'error')
            return redirect(url_for('login'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('¡Cuenta creada con éxito! Ahora puedes completar tu reporte.', 'success')
        return redirect(url_for('completar_reporte'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.password_hash and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash('¡Inicio de sesión exitoso!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Error al iniciar sesión. Verifica tu email y contraseña.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'success')
    return redirect(url_for('login'))

# --- Rutas de Login con Google ---
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/login/google/callback')
def authorize_google():
    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.get('userinfo').json()
    except Exception as e:
        print(f"Error en el callback de Google: {e}")
        flash("Error al iniciar sesión con Google. Inténtalo de nuevo.", "error")
        return redirect(url_for('login'))
    email = user_info.get('email')
    if not email:
        flash("No se pudo obtener tu email de Google.", "error")
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, password_hash=None)
        db.session.add(user)
        db.session.commit()
        flash('¡Cuenta creada con éxito a través de Google!', 'success')
    else:
        flash('¡Inicio de sesión exitoso con Google!', 'success')
    login_user(user)
    if 'foto_pendiente' in session:
        return redirect(url_for('completar_reporte'))
    else:
        return redirect(url_for('index'))

# --- Funciones de IA y Distancia ---
def obtener_metadatos_gps(imagen_path):
    try:
        img = Image.open(imagen_path)
        exif_data_raw = img._getexif()
        if not exif_data_raw: return {"Error": "No se encontraron datos EXIF."}
        exif_data = {}
        for tag, value in exif_data_raw.items():
            tag_nombre = TAGS.get(tag, tag)
            exif_data[tag_nombre] = value
        fecha_hora = exif_data.get("DateTimeOriginal", None)
        modelo = f"{exif_data.get('Make', '')} {exif_data.get('Model', '')}".strip()
        gps_info_raw = exif_data.get("GPSInfo")
        lat_decimal, lon_decimal = None, None
        if gps_info_raw:
            gps_data = {}
            for tag, value in gps_info_raw.items():
                tag_nombre = GPSTAGS.get(tag, tag)
                gps_data[tag_nombre] = value
            lat = gps_data.get('GPSLatitude')
            lon = gps_data.get('GPSLongitude')
            if lat and lon:
                lat_ref = gps_data.get('GPSLatitudeRef', 'N')
                lon_ref = gps_data.get('GPSLongitudeRef', 'W')
                lat_decimal = lat[0] + (lat[1] / 60) + (lat[2] / 3600)
                lon_decimal = lon[0] + (lon[1] / 60) + (lon[2] / 3600)
                if lat_ref == 'S': lat_decimal = -lat_decimal
                if lon_ref == 'W': lon_decimal = -lon_decimal
        return {
            "fecha_foto": fecha_hora, "latitud": lat_decimal, "longitud": lon_decimal,
            "modelo_celular": modelo
        }
    except Exception as e:
        return {"Error": f"No se pudo leer la imagen o los datos EXIF: {e}"}

def analizar_foto_con_ia(imagen_path):
    if not GOOGLE_API_KEY: 
        print("API Key no encontrada.")
        return {"es_mascota": "Si", "especie": "Perro (Prueba)", "raza_aproximada": "Test", "color_principal": "Test", "collar": "No se ve", "fuente": "Error API"}
    try:
        model = genai.GenerativeModel('models/gemini-flash-latest') 
        img = Image.open(imagen_path)
        prompt_parts = [
            f"""
            Eres un asistente experto en clasificación de mascotas.
            Tu tarea es analizar la IMAGEN y rellenar el siguiente JSON.
            - es_mascota: Responde "Si" si la imagen es una foto real de una mascota (perro, gato, pájaro, conejo, etc.).
                          Responde "No" si es un humano, un dibujo, un meme, o una foto de stock/publicidad evidente.
            - especie: Si es_mascota es "Si", identifica la especie (ej: "Perro", "Gato", "Pájaro"). De lo contrario, "No es mascota".
            - raza_aproximada: Si es una mascota, identifica la raza (ej: "Mestizo", "Labrador", "Siamés").
            - color_principal: Color principal del pelaje (ej: "Negro", "Blanco", "Marrón", "Dorado").
            - collar: ¿Se ve un collar? (ej: "Si", "No", "No se ve").
            Responde ÚNICAMENTE con el formato JSON.
            Respuesta JSON:
            """,
            img 
        ]
        response = model.generate_content(prompt_parts)
        response_text = response.text
        start_index = response_text.find('{')
        end_index = response_text.rfind('}')
        if start_index != -1 and end_index != -1:
            json_text = response_text[start_index : end_index + 1]
            datos_json = json.loads(json_text)
        else:
            raise ValueError("No se encontró JSON en la respuesta de la IA")
        datos_json["fuente"] = "Foto+Texto"
        return datos_json
    except Exception as e:
        print(f"Error durante el análisis de IA (Multimodal): {e}")
        return {"fuente": "Error Foto", "es_mascota": "Error"}

def haversine(lon1, lat1, lon2, lat2):
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    r = 6371
    return c * r

def buscar_coincidencias(reporte_actual):
    coincidencias = []
    estado_opuesto = "Perdido" if reporte_actual.estado == "Encontrado" else "Encontrado"
    posibles_reportes = Reporte.query.filter(
        Reporte.estado == estado_opuesto,
        Reporte.ia_especie == reporte_actual.ia_especie,
        Reporte.user_id != reporte_actual.user_id
    ).all()
    RADIO_BUSQUEDA_KM = 20
    for reporte in posibles_reportes:
        if reporte_actual.latitud and reporte_actual.longitud and reporte.latitud and reporte.longitud:
            distancia = haversine(
                reporte_actual.longitud, reporte_actual.latitud,
                reporte.longitud, reporte.latitud
            )
            if distancia <= RADIO_BUSQUEDA_KM:
                coincidencias.append((reporte, round(distancia, 1)))
    coincidencias.sort(key=lambda x: x[1])
    return coincidencias

# --- Rutas de Página ---
@app.route('/')
def index():
    posibles_coincidencias = []
    reporte_creado = None
    new_report_id = request.args.get('new_report_id')
    if new_report_id:
        reporte_creado = db.session.get(Reporte, new_report_id) # Arreglo de LegacyWarning
        if reporte_creado:
            posibles_coincidencias = buscar_coincidencias(reporte_creado)
    return render_template(
        'index.html', 
        posibles_coincidencias=posibles_coincidencias, 
        reporte_creado=reporte_creado
    )

@app.route('/historial')
@login_required 
def historial():
    reportes = Reporte.query.filter_by(user_id=current_user.id).order_by(Reporte.fecha_reporte.desc()).all()
    return render_template('historial.html', reportes=reportes)

# --- Rutas del Embudo ---
@app.route('/validar-foto', methods=['POST'])
def validar_foto():
    if 'foto' not in request.files:
        flash('No se seleccionó ningún archivo.', 'error')
        return redirect(url_for('index'))
    archivo = request.files['foto']
    if archivo.filename == '':
        flash('No se seleccionó ningún archivo.', 'error')
        return redirect(url_for('index'))
    ext = os.path.splitext(archivo.filename)[1]
    unique_name = str(uuid.uuid4()) + ext
    temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    archivo.save(temp_filepath)
    print(f"Validando foto: {temp_filepath}")
    ia_tags = analizar_foto_con_ia(temp_filepath)
    es_mascota_valida = ia_tags.get('es_mascota') == 'Si'
    if es_mascota_valida:
        print("Foto aprobada por IA. Pidiendo login.")
        session['foto_pendiente'] = unique_name
        session['foto_tags'] = ia_tags
        return redirect(url_for('completar_reporte'))
    else:
        print("Foto rechazada por IA. Borrando.")
        os.remove(temp_filepath)
        flash('Error: La foto fue rechazada. Asegúrate de que sea una foto "amateur" de una mascota (no un comercial, dibujo o meme).', 'error')
        return redirect(url_for('index'))

@app.route('/completar-reporte', methods=['GET', 'POST'])
@login_required 
def completar_reporte():
    if 'foto_pendiente' not in session or 'foto_tags' not in session:
        flash('Error: Debes subir una foto primero.', 'error')
        return redirect(url_for('index'))
    temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], session['foto_pendiente'])
    ia_tags = session['foto_tags']
    if request.method == 'POST':
        estado_reporte = request.form.get('estado')
        manual_lat = request.form.get('manual_lat')
        manual_lng = request.form.get('manual_lng')
        descripcion = request.form.get('descripcion')
        imagen_url_final = None
        try:
            static_path = os.path.join(STATIC_UPLOAD_FOLDER, session['foto_pendiente'])
            if os.path.exists(temp_filepath):
                os.rename(temp_filepath, static_path)
            elif not os.path.exists(static_path):
                raise Exception("Archivo temporal no encontrado")
            imagen_url_final = session['foto_pendiente']
            print(f"Foto movida a: {static_path}")
        except Exception as e:
            print(f"Error al mover la foto: {e}")
            flash("Error de sesión. Por favor, sube la foto de nuevo.", "error")
            session.pop('foto_pendiente', None)
            session.pop('foto_tags', None)
            return redirect(url_for('index'))
        
        exif_lat, exif_lng, exif_fecha, exif_modelo = None, None, None, None
        resultados_exif = obtener_metadatos_gps(static_path)
        if "Error" not in resultados_exif:
            exif_lat = resultados_exif.get('latitud')
            exif_lng = resultados_exif.get('longitud')
            exif_fecha = resultados_exif.get('fecha_foto')
            exif_modelo = resultados_exif.get('modelo_celular')
        final_lat = exif_lat or (float(manual_lat) if manual_lat else None)
        final_lng = exif_lng or (float(manual_lng) if manual_lng else None)
        
        nuevo_reporte = Reporte(
            user_id=current_user.id,
            estado=estado_reporte,
            latitud=final_lat,
            longitud=final_lng,
            descripcion=descripcion,
            fecha_foto=exif_fecha,
            modelo_celular=exif_modelo,
            imagen_url=imagen_url_final,
            ia_es_mascota=ia_tags.get('es_mascota'),
            ia_especie=ia_tags.get('especie'),
            ia_raza=ia_tags.get('raza_aproximada'),
            ia_color_principal=ia_tags.get('color_principal'),
            ia_collar=ia_tags.get('collar'),
            ia_fuente=ia_tags.get('fuente', 'Foto+Texto')
        )
        db.session.add(nuevo_reporte)
        db.session.commit()
        session.pop('foto_pendiente', None)
        session.pop('foto_tags', None)
        flash(f"¡Reporte #{nuevo_reporte.id} ('{nuevo_reporte.estado}') creado con éxito!", "success")
        return redirect(url_for('index', new_report_id=nuevo_reporte.id))
    
    return render_template('completar_reporte.html', foto_url=session['foto_pendiente'], ia_tags=ia_tags)

# --- Código para crear la BBDD ---
with app.app_context():
    db.create_all()

# --- Punto de entrada (para Render) ---
# No incluimos app.run() aquí, Gunicorn se encarga.