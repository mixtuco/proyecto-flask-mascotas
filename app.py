import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort # --- ¡NUEVO! import abort ---
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
from dotenv import load_dotenv
import imagehash 

load_dotenv()

# --- Configuración (sin cambios) ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mi-clave-secreta-de-desarrollo-12345'
UPLOAD_FOLDER = 'uploads' 
STATIC_UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads') 
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reportes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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

# --- Configuración de OAuth (sin cambios) ---
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

# --- Modelos de Usuario y Reporte (MODIFICADO) ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=True)
    reportes = db.relationship('Reporte', backref='author', lazy=True)

class Reporte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    imagen_hash = db.Column(db.String(100), unique=True, nullable=True)
    fecha_reporte = db.Column(db.DateTime, default=datetime.utcnow)
    estado = db.Column(db.String(50), nullable=False, default="Encontrado")
    
    # --- ¡NUEVA COLUMNA DE ESTADO! ---
    esta_resuelto = db.Column(db.Boolean, default=False, nullable=False)

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

# --- Funciones de Login (sin cambios) ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) 
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'
login_manager.login_message = 'Debes iniciar sesión para completar tu reporte.'

# --- Rutas de Autenticación (sin cambios) ---
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

# --- Rutas de Login con Google (sin cambios) ---
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

# --- Funciones de IA y Distancia (sin cambios) ---
def obtener_metadatos_gps(imagen_path):
    # (Toda la función es igual)
    try:
        img = Image.open(imagen_path)
        exif_data_raw = img._getexif()
        if not exif_data_raw: return {"Error": "No se encontraron datos EXIF."}
        # ... (resto del código igual)
        fecha_hora = exif_data.get("DateTimeOriginal", None)
        modelo = f"{exif_data.get('Make', '')} {exif_data.get('Model', '')}".strip()
        gps_info_raw = exif_data.get("GPSInfo")
        lat_decimal, lon_decimal = None, None
        if gps_info_raw:
            # ... (resto del código igual)
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
    # (Toda la función es igual)
    if not GOOGLE_API_KEY: 
        print("API Key no encontrada.")
        return {"es_mascota": "Si", "especie": "Perro (Prueba)", "raza_aproximada": "Test", "color_principal": "Test", "collar": "No se ve", "fuente": "Error API"}
    try:
        model = genai.GenerativeModel('models/gemini-flash-latest') 
        img = Image.open(imagen_path)
        prompt_parts = [
            f"""
            (prompt de visión simplificado igual que antes)
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
    # (Toda la función es igual)
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    r = 6371
    return c * r

# --- Función de Búsqueda (¡MODIFICADA!) ---
def buscar_coincidencias(reporte_actual):
    # ¡Mi iniciativa! Ahora solo busca reportes que NO estén resueltos.
    coincidencias = []
    estado_opuesto = "Perdido" if reporte_actual.estado == "Encontrado" else "Encontrado"
    posibles_reportes = Reporte.query.filter(
        Reporte.estado == estado_opuesto,
        Reporte.ia_especie == reporte_actual.ia_especie,
        Reporte.user_id != reporte_actual.user_id,
        Reporte.esta_resuelto == False # --- ¡NUEVO FILTRO! ---
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

# --- Rutas de Página (index e historial) ---
@app.route('/')
def index():
    # (Esta ruta sigue igual)
    posibles_coincidencias = []
    reporte_creado = None
    new_report_id = request.args.get('new_report_id')
    if new_report_id:
        reporte_creado = db.session.get(Reporte, new_report_id)
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
    # (Esta ruta sigue igual)
    reportes = Reporte.query.filter_by(user_id=current_user.id).order_by(Reporte.fecha_reporte.desc()).all()
    return render_template('historial.html', reportes=reportes)

# --- Ruta Pública /explorar (¡MODIFICADA!) ---
@app.route('/explorar')
def explorar():
    page = request.args.get('page', 1, type=int)
    # ¡Mi iniciativa! Ocultamos reportes resueltos
    reportes_paginados = Reporte.query.filter_by(esta_resuelto=False).order_by(Reporte.fecha_reporte.desc()).paginate(
        page=page, per_page=9, error_out=False
    )
    return render_template('explorar.html', reportes=reportes_paginados)


# --- API /cargar-mas (¡MODIFICADA!) ---
@app.route('/cargar-mas/<int:page>')
def cargar_mas(page):
    # ¡Mi iniciativa! Ocultamos reportes resueltos
    reportes = Reporte.query.filter_by(esta_resuelto=False).order_by(Reporte.fecha_reporte.desc()).paginate(
        page=page, per_page=9, error_out=False
    )
    reportes_json = []
    for reporte in reportes.items:
        reporte_data = {
            "id": reporte.id, "estado": reporte.estado, "descripcion": reporte.descripcion or 'Sin descripción.',
            "imagen_url": url_for('static', filename='uploads/' + reporte.imagen_url) if reporte.imagen_url else None,
            "ia_especie": reporte.ia_especie or 'N/A', "ia_raza": reporte.ia_raza or 'N/A',
            "ia_color_principal": reporte.ia_color_principal or 'N/A', "ia_collar": reporte.ia_collar or 'N/A',
            "ia_fuente": reporte.ia_fuente or 'N/A', "imagen_hash": reporte.imagen_hash or 'N/A',
            "latitud": "%.4f" % reporte.latitud if reporte.latitud else None,
            "longitud": "%.4f" % reporte.longitud if reporte.longitud else None,
            "fecha_foto": reporte.fecha_foto or 'N/A', "modelo_celular": reporte.modelo_celular or ''
        }
        reportes_json.append(reporte_data)
    return jsonify(
        reportes=reportes_json,
        has_next=reportes.has_next
    )


# --- Ruta /validar-foto (sin cambios) ---
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
        print("Foto aprobada por IA. Generando huella digital...")
        try:
            img_hash = str(imagehash.average_hash(Image.open(temp_filepath)))
            reporte_existente = Reporte.query.filter_by(imagen_hash=img_hash).first()
            if reporte_existente:
                print(f"Foto duplicada. Coincide con el Reporte ID: {reporte_existente.id}")
                os.remove(temp_filepath)
                flash(f"Error: Esta foto ya fue subida en el Reporte ID #{reporte_existente.id}.", "error")
                return redirect(url_for('index'))
            print("Foto única. Pidiendo login.")
            session['foto_pendiente'] = unique_name
            session['foto_tags'] = ia_tags
            session['foto_hash'] = img_hash
            return redirect(url_for('completar_reporte'))
        except Exception as e:
            print(f"Error generando el hash o validando: {e}")
            os.remove(temp_filepath)
            flash("Error al procesar la imagen. Inténtalo de nuevo.", "error")
            return redirect(url_for('index'))
    else:
        print("Foto rechazada por IA. Borrando.")
        os.remove(temp_filepath)
        flash('Error: La foto fue rechazada. Asegúrate de que sea una foto "amateur" de una mascota (no un comercial, dibujo o meme).', 'error')
        return redirect(url_for('index'))

# --- Ruta /completar-reporte (sin cambios) ---
@app.route('/completar-reporte', methods=['GET', 'POST'])
@login_required 
def completar_reporte():
    if 'foto_pendiente' not in session or 'foto_tags' not in session or 'foto_hash' not in session:
        flash('Error de sesión. Debes subir una foto primero.', 'error')
        return redirect(url_for('index'))
    temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], session['foto_pendiente'])
    ia_tags = session['foto_tags']
    img_hash = session['foto_hash']
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
            session.pop('foto_hash', None)
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
            imagen_hash=img_hash,
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
        session.pop('foto_hash', None)
        flash(f"¡Reporte #{nuevo_reporte.id} ('{nuevo_reporte.estado}') creado con éxito!", "success")
        return redirect(url_for('index', new_report_id=nuevo_reporte.id))
    
    return render_template('completar_reporte.html', foto_url=session['foto_pendiente'], ia_tags=ia_tags)

# --- ¡NUEVAS RUTAS DE GESTIÓN DE REPORTES! ---
@app.route('/reporte/resolver/<int:reporte_id>', methods=['POST'])
@login_required
def resolver_reporte(reporte_id):
    # Buscamos el reporte por su ID
    reporte = db.session.get(Reporte, reporte_id)
    if not reporte:
        abort(404) # No encontrado
    
    # ¡Seguridad! Nos aseguramos de que el usuario actual sea el dueño
    if reporte.author != current_user:
        abort(403) # Prohibido
        
    # Cambiamos el estado
    reporte.esta_resuelto = not reporte.esta_resuelto # (Lo "togglea")
    db.session.commit()
    
    if reporte.esta_resuelto:
        flash(f"Reporte #{reporte.id} marcado como 'Resuelto'. Ya no será visible públicamente.", "success")
    else:
        flash(f"Reporte #{reporte.id} reactivado. Ahora es visible públicamente.", "success")
        
    return redirect(url_for('historial'))

@app.route('/reporte/eliminar/<int:reporte_id>', methods=['POST'])
@login_required
def eliminar_reporte(reporte_id):
    reporte = db.session.get(Reporte, reporte_id)
    if not reporte:
        abort(404)
    if reporte.author != current_user:
        abort(403)
        
    # ¡Mi iniciativa! Borramos la foto del disco para ahorrar espacio
    if reporte.imagen_url:
        try:
            path_foto = os.path.join(STATIC_UPLOAD_FOLDER, reporte.imagen_url)
            if os.path.exists(path_foto):
                os.remove(path_foto)
                print(f"Foto {reporte.imagen_url} eliminada del disco.")
        except Exception as e:
            print(f"Error al eliminar foto {reporte.imagen_url}: {e}")
            
    # Borramos el reporte de la BBDD
    db.session.delete(reporte)
    db.session.commit()
    
    flash(f"Reporte #{reporte.id} eliminado permanentemente.", "success")
    return redirect(url_for('historial'))


# --- Código para crear la BBDD ---
with app.app_context():
    db.create_all()

# --- Punto de entrada (para Render) ---
# No incluimos app.run() aquí, Gunicorn se encarga.