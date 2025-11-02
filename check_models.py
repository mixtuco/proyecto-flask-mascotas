import os
import google.generativeai as genai

print("Iniciando script para listar modelos...")

try:
    # 1. Cargar la API Key
    GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')
    if not GOOGLE_API_KEY:
        print("ERROR: No se encontró la variable de entorno GOOGLE_API_KEY.")
        exit()

    genai.configure(api_key=GOOGLE_API_KEY)

    # 2. Pedir la lista de modelos
    print("Conectando a Google AI para obtener la lista de modelos...")

    # Iteramos sobre la lista de modelos que la API nos devuelve
    for model in genai.list_models():
        # Imprimimos solo los modelos que soportan "generateContent" (que es lo que queremos hacer)
        if 'generateContent' in model.supported_generation_methods:
            print(f"Modelo encontrado: {model.name}")

    print("--- Fin de la lista ---")

except Exception as e:
    print(f"Error al conectar con la API de Google: {e}")