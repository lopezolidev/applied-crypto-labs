# =====================================================================
# IMPORTACIONES DE GRADO CRIPTOGRÁFICO (PyCryptodome) - LAB 1
# =====================================================================

# 1. Importamos el estándar RSA.
# Proporciona la matemática fundamental para generar y gestionar el par 
# de llaves asimétricas (pública y privada). En producción, esto reemplaza 
# nuestros cálculos manuales por algoritmos ultra-optimizados que buscan 
# números primos gigantescos para crear llaves seguras (ej. 2048 bits).
from Crypto.PublicKey import RSA

# 2. Importamos el esquema de relleno OAEP (Optimal Asymmetric Encryption Padding).
# Es el "envoltorio inteligente" indispensable para que RSA sea seguro. 
# Inyecta una semilla aleatoria en cada cifrado para destruir el determinismo 
# y aplica un enredo matemático (Red de Feistel) que bloquea la maleabilidad, 
# impidiendo que un atacante modifique el criptograma en tránsito.
from Crypto.Cipher import PKCS1_OAEP

# 3. Importamos la función de resumen SHA-256.
# En este laboratorio, OAEP la utiliza internamente como su Función Generadora 
# de Máscaras (MGF). Su trabajo es expandir la semilla aleatoria para mezclarla 
# con el mensaje usando operaciones de bit (XOR), creando el bloque de datos
# final que será elevado matemáticamente por RSA.
from Crypto.Hash import SHA256

# ==========================================
# FASE 1: GENERACION DE LLAVES SEGURAS
# ==========================================
print("--- 1. GENERACIÓN DE LLAVES DE GRADO INDUSTRIAL ---")

# En lugar de usar '7' y '11', pedimos a la librería que busque
# números primos gigantescos que al multiplicarse (p * q) generen 
# un módulo 'n' de 2048 bits de longitud.
# Esto asegura que n = p * q sea imposible de factorizar con tecnología actual.
llave_privada_obj = RSA.generate(2048)

# La llave pública (e, n) se deriva de la privada.
# e suele ser el estándar de la industria: 65537
llave_publica_obj = llave_privada_obj.publickey()

# En la vida real, exportamos estas llaves a archivos .pem
# para guardarlas de forma segura o compartirlas.
pem_privada = llave_privada_obj.export_key().decode('utf-8')
pem_publica = llave_publica_obj.export_key().decode('utf-8')

print("Llaves generadas en formato PEM (solo mostrando cabeceras):")
print(pem_publica[:60] + "...") 
print(pem_privada[:60] + "...")

# ==========================================
# FASE 2: CIFRADO CON RELLENO OAEP
# ==========================================
print("\n--- 2. CIFRADO (Protegido contra maleabilidad y determinismo) ---")

# Nuestro mensaje ya no es un número simple, es texto (bytes).
mensaje_original = b"Ataque a la base de datos a medianoche"
print(f"Mensaje original: {mensaje_original}")

# Configuramos el "motor de cifrado". 
# 1. Le pasamos la clave pública (e, n).
# 2. Le indicamos que use el estándar de relleno PKCS#1 OAEP.
# 3. Configuramos SHA-256 como la función de Hash (MGF) para el enredo cruzado.
motor_cifrado = PKCS1_OAEP.new(llave_publica_obj, hashAlgo=SHA256)

# Al llamar a encrypt():
# - Genera una semilla aleatoria nueva.
# - Construye el DataBlock con el mensaje, ceros y hashes de control.
# - Aplica el enredo cruzado XOR (Red de Feistel).
# - Al bloque resultante, le aplica RSA clásico: C = Bloque^e mod n
criptograma = motor_cifrado.encrypt(mensaje_original)

print(f"Criptograma (hexadecimal, 256 bytes): {criptograma.hex()[:60]}...")

# ==========================================
# FASE 3: DESCIFRADO Y VERIFICACIÓN
# ==========================================
print("\n--- 3. DESCIFRADO ---")

# Configuramos el "motor de descifrado" para el receptor.
# Requiere la llave privada (d, n) y la configuración exacta de OAEP/Hash
# que usó el emisor.
motor_descifrado = PKCS1_OAEP.new(llave_privada_obj, hashAlgo=SHA256)

# Al llamar a decrypt():
# - Aplica RSA clásico para recuperar el bloque gigante: Bloque = C^d mod n
# - Deshace el enredo cruzado XOR para separar la semilla y el DataBlock.
# - Verifica los hashes de control y los ceros de relleno.
# - Si todo cuadra (no hay maleabilidad), extrae los bytes originales.
# - Si un bit fue alterado, lanza ValueError("Ciphertext with incorrect length" o similar).
try:
    mensaje_recuperado = motor_descifrado.decrypt(criptograma)
    print(f"Mensaje recuperado: {mensaje_recuperado.decode('utf-8')}")
except ValueError as e:
    print(f"❌ ALERTA DE SEGURIDAD: El mensaje fue alterado. {e}")

# Verificación de que el sistema destruye el determinismo:
print("\n--- PRUEBA DE NO-DETERMINISMO ---")
criptograma_2 = motor_cifrado.encrypt(mensaje_original)
print("¿Son iguales los criptogramas del mismo mensaje?")
print(f"Criptograma 1: {criptograma.hex()[:30]}...")
print(f"Criptograma 2: {criptograma_2.hex()[:30]}...")
print("Resultado:", criptograma == criptograma_2)