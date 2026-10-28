# =====================================================================
# IMPORTACIONES DE GRADO CRIPTOGRÁFICO (PyCryptodome)
# =====================================================================

# 1. Importamos el estándar RSA.
# Proporciona la matemática para generar y gestionar el par de llaves 
# asimétricas (pública y privada) de forma segura.
from Crypto.PublicKey import RSA

# 2. Importamos el esquema de relleno OAEP.
# Es el "envoltorio protector" que inyecta aleatoriedad (semillas) a RSA. 
# Mitiga los ataques de maleabilidad y evita el determinismo del cifrado.
from Crypto.Cipher import PKCS1_OAEP

# 3. Importamos AES, el algoritmo de cifrado simétrico.
# Actuará como el "músculo" rápido de la operación. Se encarga de cifrar 
# los datos pesados (el documento real) consumiendo muy pocos recursos.
from Crypto.Cipher import AES

# 4. Importamos el generador de bytes aleatorios (CSPRNG).
# A diferencia de un 'random' normal, este módulo extrae entropía real del 
# sistema operativo. Es vital para crear la Clave de Sesión AES temporal.
from Crypto.Random import get_random_bytes

# 5. Importamos la función de resumen SHA-256.
# OAEP la utiliza internamente como Función Generadora de Máscaras (MGF) 
# para mezclar la semilla con el mensaje y verificar la integridad.
from Crypto.Hash import SHA256

def generar_llaves_rsa():
    """
    Genera un par de llaves RSA de 2048 bits para el receptor.
    """
    llave_privada = RSA.generate(2048)
    llave_publica = llave_privada.publickey()
    return llave_privada, llave_publica

def cifrar_documento(archivo_bytes, llave_publica_receptor):
    """
    Cifra un archivo pesado usando Criptografía Híbrida (Sobre Digital).
    Paso a paso explícito.
    """
    # ---------------------------------------------------------
    # PARTE 1: CIFRADO SIMÉTRICO (AES) - Para el archivo pesado
    # ---------------------------------------------------------
    
    # 1. Generamos una clave AES aleatoria de 256 bits (32 bytes).
    # Esta clave es de un solo uso (Clave de Sesión).
    clave_sesion_aes = get_random_bytes(32)
    
    # 2. Creamos el motor de cifrado AES.
    # Usamos el modo GCM (Galois/Counter Mode) porque además de cifrar, 
    # genera una etiqueta matemática que garantiza que el archivo no sea alterado.
    motor_cifrado_aes = AES.new(clave_sesion_aes, AES.MODE_GCM)
    
    # 3. El motor GCM genera un "Nonce" (Number Used Once). 
    # Es un valor público único necesario para que la matemática de AES arranque.
    nonce_publico_aes = motor_cifrado_aes.nonce
    
    # 4. Ciframos el documento pesado. 
    # El motor nos devuelve el documento cifrado y la etiqueta de autenticidad (MAC).
    documento_cifrado = motor_cifrado_aes.encrypt(archivo_bytes)
    etiqueta_mac = motor_cifrado_aes.digest()

    # ---------------------------------------------------------
    # PARTE 2: CIFRADO ASIMÉTRICO (RSA) - Para proteger la clave AES
    # ---------------------------------------------------------
    
    # 5. Creamos el motor RSA-OAEP usando la llave pública del receptor.
    motor_cifrado_rsa = PKCS1_OAEP.new(llave_publica_receptor, hashAlgo=SHA256)
    
    # 6. Ciframos ÚNICAMENTE la pequeña clave de sesión AES.
    clave_aes_cifrada_por_rsa = motor_cifrado_rsa.encrypt(clave_sesion_aes)
    
    # 7. Empaquetamos todo en el "Sobre Digital" para enviarlo por la red.
    # El sobre contiene las instrucciones para abrir la cerradura y el contenido.
    sobre_digital = {
        "clave_aes_cifrada": clave_aes_cifrada_por_rsa,
        "nonce_aes": nonce_publico_aes,
        "etiqueta_mac_aes": etiqueta_mac,
        "documento_cifrado": documento_cifrado
    }
    
    return sobre_digital

def descifrar_documento(sobre_digital, llave_privada_receptor):
    """
    Abre el Sobre Digital y recupera el documento original.
    """
    # 1. Extraemos los componentes del sobre digital.
    clave_aes_cifrada = sobre_digital["clave_aes_cifrada"]
    nonce_aes = sobre_digital["nonce_aes"]
    etiqueta_mac_aes = sobre_digital["etiqueta_mac_aes"]
    documento_cifrado = sobre_digital["documento_cifrado"]
    
    # ---------------------------------------------------------
    # PARTE 1: DESCIFRADO ASIMÉTRICO (RSA) - Recuperar la clave AES
    # ---------------------------------------------------------
    
    # 2. Creamos el motor RSA-OAEP con la llave privada del receptor.
    motor_descifrado_rsa = PKCS1_OAEP.new(llave_privada_receptor, hashAlgo=SHA256)
    
    # 3. Desciframos la clave de sesión AES.
    clave_sesion_aes = motor_descifrado_rsa.decrypt(clave_aes_cifrada)
    
    # ---------------------------------------------------------
    # PARTE 2: DESCIFRADO SIMÉTRICO (AES) - Recuperar el documento
    # ---------------------------------------------------------
    
    # 4. Reconstruimos el motor AES exactamente con la misma clave y el mismo Nonce.
    motor_descifrado_aes = AES.new(clave_sesion_aes, AES.MODE_GCM, nonce=nonce_aes)
    
    # 5. Desciframos el documento y verificamos la etiqueta MAC al mismo tiempo.
    # Si alguien alteró un solo bit del documento cifrado en la red, 
    # la verificación MAC fallará y arrojará un error.
    try:
        documento_original = motor_descifrado_aes.decrypt_and_verify(
            documento_cifrado, 
            etiqueta_mac_aes
        )
        return documento_original
    except ValueError:
        raise ValueError("ALERTA: El documento fue alterado en tránsito o la clave es incorrecta.")

# ==========================================
# PRUEBA DE EJECUCIÓN (MAIN)
# ==========================================
if __name__ == "__main__":
    print("1. Generando llaves RSA para el Receptor...")
    llave_privada, llave_publica = generar_llaves_rsa()
    
    # Simulamos un documento grande (por ejemplo, 100 MB).
    # Aquí usamos un texto pequeño por simplicidad visual, 
    # pero AES procesaría gigabytes sin problema.
    datos_originales = b"Este es un documento clasificado de altisimo peso y volumen..." * 1000
    print(f"2. Tamaño del documento a cifrar: {len(datos_originales)} bytes.")
    
    print("3. Iniciando Cifrado Híbrido (Creando Sobre Digital)...")
    paquete_red = cifrar_documento(datos_originales, llave_publica)
    
    print("4. Sobre Digital listo para transmisión.")
    print(f"   - Tamaño de Clave AES Cifrada (RSA): {len(paquete_red['clave_aes_cifrada'])} bytes.")
    print(f"   - Tamaño del Documento Cifrado (AES): {len(paquete_red['documento_cifrado'])} bytes.")
    
    print("5. Receptor iniciando Descifrado Híbrido...")
    datos_recuperados = descifrar_documento(paquete_red, llave_privada)
    
    if datos_originales == datos_recuperados:
        print("6. EXITO: El documento fue recuperado con Integridad y Confidencialidad perfectas.")