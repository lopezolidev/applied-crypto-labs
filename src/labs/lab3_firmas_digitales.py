# =====================================================================
# IMPORTACIONES DE GRADO CRIPTOGRÁFICO (PyCryptodome)
# =====================================================================

# 1. Importamos el estándar RSA para generar las llaves.
from Crypto.PublicKey import RSA

# 2. Importamos la función de resumen criptográfico SHA-256.
# Su labor es triturar un documento (sin importar su tamaño) y convertirlo 
# en una huella digital única (Hash) de 32 bytes de longitud fija.
from Crypto.Hash import SHA256

# 3. Importamos el esquema de firma probabilístico PSS (Probabilistic Signature Scheme).
# PSS añade aleatoriedad a la firma para que firmar el mismo documento
# dos veces genere firmas diferentes, mitigando ataques de falsificación.
from Crypto.Signature import pss

def generar_llaves_rsa():
    """
    Genera un par de llaves RSA de 2048 bits para el EMISOR.
    En las firmas digitales, las llaves pertenecen a quien firma, no a quien recibe.
    """
    llave_privada = RSA.generate(2048)
    llave_publica = llave_privada.publickey()
    return llave_privada, llave_publica

def firmar_documento(archivo_bytes, llave_privada_emisor):
    """
    Firma digitalmente un documento garantizando Autenticidad, Integridad y No repudio.
    Esta acción SOLO la puede hacer el dueño de la llave privada.
    """
    # ---------------------------------------------------------
    # PARTE 1: CREAR EL RESUMEN DEL DOCUMENTO (HASHING)
    # ---------------------------------------------------------
    
    # 1. Creamos un nuevo motor de Hash usando SHA-256
    motor_hash = SHA256.new()
    
    # 2. Introducimos los bytes de nuestro archivo pesado en el motor.
    motor_hash.update(archivo_bytes)
    
    # El objeto 'motor_hash' ahora contiene la huella digital inmutable del archivo.
    # Si alguien altera un solo punto '.' del texto original, esta huella cambiará.

    # ---------------------------------------------------------
    # PARTE 2: CIFRAR EL HASH CON LA LLAVE PRIVADA (FIRMAR)
    # ---------------------------------------------------------
    
    # 3. Creamos el motor de firmas usando el estándar seguro PSS y la LLAVE PRIVADA.
    motor_firma = pss.new(llave_privada_emisor)
    
    # 4. Generamos la firma digital aplicando el motor sobre la huella digital.
    # En matemáticas básicas, esto equivale a: firma = hash^d mod n
    firma_digital = motor_firma.sign(motor_hash)
    
    return firma_digital

def verificar_firma(archivo_bytes, firma_digital, llave_publica_emisor):
    """
    Verifica matemáticamente que el documento no ha sido alterado y
    que provino indudablemente del emisor original.
    """
    # ---------------------------------------------------------
    # PARTE 1: RECALCULAR EL RESUMEN DEL DOCUMENTO RECIBIDO
    # ---------------------------------------------------------
    
    # 1. El receptor calcula el Hash del archivo EXACTAMENTE como lo hizo el emisor.
    motor_hash_recibido = SHA256.new()
    motor_hash_recibido.update(archivo_bytes)
    
    # ---------------------------------------------------------
    # PARTE 2: VERIFICAR LA FIRMA CONTRA EL HASH RECALCULADO
    # ---------------------------------------------------------
    
    # 2. Creamos el motor de firmas PSS pero ahora usando la LLAVE PÚBLICA.
    motor_verificacion = pss.new(llave_publica_emisor)
    
    # 3. Solicitamos al motor que valide si la 'firma_digital' que nos llegó por red
    # coincide matemáticamente con el 'motor_hash_recibido' recién calculado.
    # En matemáticas básicas, el sistema hace: hash_original = firma^e mod n
    # y luego compara si hash_original == hash_recibido.
    try:
        motor_verificacion.verify(motor_hash_recibido, firma_digital)
        # Si la ejecución pasa esta línea sin lanzar error, la firma es auténtica.
        return True
    except (ValueError, TypeError):
        # ValueError ocurre si los cálculos no cuadran (el documento fue alterado 
        # o la firma pertenece a otra persona).
        return False

# ==========================================
# PRUEBA DE EJECUCIÓN (MAIN)
# ==========================================
if __name__ == "__main__":
    print("1. El Emisor genera sus llaves RSA de 2048 bits...")
    llave_privada_emisor, llave_publica_emisor = generar_llaves_rsa()
    
    # El documento original que el Emisor quiere avalar.
    contrato_original = b"Acuerdo oficial: Transfiero la propiedad del servidor AWS a favor del cliente."
    
    print("\n2. El Emisor esta firmando el documento...")
    firma_del_emisor = firmar_documento(contrato_original, llave_privada_emisor)
    
    print(f"   - Tamaño del documento: {len(contrato_original)} bytes")
    print(f"   - Tamaño de la Firma Digital: {len(firma_del_emisor)} bytes")
    
    print("\n3. El Emisor publica su Llave Publica y envia [Documento + Firma] por la red.")
    
    # --- ESCENARIO A: EL DOCUMENTO LLEGA INTACTO ---
    print("\n--- ESCENARIO A: El destinatario recibe los archivos legitimos ---")
    es_valido = verificar_firma(contrato_original, firma_del_emisor, llave_publica_emisor)
    if es_valido:
        print("✅ EXITO: El contrato es integro y sin duda pertenece al Emisor original.")
    else:
        print("❌ ALERTA: La validacion fallo.")
        
    # --- ESCENARIO B: UN ATACANTE MODIFICA EL DOCUMENTO EN LA RED ---
    print("\n--- ESCENARIO B: Un atacante intercepta y modifica el contrato ---")
    contrato_falsificado = b"Acuerdo oficial: Transfiero la propiedad del servidor AWS a favor del atacante."
    
    print("El destinatario intenta verificar el documento alterado usando la misma firma...")
    es_valido_falso = verificar_firma(contrato_falsificado, firma_del_emisor, llave_publica_emisor)
    
    if es_valido_falso:
        print("✅ EXITO (Esto no deberia pasar)")
    else:
        print("❌ ALERTA CRITICA: ¡Documento repudiado! La verificacion fallo matematicamente.")
        print("   -> El sistema detecto que el texto fue manipulado despues de ser firmado.")