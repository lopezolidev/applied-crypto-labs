# applied-crypto-labs
Laboratorios prácticos de criptografía: implementación segura de RSA con PyCryptodome, demostración de ataques por fuerza bruta y simulación del intercambio de claves Diffie-Hellman.

---


# Entorno
 
Debemos iniciar con un entorno virtual en python para descargar los modulos de forma segura.

###### 1. Crear un entorno virtual dentro de la carpeta de tus laboratorios
```python
python3 -m venv crypto_env
```

###### 2. Activar el entorno virtual (notarás que tu prompt cambia)
```python
source crypto_env/bin/activate
```

###### 3. Desinstalar versiones conflictivas (por si acaso)
```python
pip3 uninstall crypto pycrypto -y
```

###### 4. Instalar la librería criptográfica oficial y moderna
```python
pip3 install pycryptodome
```

###### 5. Ejecutar tu script (con el entorno activado)
```python
python3 src/labs/lab2_cifrado_hibrido.py
```

---

# Laboratorio 1: Cifrado Asimétrico Industrial (RSA-OAEP)

## 🎯 Objetivo del Laboratorio
Realizar la transición desde el "RSA de libro de texto" (Textbook RSA) hacia una implementación criptográfica de grado de producción. El objetivo central es mitigar las dos vulnerabilidades matemáticas fundamentales del RSA clásico: el determinismo (el mismo mensaje siempre genera el mismo criptograma) y la maleabilidad homomórfica (la capacidad de alterar matemáticamente el criptograma sin poseer la clave).

## 🧠 Fundamentos Teóricos

El algoritmo RSA puro se basa en la elegancia de la exponenciación modular ($C = M^e \pmod n$), pero esta simplicidad matemática es su mayor debilidad en el mundo real. Si un atacante intercepta un criptograma, aunque no pueda leerlo, puede multiplicarlo por un factor externo y el destinatario legítimo descifrará un mensaje manipulado sin darse cuenta.

Para blindar la matemática de RSA, la industria impone una capa previa conocida como **OAEP (Optimal Asymmetric Encryption Padding)**. 

### El blindaje en tres pasos (OAEP):
1. **Semilla Aleatoria:** OAEP inyecta una semilla dinámica nueva en cada operación. Si cifras la palabra "Ataque" mil veces, obtendrás mil criptogramas radicalmente distintos. Adiós al determinismo.
2. **Red de Feistel (Enredo Cruzado):** Utilizando una Función Generadora de Máscaras (MGF) impulsada por un algoritmo de Hash (SHA-256), OAEP mezcla el mensaje original con la semilla aleatoria mediante operaciones XOR bidireccionales.
3. **Cifrado Final:** El bloque resultante, que ahora es un revoltijo pseudoaleatorio indivisible, es el que finalmente se somete a la ecuación de RSA. Si un atacante altera un solo bit del criptograma en la red, la matemática inversa al descifrar colapsará, los hashes de verificación internos no cuadrarán, y la librería rechazará el mensaje instantáneamente protegiendo la **Integridad**.

## 🛠️ Aspectos Técnicos Relevantes en la Implementación

* **Generación de Llaves de 2048 bits:** El laboratorio automatiza la búsqueda de primos criptográficos ($p$ y $q$) y el cálculo de la función totiente ($\phi(n)$) para generar módulos $n$ de 2048 bits, impenetrables mediante fuerza bruta o factorización con la tecnología clásica actual.
* **Manejo de Excepciones Seguras:** Al fallar la verificación de integridad durante el descifrado, la librería lanza un error genérico (`ValueError`). Esto no es casualidad; es una práctica de seguridad (mitigación de *Padding Oracle Attacks*) para no darle pistas al atacante sobre qué parte exacta de la estructura interna falló.
* **Separación de Responsabilidades:** Se hace evidente que RSA no fue diseñado para cifrar bases de datos ni archivos grandes debido a la pesada carga de procesamiento (exponenciación de números de cientos de dígitos) y al límite de tamaño de bloque.

## 🚀 Requisitos y Ejecución

* **Dependencias:** `pip install pycryptodome`
* **Ejecución:** `python lab1_rsa_oaep.py`

El script ejecuta un flujo *end-to-end* emulando la generación de llaves, el cifrado de un mensaje en texto plano mediante OAEP y el descifrado seguro, finalizando con una prueba empírica que demuestra la destrucción del determinismo.

---

# Laboratorio 2: Criptografía Híbrida y el Sobre Digital (RSA + AES)

## 🎯 Objetivo del Laboratorio
Implementar una arquitectura de Criptografía Híbrida de grado de producción. Este laboratorio resuelve la limitación física fundamental de RSA (incapacidad para cifrar grandes volúmenes de datos y alto coste computacional) fusionándolo con el cifrado simétrico AES-256 en modo GCM.

## 🧠 Fundamentos Teóricos

El sistema RSA es excelente para proteger secretos, pero su matemática escalar (exponenciación modular) lo hace extremadamente lento e impone un límite de tamaño de bloque (~190 bytes para claves de 2048 bits con relleno OAEP). Por otro lado, AES (Estándar de Cifrado Avanzado) es capaz de cifrar gigabytes de información en fracciones de segundo con un consumo mínimo de CPU, pero sufre del "Problema de Distribución de Claves": emisor y receptor deben acordar una misma contraseña previamente.

La **Criptografía Híbrida** resuelve ambos problemas simultáneamente creando un **Sobre Digital**.

### ¿Cómo funciona la arquitectura?
Se delega el trabajo pesado (cifrar el archivo) a la herramienta rápida (AES), y el transporte del secreto (la contraseña de AES) a la herramienta segura de llave pública (RSA).

1. **Cifrado (El Emisor):**
   * Genera una clave simétrica aleatoria temporal (Clave de Sesión AES) de 256 bits.
   * Cifra el documento completo usando AES con esa clave temporal.
   * Cifra la pequeña clave temporal usando RSA con la **Llave Pública del Receptor**.
   * Envía por la red el "Sobre Digital": `[Clave_AES_Cifrada_con_RSA] + [Documento_Cifrado_con_AES]`.

2. **Descifrado (El Receptor):**
   * Extrae la Clave AES cifrada y usa su **Llave Privada RSA** para descifrarla.
   * Usa la Clave AES recién obtenida para descifrar el documento pesado.

## 🛠️ Aspectos Técnicos Relevantes en la Implementación

* **AES-GCM (Galois/Counter Mode):** No se utiliza un cifrado simétrico clásico, sino Cifrado Autenticado (AEAD). El modo GCM genera una etiqueta matemática (`MAC Tag`) durante el cifrado. Al descifrar, el algoritmo recalcula la etiqueta; si difiere por un solo bit, la operación se aborta de inmediato. Esto garantiza la **Integridad** del archivo masivo, previniendo ataques de maleabilidad sobre el canal AES.
* **RSA-OAEP (Optimal Asymmetric Encryption Padding):** Mantiene la seguridad de la fase asimétrica. Al cifrar la pequeña clave de sesión de 32 bytes con RSA, se aplica el relleno OAEP para evitar el determinismo y blindar el intercambio de la clave contra ataques homomórficos.
* **Cero Reutilización (Nonce):** AES-GCM genera un Vector de Inicialización (Nonce) único para cada operación de cifrado, asegurando que cifrar el mismo documento dos veces genere criptogramas radicalmente diferentes.

## 🚀 Requisitos y Ejecución

* **Dependencias:** `pip install pycryptodome`
* **Ejecución:** `python lab2_cifrado_hibrido.py`

El script ejecuta un flujo *end-to-end* que emula la preparación del Sobre Digital, su transmisión teórica, y la apertura estructurada en destino validando Confidencialidad e Integridad.

---

# Laboratorio 3: Firmas Digitales y Autenticación de Identidad (RSA-PSS)

## 🎯 Objetivo del Laboratorio
Implementar un sistema de Firmas Digitales robusto. Mientras que el cifrado protege la información de miradas indiscretas, la firma digital resuelve un problema igual de crítico: probar la identidad del emisor (**Autenticación**), garantizar que el mensaje no cambió un solo bit en tránsito (**Integridad**) y asegurar que el emisor no pueda negar haberlo enviado (**No repudio**).

## 🧠 Fundamentos Teóricos

En la criptografía asimétrica, las llaves funcionan en dos vías. 
* Si encriptas con la *Pública*, solo la *Privada* puede abrirlo (Confidencialidad). 
* Si encriptas algo con tu **Llave Privada**, cualquier persona en el mundo puede abrirlo usando tu **Llave Pública**. 

Esta segunda vía es la base de las firmas digitales: si un documento matemático es "abierto" con éxito usando tu llave pública, significa que **únicamente tu llave privada pudo haberlo "cerrado"**.

### El problema de la eficiencia (Hashing)
Dado que RSA es un algoritmo lento y con limitaciones severas de tamaño, no se "firma" (no se encripta con la llave privada) todo el documento de 10 MB. 

En su lugar, el proceso es:
1. **Reducción:** Se introduce el archivo de 10 MB en una función de *Hash* (como SHA-256), que lo tritura y extrae una huella digital única de apenas 32 bytes.
2. **Firma:** Se cifra únicamente esa huella digital de 32 bytes con la Llave Privada.
3. **Verificación:** El receptor, quien tiene el documento y la firma, calcula el hash del documento por su cuenta. Luego "abre" la firma usando la Llave Pública. Si el Hash que él calculó es idéntico al Hash que sacó de la firma, el documento es auténtico.

## 🛠️ Aspectos Técnicos Relevantes en la Implementación

* **RSA-PSS (Probabilistic Signature Scheme):** Es el estándar de relleno más seguro para firmas en la actualidad. Introduce "sal" (bytes aleatorios) antes de firmar el hash. Si firmas el mismo contrato diez veces, las diez firmas resultantes serán matemáticamente distintas, pero todas validarán correctamente bajo tu llave pública. Esto mitiga vulnerabilidades históricas de firmas predictivas encontradas en el esquema antiguo (PKCS#1 v1.5).
* **SHA-256 (Secure Hash Algorithm 256-bit):** Provee una garantía matemática contra *colisiones* (la imposibilidad práctica de crear un documento falsificado que por casualidad genere el mismo Hash que el documento original).
* **La Independencia del Secreto:** En este laboratorio, el documento en sí mismo no viaja cifrado (viaja en texto plano). El objetivo aquí no es ocultarlo, sino blindar legal y matemáticamente su origen.

## 🚀 Requisitos y Ejecución

* **Dependencias:** `pip install pycryptodome`
* **Ejecución:** `python lab3_firmas_digitales.py`

El script recrea un flujo de emisión y recepción evaluando dos escenarios: un documento íntegro que pasa la validación asimétrica, y la intercepción de un atacante que altera el contenido demostrando cómo el motor criptográfico destruye la confianza y lanza un error.

