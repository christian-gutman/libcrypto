# libcrypto

### Cryptographic Functions | Visual FoxPro Cryptographic Library

> ⚠️ **Nota de migración y estado del proyecto:** 
> Este desarrollo pertenecía originalmente a la cuenta `@christiangutman`. Lamentablemente, debido a un robo de hardware, se perdió el acceso definitivo a dicha cuenta y a su repositorio original. 
> 
> Gracias a que el código se encontraba respaldado en diferentes proveedores y servidores externos, logré recuperar las fuentes de manera íntegra. A raíz de este suceso, he tomado la firme decisión de liberar el proyecto, transformándolo en un desarrollo completamente **público y de código abierto** para la comunidad. 
> 
> A partir de ahora, **este repositorio será el hogar oficial y definitivo** para el mantenimiento, actualizaciones y evolución de **libcrypto**. ¡Las contribuciones y reportes de bugs son más que bienvenidos aquí!


# libcrypto

Una librería ligera de criptografía en C/C++ diseñada específicamente para entornos **Windows**, utilizando las APIs nativas de alto rendimiento **BCrypt** y **CryptoAPI (wincrypt)**. 

Este componente provee abstracciones simples para algoritmos de hashing, HMAC (para datos en memoria y streaming de archivos), manipulación Base64 y cifrado simétrico AES-256 sin añadir dependencias pesadas de terceros (como OpenSSL).

## 🚀 Características

* **Cero dependencias externas:** Utiliza las librerías nativas de Windows (`bcrypt.dll`, `crypt32.dll`, `ncrypt.dll`).
* **Hashing Eficiente:** Soporte nativo para MD5, SHA-1, SHA-256, SHA-384 y SHA-512.
* **Procesamiento de Archivos (Streaming):** Funciones optimizadas para calcular hashes y HMACs de archivos grandes sin cargarlos por completo en memoria RAM.
* **Seguridad Simétrica:** Cifrado y descifrado AES-256.
* **Generación Segura:** Creación de Nonces / Salts aleatorios criptográficamente seguros.
* **Compatibilidad ABI:** Diseñada con interfaces en C puro (`extern "C"`) compatibles con C++ y exportables mediante `CORE_API`.

## 📁 Estructura del Repositorio 

```text 
```

## ⚙️ Integración con CMake

Para consumir esta librería en tus proyectos mediante CMake, agrega lo siguiente a tu configuración:

```cmake 
```

> **Nota de Windows:** El archivo de cabecera ya incluye los `#pragma comment(lib, ...)` necesarios, por lo que el enlazador de MSVC resolverá automáticamente las dependencias de las librerías del sistema de Windows.

## 💻 Ejemplo de Uso rápido

```c 
```

## 🛠️ API Referencia resumida

### Hashing & HMAC (Memoria)
* `SHA256(data, len, outHex)` / `SHA512(...)` - Generación de hashes rápidos.
* `HMACSHA256(data, len, key, keyLen, outHex)` - Autenticación de mensajes basada en hash.

### Hashing de Archivos (Streaming)
* `SHA256File(wFilePath, outHex)` - Lee bloques de archivo de forma eficiente usando rutas en formato `wchar_t` (UTF-16 nativo de Windows).

### Cifrado AES-256
* `SecureEncryptString(plainText, key, ppOutBase64Result)` - Cifra una cadena de texto y devuelve automáticamente el resultado codificado en formato Base64 listo para transmitir o almacenar.

## ⚠️ Requisitos del Sistema
* **Sistema Operativo:** Windows 10 o superior / Windows Server 2008 o superior 
* **Compilador:** MSVC (Microsoft Visual C++) o MinGW con soporte de SDK de Windows actualizado.


