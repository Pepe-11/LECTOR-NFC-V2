# DESFire EV3 SDM Tool

Aplicación Android para leer, escribir y configurar **Secure Dynamic Messaging (SDM)** en tarjetas **MIFARE DESFire EV3** usando el SDK TapLinx de NXP.

---

## 📋 Requisitos

| Requisito | Versión/Detalles |
|-----------|-----------------|
| Android Studio | Hedgehog o superior |
| Android SDK | API 26 (Android 8.0) mínimo |
| Dispositivo | Android con NFC |
| Tarjeta | MIFARE DESFire EV3 |
| SDK NXP | TapLinx v5.0.0 (incluido como `.aar`) |
| API Key | Cuenta en https://www.nxp.com/taplinx |

---

## 🚀 Configuración inicial

### 1. Obtener API Key de TapLinx

1. Regístrate en [NXP TapLinx](https://www.nxp.com/taplinx)
2. Crea una nueva aplicación
3. Copia tu API Key

### 2. Configurar la API Key en el proyecto

Abre `app/src/main/java/com/example/desfiresdm/NfcManager.java` y sustituye:

```java
public static final String TAPLINX_API_KEY = "PUT_YOUR_TAPLINX_API_KEY_HERE";
```

por tu clave real.

### 3. Abrir en Android Studio

```
File → Open → selecciona la carpeta DesfireSDM
```

### 4. Compilar y ejecutar

```
Build → Make Project
Run → Run 'app'
```

---

## 📱 Funcionalidades

### 📖 Leer Tarjeta
- UID de la tarjeta (7 bytes)
- Versión hardware/software
- Lista de aplicaciones presentes
- Contenido del fichero NDEF (URL)
- Configuración SDM activa

### ✏️ Escribir URL NDEF
Escribe una URL en el fichero NDEF de la tarjeta.

La URL puede incluir **placeholders de ceros** para los campos dinámicos SDM:

| Campo | Placeholder | Longitud |
|-------|------------|----------|
| PICC Data (UID cifrado) | `00000000000000000000000000000000` | 32 hex = 16 bytes |
| MAC | `0000000000000000` | 16 hex = 8 bytes |
| Contador | `000000` | 6 hex = 3 bytes |

**Ejemplo de URL con SDM completo:**
```
https://sdm.nfctron.com/st?p=00000000000000000000000000000000&m=0000000000000000
```

### 🔐 Configurar SDM (Secure Dynamic Messaging)

Configura la tarjeta para que genere automáticamente los valores dinámicos en cada lectura NFC.

**Opciones:**
- ✅ **UID Mirroring**: El UID de la tarjeta se inserta cifrado en la URL
- ✅ **Contador de lecturas**: Se incrementa con cada lectura
- ⬜ **Cifrado de datos**: Parte del contenido se cifra
- ⬜ **Límite de lecturas**: La tarjeta deja de responder tras N lecturas

---

## 🔐 Concepto SDM explicado

Cuando SDM está activo, cada vez que un teléfono lee la tarjeta:

1. La tarjeta genera criptográficamente:
   - **PICC Data**: UID cifrado con AES + contador
   - **MAC**: Firma del mensaje con clave SDM
   - *(opcional)* **datos cifrados** del fichero

2. Inserta estos valores en los placeholders de la URL

3. El lector recibe una URL como:
   ```
   https://sdm.nfctron.com/st?p=EF963FF7828658A599F3041510671E88&m=94EED9EE65337086
   ```

4. Tu servidor verifica la autenticidad con la misma clave AES

**Esto permite:**
- Detectar clonación (cada lectura tiene MAC diferente)
- Contar lecturas en el servidor
- Vincular cada tap con un UID verificado criptográficamente

---

## 🏗️ Estructura del proyecto

```
DesfireSDM/
├── app/
│   ├── libs/
│   │   └── NxpNfcAndroidLib-release-protected.aar  ← SDK NXP
│   └── src/main/
│       ├── java/com/example/desfiresdm/
│       │   ├── NfcManager.java          ← Gestión NFC y SDK TapLinx
│       │   ├── DesfireOperations.java   ← Operaciones DESFire EV3
│       │   ├── SdmConfig.java           ← Modelo configuración SDM
│       │   ├── MainActivity.java        ← Pantalla principal
│       │   ├── ReadCardActivity.java    ← Lectura de tarjeta
│       │   ├── WriteUrlActivity.java    ← Escritura URL NDEF
│       │   └── SdmConfigActivity.java  ← Configuración SDM
│       ├── res/xml/
│       │   └── nfc_tech_filter.xml     ← Filtro tecnologías NFC
│       └── AndroidManifest.xml
└── build.gradle
```

---

## ⚠️ Notas importantes

### Claves criptográficas
- Las tarjetas DESFire EV3 nuevas tienen la clave maestra por defecto: **16 bytes a 0x00**
- Debes cambiar esta clave en producción
- Las claves se usan para autenticar antes de escribir o cambiar configuración

### Offsets SDM
Los offsets indican la posición exacta (en bytes) dentro del fichero NDEF donde la tarjeta insertará los campos dinámicos. Se calculan automáticamente a partir de los placeholders en la URL.

### Servidor de validación
Para validar las URLs dinámicas en el servidor necesitas:
- La clave SDM (SesSDMFileReadMAC o SesSDMENCFileReadKey)
- Implementar la verificación AES-128 CMAC
- Ver: [NXP AN12196 - MIFARE DESFire Light Features](https://www.nxp.com/docs/en/application-note/AN12196.pdf)

---

## 📚 Referencias

- [TapLinx SDK Documentation](https://www.nxp.com/taplinx)
- [MIFARE DESFire EV3 Product Page](https://www.nxp.com/products/rfid-nfc/mifare-hf/mifare-desfire/mifare-desfire-ev3)
- [AN12196 - SDM Feature Description](https://www.nxp.com/docs/en/application-note/AN12196.pdf)
- [SDM Backend Example (nfcdeveloper.com)](https://github.com/nfcdeveloper/sdm-backend)
