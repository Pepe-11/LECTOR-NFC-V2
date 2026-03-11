package com.example.desfiresdm;

import android.util.Log;

import com.nxp.nfclib.desfire.DESFireEV3;
import com.nxp.nfclib.desfire.DESFireEV3File;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.interfaces.IKeyData;
import com.nxp.nfclib.KeyType;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Clase que encapsula todas las operaciones DESFire EV3 relevantes para SDM:
 *
 *  1. Leer info básica de la tarjeta (UID, versión, aplicaciones)
 *  2. Crear una aplicación NDEF con soporte SDM
 *  3. Escribir una URL en el fichero NDEF
 *  4. Configurar SDM (Secure Dynamic Messaging) en el fichero
 *  5. Leer el contenido actual del fichero NDEF
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * FLUJO TÍPICO DE CONFIGURACIÓN SDM
 * ─────────────────────────────────────────────────────────────────────────────
 *  1. authenticate()     → autenticarse con la clave maestra de la aplicación
 *  2. createNdefApp()    → crear aplicación NDEF (AID D2760000850101 estándar)
 *  3. writeNdefUrl()     → escribir URL con placeholders para los campos dinámicos
 *  4. configureSdm()     → activar SDM e indicar los offsets de los campos
 *
 * Tras esto, cada vez que un teléfono lee la tarjeta, el EV3 genera una URL como:
 *   https://tu.dominio/nfc?picc=<UID_cifrado>&mac=<MAC>&ctr=<contador>
 * ─────────────────────────────────────────────────────────────────────────────
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    // ── AID estándar para aplicación NDEF (ISO 7816-4 / NFC Forum Type 4) ──
    public static final byte[] NDEF_AID = new byte[]{(byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01};

    // ── File IDs estándar NDEF ───────────────────────────────────────────────
    public static final byte NDEF_CC_FILE_ID    = 0x01; // Capability Container
    public static final byte NDEF_DATA_FILE_ID  = 0x02; // Fichero con el mensaje NDEF

    // ── Tamaño máximo del fichero NDEF ───────────────────────────────────────
    public static final int NDEF_FILE_SIZE = 256; // bytes

    // ── Clave AES-128 por defecto (16 bytes a cero = fábrica) ───────────────
    // ADVERTENCIA: Cambia esto antes de desplegar en producción.
    public static final byte[] DEFAULT_KEY = new byte[16]; // 16 x 0x00

    private final DESFireEV3 card;

    public DesfireOperations(DESFireEV3 card) {
        this.card = card;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. LECTURA DE INFORMACIÓN BÁSICA
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Lee el UID de la tarjeta (7 bytes).
     * No requiere autenticación.
     */
    public byte[] readUid() throws Exception {
        // GetVersion retorna info del chip incluyendo el UID
        IDESFireEV1.VersionInfo version = card.getVersion();
        if (version != null && version.getUID() != null) {
            return version.getUID();
        }
        throw new Exception("No se pudo leer el UID");
    }

    /**
     * Lee la versión del hardware y software de la tarjeta.
     */
    public IDESFireEV1.VersionInfo readVersion() throws Exception {
        return card.getVersion();
    }

    /**
     * Lee la lista de Application IDs presentes en la tarjeta.
     */
    public byte[][] readApplicationIds() throws Exception {
        return card.getApplicationIDs();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. AUTENTICACIÓN
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Autentica con la clave maestra de PICC (nivel tarjeta, key 0).
     * Necesario para crear/borrar aplicaciones.
     *
     * @param masterKey clave AES-128 (16 bytes). Si es null usa la clave por defecto (0x00 * 16)
     */
    public void authenticatePicc(byte[] masterKey) throws Exception {
        byte[] key = (masterKey != null) ? masterKey : DEFAULT_KEY;
        IKeyData keyData = buildKeyData(key);
        card.authenticate(keyData, 0, false, IDESFireEV1.AuthType.Native);
        Log.d(TAG, "Autenticado en PICC con clave maestra");
    }

    /**
     * Selecciona una aplicación por AID y autentica con su clave.
     *
     * @param aid       Application ID (3 bytes para DESFire nativo, 7 para ISO)
     * @param keyNo     Número de clave (0 = clave maestra de app)
     * @param appKey    Clave AES-128 (16 bytes)
     */
    public void selectAndAuthenticate(byte[] aid, int keyNo, byte[] appKey) throws Exception {
        card.selectApplication(aid);
        byte[] key = (appKey != null) ? appKey : DEFAULT_KEY;
        IKeyData keyData = buildKeyData(key);
        card.authenticate(keyData, keyNo, false, IDESFireEV1.AuthType.Native);
        Log.d(TAG, "Seleccionada y autenticada aplicación " + bytesToHex(aid));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. CREAR APLICACIÓN NDEF CON SOPORTE SDM
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Crea la aplicación NDEF estándar (AID D2760000850101) lista para SDM.
     *
     * Necesitas estar autenticado en el PICC antes de llamar esto.
     *
     * Configuración de la app:
     *  - AES-128
     *  - 2 claves: key 0 (maestra) + key 1 (SDM)
     *  - Acceso NDEF libre para lectura sin autenticación
     */
    public void createNdefApp(byte[] appMasterKey) throws Exception {
        // Seleccionar PICC (aplicación raíz)
        card.selectApplication(new byte[]{0x00, 0x00, 0x00});

        // Autenticar en PICC
        authenticatePicc(null);

        // Verificar si la aplicación ya existe
        byte[][] existingApps = card.getApplicationIDs();
        for (byte[] existingAid : existingApps) {
            if (Arrays.equals(existingAid, NDEF_AID)) {
                Log.w(TAG, "La aplicación NDEF ya existe");
                return;
            }
        }

        // Configurar la aplicación: AES, 2 claves, flags ISO
        // KeySettings: [changeKeyAccessRights=0, masterKeyChangeable, listFilesAllowed, createDeleteFilesAllowed, accessRightsChangeable]
        byte keySettings = 0x0F; // configuración por defecto
        byte numberOfKeys = 0x82; // 2 claves (0x80 = AES, 0x02 = 2 claves)

        card.createApplication(NDEF_AID, keySettings, numberOfKeys);
        Log.d(TAG, "Aplicación NDEF creada");

        // Seleccionar la nueva aplicación
        card.selectApplication(NDEF_AID);

        // Autenticar con la clave maestra de la app (por defecto = 0x00 * 16 en nueva app)
        authenticateApp(null, 0);

        // Cambiar clave maestra si se proporcionó una personalizada
        if (appMasterKey != null && !Arrays.equals(appMasterKey, DEFAULT_KEY)) {
            IKeyData newKey = buildKeyData(appMasterKey);
            card.changeKey(0, newKey, KeyType.AES128);
            Log.d(TAG, "Clave maestra de aplicación actualizada");
        }

        // Crear fichero Capability Container (CC) - requerido por NFC Forum Type 4
        createCapabilityContainerFile();

        // Crear fichero NDEF con SDM habilitado
        createNdefDataFile();

        Log.d(TAG, "Aplicación NDEF con SDM configurada correctamente");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. ESCRIBIR URL EN EL FICHERO NDEF
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Escribe una URL en el fichero NDEF de la tarjeta.
     *
     * La URL puede contener placeholders para los campos SDM dinámicos.
     * Ejemplo:
     *   https://sdm.ejemplo.com/nfc?picc=00000000000000000000000000000000&enc=00000000000000000000000000000000&mac=0000000000000000
     *
     * Los ceros son placeholders que la tarjeta sobreescribirá con los datos
     * criptográficos reales en cada lectura.
     *
     * @param url URL completa con placeholders (máx ~200 caracteres para file de 256 bytes)
     */
    public void writeNdefUrl(String url) throws Exception {
        byte[] urlBytes = url.getBytes(StandardCharsets.UTF_8);

        // Construir mensaje NDEF con record tipo URI
        byte[] ndefMessage = buildNdefUriMessage(url);

        if (ndefMessage.length + 2 > NDEF_FILE_SIZE) {
            throw new Exception("URL demasiado larga. Máximo " + (NDEF_FILE_SIZE - 2) + " bytes para el fichero");
        }

        // Seleccionar aplicación NDEF
        card.selectApplication(NDEF_AID);

        // Autenticar con clave maestra de app
        authenticateApp(null, 0);

        // Escribir el mensaje NDEF en el fichero (offset 0, en claro)
        card.writeData(
            NDEF_DATA_FILE_ID,
            0,                  // offset
            ndefMessage.length,
            ndefMessage,
            IDESFireEV1.CommunicationType.Plain
        );

        Log.d(TAG, "URL NDEF escrita: " + url + " (" + ndefMessage.length + " bytes)");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. CONFIGURAR SDM (Secure Dynamic Messaging)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Activa y configura SDM en el fichero NDEF de datos.
     *
     * Esta es la operación más importante: indica a la tarjeta qué campos
     * dinámicos debe insertar en la URL y en qué posición byte exacta.
     *
     * ⚠️  Los offsets deben calcularse con cuidado:
     *     - Son posiciones dentro del fichero NDEF completo
     *     - El mensaje NDEF empieza en el byte 2 (los primeros 2 bytes son el length)
     *     - El record URI tiene una cabecera antes del payload
     *     - El payload es la URL
     *     Usa el método calculateSdmOffsets() para ayudarte.
     *
     * @param config Configuración SDM con URLs y offsets
     */
    public void configureSdm(SdmConfig config) throws Exception {
        // Seleccionar aplicación NDEF
        card.selectApplication(NDEF_AID);

        // Autenticar con clave maestra
        authenticateApp(null, 0);

        // Obtener configuración actual del fichero
        DESFireEV3File.EV3FileSettings settings = card.getDESFireEV3FileSettings(NDEF_DATA_FILE_ID);

        if (!(settings instanceof DESFireEV3File.StdEV3DataFileSettings)) {
            throw new Exception("El fichero " + NDEF_DATA_FILE_ID + " no es un fichero de datos estándar");
        }

        DESFireEV3File.StdEV3DataFileSettings dataSettings =
            (DESFireEV3File.StdEV3DataFileSettings) settings;

        // ── Activar SDM ───────────────────────────────────────────────────────
        dataSettings.setSDMEnabled(true);

        // ── Configurar mirroring de UID ───────────────────────────────────────
        dataSettings.setUIDMirroringEnabled(config.isUidMirroringEnabled());
        if (config.isUidMirroringEnabled()) {
            dataSettings.setUidOffset(config.getPiccDataOffset());
            Log.d(TAG, "UID mirroring offset: " + config.getPiccDataOffset());
        }

        // ── Configurar contador de lecturas ───────────────────────────────────
        dataSettings.setSDMReadCounterEnabled(config.isSdmReadCounterEnabled());
        if (config.isSdmReadCounterEnabled()) {
            dataSettings.setSdmReadCounterOffset(config.getSdmReadCounterOffset());
            Log.d(TAG, "Contador SDM offset: " + config.getSdmReadCounterOffset());
        }

        // ── Configurar límite de lecturas ────────────────────────────────────
        dataSettings.setSDMReadCounterLimitEnabled(config.isSdmReadCounterLimitEnabled());
        if (config.isSdmReadCounterLimitEnabled()) {
            dataSettings.setSdmReadCounterLimit(config.getSdmReadCounterLimit());
        }

        // ── Configurar cifrado de datos (opcional) ────────────────────────────
        dataSettings.setSDMEncryptFileDataEnabled(config.isSdmEncryptionEnabled());
        if (config.isSdmEncryptionEnabled()) {
            dataSettings.setSdmEncryptionOffset(config.getSdmEncOffset());
            dataSettings.setSdmEncryptionLength(config.getSdmEncLength());
            Log.d(TAG, "SDM Encryption offset: " + config.getSdmEncOffset() +
                       " length: " + config.getSdmEncLength());
        }

        // ── Configurar offset del MAC ─────────────────────────────────────────
        dataSettings.setSdmMacOffset(config.getSdmMacOffset());
        dataSettings.setSdmMacInputOffset(config.getSdmMacOffset()); // normalmente igual
        Log.d(TAG, "SDM MAC offset: " + config.getSdmMacOffset());

        // ── Configurar derechos de acceso SDM ────────────────────────────────
        // Formato: byte[] con los access rights
        // [SDMMetaReadKey (0x0E=libre), SDMFileReadKey (0x0E=libre)]
        dataSettings.setSdmAccessRights(new byte[]{config.getSdmAccessRights(), config.getSdmAccessRights()});

        // ── Aplicar configuración a la tarjeta ────────────────────────────────
        card.changeDESFireEV3FileSettings(NDEF_DATA_FILE_ID, dataSettings);

        Log.d(TAG, "SDM configurado correctamente en fichero " + NDEF_DATA_FILE_ID);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. LECTURA DEL FICHERO NDEF
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Lee el contenido del fichero NDEF de la tarjeta.
     * No requiere autenticación si el fichero tiene acceso libre.
     *
     * @return contenido raw del fichero en bytes
     */
    public byte[] readNdefFile() throws Exception {
        card.selectApplication(NDEF_AID);

        byte[] data = card.readData(
            NDEF_DATA_FILE_ID,
            0,              // offset
            0,              // length=0 = leer todo
            IDESFireEV1.CommunicationType.Plain
        );

        Log.d(TAG, "Leídos " + (data != null ? data.length : 0) + " bytes del fichero NDEF");
        return data;
    }

    /**
     * Lee el fichero NDEF y lo interpreta como texto UTF-8.
     */
    public String readNdefAsString() throws Exception {
        byte[] raw = readNdefFile();
        if (raw == null || raw.length < 2) {
            return "(fichero vacío)";
        }
        // Los primeros 2 bytes son el length del mensaje NDEF
        int ndefLength = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
        if (ndefLength == 0 || ndefLength > raw.length - 2) {
            return "(sin mensaje NDEF)";
        }
        return parseNdefUriRecord(raw, 2, ndefLength);
    }

    /**
     * Lee la configuración SDM actual del fichero.
     */
    public DESFireEV3File.StdEV3DataFileSettings readSdmSettings() throws Exception {
        card.selectApplication(NDEF_AID);
        authenticateApp(null, 0);

        DESFireEV3File.EV3FileSettings settings = card.getDESFireEV3FileSettings(NDEF_DATA_FILE_ID);

        if (settings instanceof DESFireEV3File.StdEV3DataFileSettings) {
            return (DESFireEV3File.StdEV3DataFileSettings) settings;
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. CALCULAR OFFSETS SDM
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Calcula automáticamente los offsets SDM para una URL dada.
     *
     * Los placeholders en la URL deben ser cadenas de ceros hexadecimales
     * con la longitud exacta del campo correspondiente:
     *
     *   PICC Data (UID cifrado):   32 caracteres hex = 16 bytes
     *   SDM MAC:                   16 caracteres hex = 8 bytes
     *   SDM Enc (datos cifrados):  variable (múltiplo de 32 chars = 16 bytes)
     *   Read Counter (en claro):   6 caracteres hex = 3 bytes
     *
     * Ejemplo de URL con todos los placeholders:
     *   https://sdm.test/t?e=00000000000000000000000000000000&c=000000&m=0000000000000000
     *
     *   Dónde el placeholder de 32 ceros = PICC/ENC data
     *         el placeholder de 6 ceros  = counter
     *         el placeholder de 16 ceros = MAC
     *
     * @param url URL con placeholders de ceros
     * @param config SdmConfig a rellenar con los offsets calculados
     */
    public void calculateSdmOffsets(String url, SdmConfig config) {
        // El fichero NDEF tiene estructura:
        // [2 bytes length] [NDEF message]
        // El NDEF message = [header bytes del record] [payload = url]
        //
        // Para un URI record NDEF:
        // Byte 0: MB|ME|CF|SR|IL|TNF = 0xD1
        // Byte 1: Type length = 0x01
        // Byte 2: Payload length (1 byte si SR=1)
        // Byte 3: Type = 0x55 ('U')
        // Byte 4: URI Identifier Code (0x04 = "https://")
        // Bytes 5+: URL sin el prefijo "https://"

        // Offset base: 2 (length) + 4 (record header antes del payload URL) + 1 (URI identifier)
        // = 7 bytes antes de que empiece la URL en el fichero
        int urlOffsetInFile = 7;

        // Si la URL empieza por "https://"
        String urlForSearch = url;
        if (url.startsWith("https://")) {
            // El byte 0x04 del URI identifier ya consume "https://"
            urlForSearch = url.substring("https://".length());
            urlOffsetInFile = 7; // [2 bytes len][0xD1][0x01][len][0x55][0x04] = 7
        } else if (url.startsWith("http://")) {
            urlForSearch = url.substring("http://".length());
            urlOffsetInFile = 7;
        }

        // Buscar posiciones de los placeholders en la URL
        // Placeholder PICC (32 hex chars)
        int piccPos = url.indexOf("00000000000000000000000000000000");
        if (piccPos >= 0) {
            // Posición en el fichero = posición en la URL + offset header
            // Pero hay que contar desde el inicio de urlForSearch
            int posInUrl = url.indexOf("00000000000000000000000000000000");
            int protocolLen = url.startsWith("https://") ? "https://".length() : 
                             (url.startsWith("http://") ? "http://".length() : 0);
            config.setPiccDataOffset(urlOffsetInFile + (posInUrl - protocolLen));
            Log.d(TAG, "PICC offset calculado: " + config.getPiccDataOffset());
        }

        // Buscar placeholder MAC (16 hex chars, distinto de los 32)
        // Primero eliminar todos los 32-char placeholders para no confundir
        String urlTemp = url.replaceAll("00000000000000000000000000000000", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        int macPlaceholder16 = urlTemp.indexOf("0000000000000000");
        if (macPlaceholder16 >= 0) {
            int protocolLen = url.startsWith("https://") ? "https://".length() :
                             (url.startsWith("http://") ? "http://".length() : 0);
            config.setSdmMacOffset(urlOffsetInFile + (macPlaceholder16 - protocolLen));
            Log.d(TAG, "MAC offset calculado: " + config.getSdmMacOffset());
        }

        // Buscar placeholder counter (6 hex chars)
        String urlTemp2 = url.replaceAll("0000000000000000", "YYYYYYYYYYYYYYYY")
                             .replaceAll("00000000000000000000000000000000", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        int ctrPlaceholder = urlTemp2.indexOf("000000");
        if (ctrPlaceholder >= 0) {
            int protocolLen = url.startsWith("https://") ? "https://".length() :
                             (url.startsWith("http://") ? "http://".length() : 0);
            config.setSdmReadCounterOffset(urlOffsetInFile + (ctrPlaceholder - protocolLen));
            Log.d(TAG, "Counter offset calculado: " + config.getSdmReadCounterOffset());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MÉTODOS PRIVADOS AUXILIARES
    // ─────────────────────────────────────────────────────────────────────────

    private void authenticateApp(byte[] key, int keyNo) throws Exception {
        byte[] k = (key != null) ? key : DEFAULT_KEY;
        IKeyData keyData = buildKeyData(k);
        card.authenticate(keyData, keyNo, false, IDESFireEV1.AuthType.Native);
    }

    /**
     * Crea el fichero Capability Container (CC) requerido por NFC Forum Type 4.
     * Este fichero de 15 bytes indica al lector cómo acceder al fichero NDEF.
     */
    private void createCapabilityContainerFile() throws Exception {
        // El CC para DESFire EV3 NDEF
        // Access rights: lectura libre (0xE), escritura con key 0 (0x0)
        byte readAccess  = (byte) 0xEE; // libre
        byte writeAccess = (byte) 0x00; // solo key 0

        // Crear fichero estándar de datos (15 bytes = tamaño del CC)
        DESFireEV3File.StdEV3DataFileSettings ccSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                readAccess, readAccess, writeAccess, readAccess, // RW, CAR, R, W
                15,   // tamaño
                false, // SDM deshabilitado en CC
                null   // sin opciones extra
            );

        card.createFile(NDEF_CC_FILE_ID, ccSettings);

        // Escribir el CC estándar
        byte[] cc = new byte[]{
            0x00, 0x0F,       // CCLEN = 15
            0x20,             // Mapping version 2.0
            0x00, (byte)(NDEF_FILE_SIZE >> 8), (byte)NDEF_FILE_SIZE, // MLe (max NDEF read)
            0x00, (byte)0xFF, // MLc (max NDEF write)
            0x04,             // T = 04 (NDEF File Control TLV)
            0x06,             // L = 06
            0x00, NDEF_DATA_FILE_ID,  // File ID
            0x00, (byte)(NDEF_FILE_SIZE >> 8), (byte)NDEF_FILE_SIZE, // max NDEF size
            0x00,             // read access = free
            (byte)0x80        // write access = key 0
        };

        card.writeData(NDEF_CC_FILE_ID, 0, cc.length, cc, IDESFireEV1.CommunicationType.Plain);
        Log.d(TAG, "Fichero CC creado y escrito");
    }

    /**
     * Crea el fichero NDEF de datos con soporte SDM.
     */
    private void createNdefDataFile() throws Exception {
        // Acceso: lectura libre, escritura con clave 0
        byte readAccess  = (byte) 0xEE; // libre (sin autenticación)
        byte writeAccess = (byte) 0x00; // key 0

        DESFireEV3File.StdEV3DataFileSettings ndefSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                readAccess, readAccess, writeAccess, readAccess,
                NDEF_FILE_SIZE,
                false, // SDM se activa después con changeDESFireEV3FileSettings
                null
            );

        card.createFile(NDEF_DATA_FILE_ID, ndefSettings);
        Log.d(TAG, "Fichero NDEF de datos creado (" + NDEF_FILE_SIZE + " bytes)");
    }

    /**
     * Construye un mensaje NDEF con un URI record.
     *
     * Estructura del mensaje:
     * [2 bytes NLEN] [NDEF record]
     *
     * NDEF record:
     * [0xD1] MB+ME+SR+TNF=Well-Known
     * [0x01] Type Length = 1
     * [len]  Payload Length
     * [0x55] Type = 'U' (URI)
     * [0x04] URI Identifier = "https://"  (o 0x03 para "http://")
     * [url sin prefijo...]
     */
    private byte[] buildNdefUriMessage(String url) {
        byte uriIdentifier;
        String payload;

        if (url.startsWith("https://")) {
            uriIdentifier = 0x04;
            payload = url.substring("https://".length());
        } else if (url.startsWith("http://")) {
            uriIdentifier = 0x03;
            payload = url.substring("http://".length());
        } else {
            uriIdentifier = 0x00; // sin abreviación
            payload = url;
        }

        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        // Payload = [uri_identifier] + [url_bytes]
        int payloadLen = 1 + payloadBytes.length;

        // Construir el record
        byte[] record = new byte[4 + payloadLen]; // header(4) + payload
        record[0] = (byte) 0xD1; // MB=1, ME=1, SR=1, TNF=Well-Known
        record[1] = 0x01;        // Type Length
        record[2] = (byte) payloadLen; // Payload Length (SR=1, 1 byte)
        record[3] = 0x55;        // Type = 'U'
        record[4] = uriIdentifier;
        System.arraycopy(payloadBytes, 0, record, 5, payloadBytes.length);

        // Añadir los 2 bytes de NLEN al inicio
        byte[] message = new byte[2 + record.length];
        message[0] = (byte) ((record.length >> 8) & 0xFF);
        message[1] = (byte) (record.length & 0xFF);
        System.arraycopy(record, 0, message, 2, record.length);

        return message;
    }

    /**
     * Intenta parsear un URI record de un buffer NDEF raw.
     */
    private String parseNdefUriRecord(byte[] buffer, int offset, int length) {
        try {
            // Record header: [flags][typeLen][payloadLen][type][payload...]
            if (length < 5) return new String(buffer, offset, length, StandardCharsets.UTF_8);
            // byte 0 = flags, byte 1 = typeLen, byte 2 = payloadLen (si SR)
            int typeLen = buffer[offset + 1] & 0xFF;
            int payloadLen = buffer[offset + 2] & 0xFF;
            int payloadStart = offset + 3 + typeLen;

            if (payloadStart >= buffer.length || payloadLen < 1) return "(error parse NDEF)";

            byte uriId = buffer[payloadStart];
            String prefix = uriIdToPrefix(uriId);
            String rest = new String(buffer, payloadStart + 1, payloadLen - 1, StandardCharsets.UTF_8);
            return prefix + rest;
        } catch (Exception e) {
            return "(error: " + e.getMessage() + ")";
        }
    }

    private String uriIdToPrefix(byte id) {
        switch (id & 0xFF) {
            case 0x01: return "http://www.";
            case 0x02: return "https://www.";
            case 0x03: return "http://";
            case 0x04: return "https://";
            default:   return "";
        }
    }

    /**
     * Construye un IKeyData AES-128 a partir de un array de bytes.
     */
    private IKeyData buildKeyData(byte[] keyBytes) {
        // La forma de construir IKeyData depende del SDK.
        // NxpNfcLib provee una implementación interna:
        return com.nxp.nfclib.desfire.DESFireKeyUtils.getKey(keyBytes, KeyType.AES128);
    }

    // ── Utilidad ──────────────────────────────────────────────────────────────

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
