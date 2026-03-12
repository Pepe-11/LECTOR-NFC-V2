package com.example.desfiresdm;

import android.util.Log;

import com.nxp.nfclib.KeyType;
import com.nxp.nfclib.desfire.DESFireEV3File;
import com.nxp.nfclib.desfire.EV3ApplicationKeySettings;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.IDESFireEV3;
import com.nxp.nfclib.defaultimpl.KeyData;
import com.nxp.nfclib.interfaces.IKeyData;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Operaciones DESFire EV3 — replicando el flujo del script Python nfc_writer.py
 *
 * DIFERENCIA CLAVE respecto a la versión anterior:
 * El script Python crea la aplicación con ISO DF Name y los ficheros con ISO File IDs
 * (E103 para CC, E104 para NDEF). Esto es IMPRESCINDIBLE para que los móviles Android
 * e iOS lean NDEF por la vía ISO 7816 estándar.
 *
 * Sin ISO File IDs los móviles no encuentran el NDEF aunque los datos sean correctos.
 *
 * Estructura que crea el Python (y que replicamos aquí):
 *   App AID:    D2 76 00
 *   ISO DF Name: D2 76 00 00 85 01 01  ← nombre estándar NDEF
 *   File 01 CC:  ISO ID E1 03, tamaño 15, acceso EE (libre)
 *   File 02 NDEF: ISO ID E1 04, tamaño 255, acceso EE (libre)
 *
 * Autenticación:
 *   Tarjetas de fábrica / formateadas con Python → DES 8 bytes (clave 00..00)
 *   Tarjetas formateadas con esta app → AES-128 (clave 00..00)
 *   La app detecta automáticamente y migra DES→AES si es necesario para SDM.
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    // ── AIDs y File IDs ───────────────────────────────────────────────────────
    public static final byte[] NDEF_AID          = new byte[]{(byte)0xD2, 0x76, 0x00};
    public static final int    NDEF_CC_FILE_ID   = 0x01;
    public static final int    NDEF_DATA_FILE_ID = 0x02;
    public static final int    NDEF_FILE_SIZE    = 255;

    // ISO DF Name estándar para NDEF (idéntico al script Python)
    // Necesario para que los móviles encuentren la app por ISO SELECT
    private static final byte[] ISO_DF_NAME = new byte[]{
        (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01
    };

    // ISO File IDs — CRÍTICO para lectura NDEF en móviles
    // El CC debe tener ISO ID E103, el NDEF debe tener ISO ID E104
    private static final byte[] ISO_FILE_ID_CC   = new byte[]{(byte)0xE1, 0x03};
    private static final byte[] ISO_FILE_ID_NDEF = new byte[]{(byte)0xE1, 0x04};

    // Claves de fábrica
    public static final byte[] DEFAULT_KEY_AES = new byte[16]; // 16 x 0x00
    public static final byte[] DEFAULT_KEY_DES = new byte[8];  // 8  x 0x00

    // CC correcto — apunta a E104 (imprescindible para móviles)
    // Idéntico al CC_DATA del script Python
    private static final byte[] CC_DATA = new byte[]{
        0x00, 0x0F,              // Tamaño CC: 15 bytes
        0x20,                    // Versión NDEF 2.0
        0x00, 0x7F,              // Max lectura
        0x00, 0x73,              // Max escritura
        0x04, 0x06,              // NDEF File Control TLV
        (byte)0xE1, 0x04,        // ISO File ID E104 ← clave para móviles
        0x00, (byte)0xFF,        // Max NDEF: 255 bytes
        0x00,                    // Lectura libre
        0x00                     // Escritura libre
    };

    private final IDESFireEV1 cardV1;
    private final IDESFireEV3 cardV3;

    public DesfireOperations(IDESFireEV3 card) {
        this.cardV3 = card;
        this.cardV1 = card;
    }

    /** Constructor sin tarjeta (solo para calcular offsets en preview) */
    public DesfireOperations() {
        this.cardV3 = null;
        this.cardV1 = null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LECTURA BÁSICA
    // ─────────────────────────────────────────────────────────────────────────

    public IDESFireEV1.CardDetails readCardDetails() throws Exception {
        return cardV1.getCardDetails();
    }

    @SuppressWarnings("unchecked")
    public ArrayList<byte[]> readApplicationIds() throws Exception {
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        Object result = cardV1.getApplicationIDs();
        if (result instanceof ArrayList) {
            return (ArrayList<byte[]>) result;
        }
        if (result instanceof int[]) {
            int[] ids = (int[]) result;
            ArrayList<byte[]> list = new ArrayList<>();
            for (int id : ids) {
                list.add(new byte[]{
                    (byte)(id & 0xFF),
                    (byte)((id >> 8) & 0xFF),
                    (byte)((id >> 16) & 0xFF)
                });
            }
            return list;
        }
        return new ArrayList<>();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AUTENTICACIÓN CON DETECCIÓN AUTOMÁTICA DES / AES
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Autentica en el PICC. Prueba AES primero, luego DES.
     * @return true si la tarjeta usó DES (necesita migración a AES para SDM)
     */
    private boolean authenticatePiccAuto(byte[] masterKey) throws Exception {
        try {
            byte[] key = (masterKey != null && masterKey.length == 16) ? masterKey : DEFAULT_KEY_AES;
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128, buildKeyData(key, "AES"));
            Log.d(TAG, "Auth PICC AES OK");
            return false;
        } catch (Exception e) {
            Log.w(TAG, "Auth PICC AES falló, probando DES: " + e.getMessage());
        }
        try {
            byte[] key = (masterKey != null && masterKey.length == 8) ? masterKey : DEFAULT_KEY_DES;
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES, buildKeyData(key, "DES"));
            Log.d(TAG, "Auth PICC DES OK");
            return true;
        } catch (Exception e) {
            throw new Exception("No se pudo autenticar en el PICC. Clave no reconocida.");
        }
    }

    /**
     * Autentica en la aplicación NDEF. Prueba AES primero, luego DES.
     * @return true si usó DES
     */
    private boolean authenticateAppAuto(byte[] appKey, int keyNo) throws Exception {
        try {
            byte[] key = (appKey != null && appKey.length == 16) ? appKey : DEFAULT_KEY_AES;
            cardV1.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.AES128, buildKeyData(key, "AES"));
            Log.d(TAG, "Auth App AES OK");
            return false;
        } catch (Exception e) {
            Log.w(TAG, "Auth App AES falló, probando DES: " + e.getMessage());
        }
        try {
            byte[] key = (appKey != null && appKey.length == 8) ? appKey : DEFAULT_KEY_DES;
            cardV1.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, buildKeyData(key, "DES"));
            Log.d(TAG, "Auth App DES OK");
            return true;
        } catch (Exception e) {
            throw new Exception("No se pudo autenticar en la app. Clave no reconocida.");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CREAR APLICACIÓN NDEF COMPLETA (con ISO File IDs — igual que el Python)
    //
    // Este es el método principal. Replica exactamente lo que hace formatear()
    // en el script Python:
    //   1. Selecciona Master App y autentica
    //   2. Borra la app NDEF si existe
    //   3. Crea la app con ISO DF Name D2760000850101
    //   4. Crea File 01 (CC) con ISO ID E103
    //   5. Crea File 02 (NDEF) con ISO ID E104
    //   6. Escribe el CC correcto
    //   7. Inicializa el NDEF con 0x0000
    // ─────────────────────────────────────────────────────────────────────────

    public void createNdefApp(byte[] appMasterKey) throws Exception {
        Log.i(TAG, "=== createNdefApp: creando app con ISO File IDs ===");

        // 1. Seleccionar Master App y autenticar
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        boolean wasDes = authenticatePiccAuto(null);
        Log.d(TAG, "PICC auth OK, wasDes=" + wasDes);

        // 2. Borrar app NDEF si ya existe
        ArrayList<byte[]> existingApps = readApplicationIds();
        for (byte[] aid : existingApps) {
            if (Arrays.equals(aid, NDEF_AID)) {
                Log.w(TAG, "App NDEF ya existe — borrando para recrear con ISO IDs");
                // Re-seleccionar y autenticar antes de borrar (requerido por DESFire)
                cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
                if (wasDes) {
                    cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
                        buildKeyData(DEFAULT_KEY_DES, "DES"));
                } else {
                    cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
                        buildKeyData(DEFAULT_KEY_AES, "AES"));
                }
                try {
                    cardV1.deleteApplication(NDEF_AID);
                    Log.d(TAG, "App NDEF borrada");
                } catch (Exception e) {
                    Log.w(TAG, "deleteApplication: " + e.getMessage());
                }
                // Re-autenticar tras borrar (DESFire lo requiere)
                cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
                if (wasDes) {
                    cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
                        buildKeyData(DEFAULT_KEY_DES, "DES"));
                } else {
                    cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
                        buildKeyData(DEFAULT_KEY_AES, "AES"));
                }
                break;
            }
        }

        // 3. Crear la aplicación NDEF con AES + ISO DF Name
        //    Equivalente al CreateApplication del Python con payload:
        //    DESFIRE_AID + [0x0F, 0x21] + [0x10, 0xE1] + ISO_DF_NAME
        //    - 0x0F = 1 clave, auth requerida para todo salvo lectura
        //    - 0x21 = AES, 2 claves máx
        //    - 0x10, 0xE1 = número de claves con flags ISO
        EV3ApplicationKeySettings keySettings = new EV3ApplicationKeySettings.Builder()
            .setKeyTypeOfApplicationKeys(KeyType.AES128)
            .setMaxNumberOfApplicationKeys(2)
            .setAppMasterKeyChangeable(true)
            .setAppKeySettingsChangeable(true)
            .setAuthenticationRequiredForFileManagement(false)
            // ISO DF Name — permite que los móviles seleccionen la app por nombre ISO
            .setISODFName(ISO_DF_NAME)
            .build();

        cardV3.createApplication(NDEF_AID, keySettings);
        Log.d(TAG, "App NDEF creada con AES + ISO DF Name");

        // 4. Seleccionar la nueva app y autenticar con AES (siempre AES aunque el PICC era DES)
        cardV1.selectApplication(NDEF_AID);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
            buildKeyData(DEFAULT_KEY_AES, "AES"));

        // Cambiar clave si se proporcionó una personalizada
        if (appMasterKey != null && !Arrays.equals(appMasterKey, DEFAULT_KEY_AES)) {
            cardV1.changeKey(0, KeyType.AES128, appMasterKey, DEFAULT_KEY_AES, (byte)0x01);
            Log.d(TAG, "Clave de app cambiada");
        }

        // 5. Crear ficheros con ISO File IDs (clave del funcionamiento NDEF en móviles)
        createCapabilityContainerFile();  // File 01 → ISO ID E103
        createNdefDataFile();             // File 02 → ISO ID E104

        // 6. Escribir CC correcto (apuntando a E104)
        cardV1.writeData(NDEF_CC_FILE_ID, 0, CC_DATA);
        Log.d(TAG, "CC escrito: " + bytesToHex(CC_DATA));

        // 7. Inicializar NDEF con longitud 0x0000 (tarjeta "vacía" pero válida)
        cardV1.writeData(NDEF_DATA_FILE_ID, 0, new byte[]{0x00, 0x00});
        Log.i(TAG, "App NDEF lista con ISO File IDs — tarjeta legible por móviles");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ESCRIBIR URL NDEF
    // ─────────────────────────────────────────────────────────────────────────

    public void writeNdefUrl(String url) throws Exception {
        byte[] ndefMessage = buildNdefUriMessage(url);
        if (ndefMessage.length > NDEF_FILE_SIZE) {
            throw new Exception("URL demasiado larga (" + ndefMessage.length + " bytes, máx " + NDEF_FILE_SIZE + ").");
        }

        Log.i(TAG, "writeNdefUrl: " + url);

        // Seleccionar app NDEF
        cardV1.selectApplication(NDEF_AID);

        // Intentar autenticación (detecta DES o AES)
        boolean wasDes = false;
        boolean authOk = false;
        try {
            wasDes = authenticateAppAuto(null, 0);
            authOk = true;
        } catch (Exception e) {
            // La tarjeta puede tener acceso libre (access rights EE) sin necesitar auth
            Log.w(TAG, "Auth falló, intentando escritura sin auth (acceso libre): " + e.getMessage());
        }

        if (authOk && wasDes) {
            // Tarjeta en DES (formateada con Python) — reformatear a AES antes de escribir
            Log.i(TAG, "Tarjeta DES — reformateando a AES...");
            reformatCardToAes(url);
            return;
        }

        // Escribir el mensaje NDEF
        cardV1.writeData(NDEF_DATA_FILE_ID, 0, ndefMessage);
        Log.d(TAG, "URL escrita OK: " + url + " (" + ndefMessage.length + " bytes)");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // REFORMATEO DES → AES (mantiene ISO File IDs)
    // ─────────────────────────────────────────────────────────────────────────

    private void reformatCardToAes(String url) throws Exception {
        Log.i(TAG, "=== reformatCardToAes ===");

        // 1. Autenticar en PICC con DES
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
            buildKeyData(DEFAULT_KEY_DES, "DES"));

        // 2. Borrar app NDEF
        try {
            cardV1.deleteApplication(NDEF_AID);
            Log.d(TAG, "App NDEF borrada");
        } catch (Exception e) {
            Log.w(TAG, "deleteApplication: " + e.getMessage());
        }

        // 3. Re-autenticar (DESFire lo exige tras deleteApplication)
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
            buildKeyData(DEFAULT_KEY_DES, "DES"));

        // 4. Crear app AES con ISO DF Name
        EV3ApplicationKeySettings keySettings = new EV3ApplicationKeySettings.Builder()
            .setKeyTypeOfApplicationKeys(KeyType.AES128)
            .setMaxNumberOfApplicationKeys(2)
            .setAppMasterKeyChangeable(true)
            .setAppKeySettingsChangeable(true)
            .setAuthenticationRequiredForFileManagement(false)
            .setISODFName(ISO_DF_NAME)
            .build();

        cardV3.createApplication(NDEF_AID, keySettings);
        Log.d(TAG, "App AES con ISO DF Name creada");

        // 5. Seleccionar y autenticar con AES
        cardV1.selectApplication(NDEF_AID);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
            buildKeyData(DEFAULT_KEY_AES, "AES"));

        // 6. Crear ficheros con ISO File IDs
        createCapabilityContainerFile();
        createNdefDataFile();

        // 7. Escribir CC y NDEF
        cardV1.writeData(NDEF_CC_FILE_ID, 0, CC_DATA);
        byte[] ndefMessage = buildNdefUriMessage(url);
        cardV1.writeData(NDEF_DATA_FILE_ID, 0, ndefMessage);

        Log.i(TAG, "Reformateo DES→AES completado, URL escrita: " + url);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURAR SDM
    // ─────────────────────────────────────────────────────────────────────────

    public void configureSdm(SdmConfig config) throws Exception {
        Log.i(TAG, "=== configureSdm ===");

        cardV1.selectApplication(NDEF_AID);

        // Autenticar con AES (SDM requiere AES en EV3)
        // Si la tarjeta está en DES, primero migrarla
        boolean wasDes = false;
        try {
            wasDes = authenticateAppAuto(null, 0);
        } catch (Exception e) {
            throw new Exception("No se pudo autenticar para SDM: " + e.getMessage());
        }

        if (wasDes) {
            Log.i(TAG, "Tarjeta DES — migrando a AES antes de SDM...");
            String currentUrl = "";
            try {
                byte[] raw = cardV1.readData(NDEF_DATA_FILE_ID, 0, 0);
                if (raw != null && raw.length > 2) {
                    int ndefLen = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
                    if (ndefLen > 0) currentUrl = parseNdefUriRecord(raw, 2, ndefLen);
                }
            } catch (Exception e) {
                Log.w(TAG, "No se pudo leer URL actual: " + e.getMessage());
            }
            if (currentUrl == null || currentUrl.isEmpty()) {
                throw new Exception("Tarjeta en DES sin URL. Escribe una URL primero para migrar a AES.");
            }
            reformatCardToAes(currentUrl);
            // Re-autenticar con AES para continuar
            cardV1.selectApplication(NDEF_AID);
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
                buildKeyData(DEFAULT_KEY_AES, "AES"));
        }

        // Obtener configuración actual del fichero NDEF
        DESFireEV3File.EV3FileSettings settings = cardV3.getDESFireEV3FileSettings(NDEF_DATA_FILE_ID);
        if (!(settings instanceof DESFireEV3File.StdEV3DataFileSettings)) {
            throw new Exception("El fichero NDEF no es StdEV3DataFileSettings. ¿Está la app bien formateada?");
        }

        DESFireEV3File.StdEV3DataFileSettings ds = (DESFireEV3File.StdEV3DataFileSettings) settings;

        // Aplicar configuración SDM
        ds.setSDMEnabled(true);
        ds.setUIDMirroringEnabled(config.isUidMirroringEnabled());
        if (config.isUidMirroringEnabled()) {
            ds.setUidOffset(intTo3Bytes(config.getPiccDataOffset()));
        }
        ds.setSDMReadCounterEnabled(config.isSdmReadCounterEnabled());
        if (config.isSdmReadCounterEnabled()) {
            ds.setSdmReadCounterOffset(intTo3Bytes(config.getSdmReadCounterOffset()));
        }
        ds.setSDMReadCounterLimitEnabled(config.isSdmReadCounterLimitEnabled());
        if (config.isSdmReadCounterLimitEnabled()) {
            ds.setSdmReadCounterLimit(intTo3Bytes(config.getSdmReadCounterLimit()));
        }
        ds.setSDMEncryptFileDataEnabled(config.isSdmEncryptionEnabled());
        if (config.isSdmEncryptionEnabled()) {
            ds.setSdmEncryptionOffset(intTo3Bytes(config.getSdmEncOffset()));
            ds.setSdmEncryptionLength(intTo3Bytes(config.getSdmEncLength()));
        }

        // MAC offset: donde está el placeholder en la URL
        ds.setSdmMacOffset(intTo3Bytes(config.getSdmMacOffset()));

        // MAC Input offset: SIEMPRE desde el inicio del NDEF (offset 2, tras NLEN)
        // Esto es diferente del MAC offset — el MAC se calcula desde el principio del mensaje
        ds.setSdmMacInputOffset(intTo3Bytes(2));

        ds.setSdmAccessRights(new byte[]{config.getSdmAccessRights(), config.getSdmAccessRights()});

        cardV3.changeDESFireEV3FileSettings(NDEF_DATA_FILE_ID, ds);
        Log.d(TAG, "SDM configurado correctamente");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LEER NDEF
    // ─────────────────────────────────────────────────────────────────────────

    public byte[] readNdefFile() throws Exception {
        cardV1.selectApplication(NDEF_AID);
        return cardV1.readData(NDEF_DATA_FILE_ID, 0, 0);
    }

    public String readNdefAsString() throws Exception {
        byte[] raw = readNdefFile();
        if (raw == null || raw.length < 2) return "(vacío)";
        int ndefLength = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
        if (ndefLength == 0 || ndefLength > raw.length - 2) return "(sin NDEF)";
        return parseNdefUriRecord(raw, 2, ndefLength);
    }

    public DESFireEV3File.StdEV3DataFileSettings readSdmSettings() throws Exception {
        cardV1.selectApplication(NDEF_AID);
        try {
            authenticateAppAuto(null, 0);
        } catch (Exception e) {
            Log.w(TAG, "Auth opcional para readSdmSettings: " + e.getMessage());
        }
        DESFireEV3File.EV3FileSettings settings = cardV3.getDESFireEV3FileSettings(NDEF_DATA_FILE_ID);
        if (settings instanceof DESFireEV3File.StdEV3DataFileSettings) {
            return (DESFireEV3File.StdEV3DataFileSettings) settings;
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CALCULAR OFFSETS SDM
    //
    // Layout del fichero NDEF (desde byte 0):
    //   [0..1] NLEN — longitud del record NDEF (2 bytes, big-endian)
    //   [2]    0xD1 — flags NDEF (MB=1, ME=1, SR=0, TNF=001)
    //   [3]    0x01 — Type Length = 1
    //   [4]    payload length (1 byte)
    //   [5]    0x55 — Type = 'U' (URI record)
    //   [6]    URI identifier code (0x04 = https://)
    //   [7..N] URL sin prefijo (p.ej. para https:// se omite "https://")
    //
    // Por tanto el offset base del contenido de la URL = 7
    // Y la posición de un placeholder en la URL = 7 + (posición en url_sin_prefijo)
    // ─────────────────────────────────────────────────────────────────────────

    public void calculateSdmOffsets(String url, SdmConfig config) {
        // Longitud del prefijo que se elimina de la URL al codificar NDEF
        int prefixLen = 0;
        if      (url.startsWith("https://www.")) prefixLen = 12;
        else if (url.startsWith("https://"))     prefixLen = 8;
        else if (url.startsWith("http://www."))  prefixLen = 11;
        else if (url.startsWith("http://"))      prefixLen = 7;

        // Offset base = 7 bytes de cabecera NDEF + 2 bytes NLEN
        // Desglose: NLEN(2) + D1(1) + TypeLen(1) + PayloadLen(1) + Type'U'(1) + UriId(1) = 7
        final int BASE = 7;

        // Buscar placeholder PICC (32 ceros = UID cifrado de 16 bytes en hex)
        int piccPos = url.indexOf("00000000000000000000000000000000");
        if (piccPos >= 0) {
            config.setPiccDataOffset(BASE + (piccPos - prefixLen));
            Log.d(TAG, "PICC offset: " + config.getPiccDataOffset() + " (piccPos=" + piccPos + " prefixLen=" + prefixLen + ")");
        }

        // Buscar placeholder MAC (16 ceros = MAC de 8 bytes en hex)
        // Reemplazar PICC placeholder primero para no confundirlo con el MAC
        String urlSinPicc = url.replace("00000000000000000000000000000000",
                                         "################################");
        int macPos = urlSinPicc.indexOf("0000000000000000");
        if (macPos >= 0) {
            config.setSdmMacOffset(BASE + (macPos - prefixLen));
            Log.d(TAG, "MAC offset: " + config.getSdmMacOffset() + " (macPos=" + macPos + " prefixLen=" + prefixLen + ")");
        }

        // Buscar placeholder contador (6 ceros = counter de 3 bytes en hex)
        String urlSinMac = urlSinPicc.replace("0000000000000000", "################");
        int ctrPos = urlSinMac.indexOf("000000");
        if (ctrPos >= 0) {
            config.setSdmReadCounterOffset(BASE + (ctrPos - prefixLen));
            Log.d(TAG, "Counter offset: " + config.getSdmReadCounterOffset() + " (ctrPos=" + ctrPos + " prefixLen=" + prefixLen + ")");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS PRIVADOS — Creación de ficheros
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Crea el fichero CC (File 01) con ISO File ID E103.
     *
     * Equivalente al comando Python:
     *   [0x90, 0xCD, 0x00, 0x00, 0x09,
     *    0x01, 0x03, 0xE1,          ← file_no=01, ISO ID E103
     *    0x00, 0xE0, 0xEE,          ← Plain, access rights EE
     *    0x0F, 0x00, 0x00, 0x00]    ← tamaño 15 bytes
     */
    private void createCapabilityContainerFile() throws Exception {
        DESFireEV3File.StdEV3DataFileSettings ccSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                (byte)0xEE,   // Read & Write access: libre (E) sin clave
                (byte)0xEE,   // Read access: libre
                (byte)0x00,   // Change access: clave 0
                (byte)0xEE,   // Read/Write access: libre
                15,           // Tamaño = 15 bytes (longitud del CC_DATA)
                (byte)0x00,
                ISO_FILE_ID_CC  // ← ISO File ID E103 — CRÍTICO
            );
        cardV3.createFile(NDEF_CC_FILE_ID, ccSettings);
        Log.d(TAG, "File CC creado con ISO ID E103");
    }

    /**
     * Crea el fichero NDEF (File 02) con ISO File ID E104.
     *
     * Equivalente al comando Python:
     *   [0x90, 0xCD, 0x00, 0x00, 0x09,
     *    0x02, 0x04, 0xE1,          ← file_no=02, ISO ID E104
     *    0x00, 0xE0, 0xEE,          ← Plain, access rights EE
     *    0xFF, 0x00, 0x00, 0x00]    ← tamaño 255 bytes
     */
    private void createNdefDataFile() throws Exception {
        DESFireEV3File.StdEV3DataFileSettings ndefSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                (byte)0xEE,   // Read & Write: libre
                (byte)0xEE,   // Read: libre
                (byte)0x00,   // Change: clave 0
                (byte)0xEE,   // Read/Write: libre
                NDEF_FILE_SIZE, // 255 bytes
                (byte)0x00,
                ISO_FILE_ID_NDEF // ← ISO File ID E104 — CRÍTICO para móviles
            );
        cardV3.createFile(NDEF_DATA_FILE_ID, ndefSettings);
        Log.d(TAG, "File NDEF creado con ISO ID E104");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS PRIVADOS — NDEF
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Construye un mensaje NDEF URI.
     * Formato: [NLEN 2 bytes big-endian][D1 01 payloadLen 55 uriId][url sin prefijo]
     *
     * Tabla de prefijos (igual que el script Python):
     *   0x01 = http://www.
     *   0x02 = https://www.   ← OJO: en el Python 0x02=http:// y 0x03=https://www.
     *   0x03 = http://
     *   0x04 = https://
     */
    private byte[] buildNdefUriMessage(String url) {
        // Usar la misma tabla de prefijos que el script Python
        byte uriId;
        String payload;
        if      (url.startsWith("https://www.")) { uriId = 0x02; payload = url.substring(12); }
        else if (url.startsWith("https://"))     { uriId = 0x04; payload = url.substring(8);  }
        else if (url.startsWith("http://www."))  { uriId = 0x01; payload = url.substring(11); }
        else if (url.startsWith("http://"))      { uriId = 0x03; payload = url.substring(7);  }
        else                                     { uriId = 0x00; payload = url;               }

        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        int payloadLen = 1 + payloadBytes.length; // uriId + url

        // Record: D1 01 <payloadLen> 55 <uriId> <url_bytes>
        byte[] record = new byte[4 + payloadLen];
        record[0] = (byte)0xD1;
        record[1] = 0x01;
        record[2] = (byte)(payloadLen & 0xFF);
        record[3] = 0x55; // Type = 'U'
        record[4] = uriId;
        System.arraycopy(payloadBytes, 0, record, 5, payloadBytes.length);

        // Mensaje: [NLEN high][NLEN low][record]
        byte[] msg = new byte[2 + record.length];
        msg[0] = (byte)((record.length >> 8) & 0xFF);
        msg[1] = (byte)(record.length & 0xFF);
        System.arraycopy(record, 0, msg, 2, record.length);
        return msg;
    }

    private String parseNdefUriRecord(byte[] buf, int offset, int length) {
        try {
            if (length < 5) return new String(buf, offset, length, StandardCharsets.UTF_8);
            int typeLen    = buf[offset + 1] & 0xFF;
            int payloadLen = buf[offset + 2] & 0xFF;
            int payloadStart = offset + 3 + typeLen;
            if (payloadStart >= buf.length || payloadLen < 1) return "(error NDEF)";
            byte uriId = buf[payloadStart];
            String prefix = uriIdPrefix(uriId);
            String rest = new String(buf, payloadStart + 1, payloadLen - 1, StandardCharsets.UTF_8);
            return prefix + rest;
        } catch (Exception e) {
            return "(error: " + e.getMessage() + ")";
        }
    }

    private String uriIdPrefix(byte id) {
        switch (id & 0xFF) {
            case 0x01: return "http://www.";
            case 0x02: return "https://www.";
            case 0x03: return "http://";
            case 0x04: return "https://";
            case 0x05: return "tel:";
            case 0x06: return "mailto:";
            default:   return "";
        }
    }

    private byte[] intTo3Bytes(int v) {
        return new byte[]{
            (byte)(v & 0xFF),
            (byte)((v >> 8) & 0xFF),
            (byte)((v >> 16) & 0xFF)
        };
    }

    /**
     * Construye IKeyData para TapLinx SDK.
     * Para DES de 8 bytes: expande a DESede 24 bytes (K||K||K) porque
     * Java no acepta claves DES de 8 bytes para DESede/3DES.
     */
    private IKeyData buildKeyData(byte[] keyBytes, String algorithm) throws Exception {
        SecretKey secretKey;
        if ("DES".equals(algorithm)) {
            // DES 8 bytes → DESede 24 bytes: K||K||K
            byte[] desEde = new byte[24];
            System.arraycopy(keyBytes, 0, desEde, 0,  8);
            System.arraycopy(keyBytes, 0, desEde, 8,  8);
            System.arraycopy(keyBytes, 0, desEde, 16, 8);
            secretKey = new SecretKeySpec(desEde, "DESede");
        } else {
            secretKey = new SecretKeySpec(keyBytes, algorithm);
        }
        KeyData keyData = new KeyData();
        keyData.setKey(secretKey);
        return keyData;
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
