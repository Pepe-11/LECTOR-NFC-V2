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
 * Operaciones DESFire EV3 — réplica exacta del script Python nfc_writer.py
 *
 * SOLUCIÓN DEFINITIVA (inspeccionando el AAR real con javap):
 *
 * Los ISO File IDs NO se pasan al Builder, sino como PARÁMETROS a los métodos:
 *
 *   1. createApplication CON ISO DF Name:
 *      cardV3.createApplication(byte[] aid, EV3ApplicationKeySettings, byte[] isoFID, byte[] dfName)
 *      → isoFID = null (no hay FID para la app, solo DF Name)
 *      → dfName = {D2 76 00 00 85 01 01}
 *
 *   2. createFile CON ISO File ID:
 *      cardV3.createFile(int fileNo, byte[] isoFileId, DESFireEV3File.EV3FileSettings)
 *      → isoFileId = {E1 03} para CC,  {E1 04} para NDEF
 *
 *   3. StdEV3DataFileSettings constructor CON ISO ID:
 *      new StdEV3DataFileSettings(CommunicationType, rw, r, w, car, size, ver, byte[] isoFileId)
 *
 * Esto es exactamente lo que hace el script Python con sus APDUs raw, pero
 * usando la API pública del SDK — sin APDUs manuales, sin IsoDep.
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    // ── AIDs y File IDs ───────────────────────────────────────────────────────
    public static final byte[] NDEF_AID          = new byte[]{(byte)0xD2, 0x76, 0x00};
    public static final int    NDEF_CC_FILE_ID   = 0x01;
    public static final int    NDEF_DATA_FILE_ID = 0x02;
    public static final int    NDEF_FILE_SIZE    = 255;

    /**
     * ISO DF Name estándar NDEF — D2 76 00 00 85 01 01
     * Permite que los móviles seleccionen la app con:
     *   ISO SELECT: 00 A4 04 00 07 D2 76 00 00 85 01 01
     */
    private static final byte[] ISO_DF_NAME = new byte[]{
        (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01
    };

    /**
     * ISO File ID del fichero CC → E1 03
     * Permite selección ISO: 00 A4 00 0C 02 E1 03
     */
    private static final byte[] ISO_FILE_ID_CC   = new byte[]{(byte)0xE1, 0x03};

    /**
     * ISO File ID del fichero NDEF → E1 04  ← EL MÁS CRÍTICO
     * Permite selección ISO: 00 A4 00 0C 02 E1 04
     * Sin este ID los móviles no pueden leer el NDEF.
     */
    private static final byte[] ISO_FILE_ID_NDEF = new byte[]{(byte)0xE1, 0x04};

    // Claves de fábrica
    public static final byte[] DEFAULT_KEY_AES = new byte[16]; // 16 x 0x00
    public static final byte[] DEFAULT_KEY_DES = new byte[8];  // 8  x 0x00

    // CC correcto — apunta a E1 04
    private static final byte[] CC_DATA = new byte[]{
        0x00, 0x0F,              // Tamaño CC: 15 bytes
        0x20,                    // Versión NDEF 2.0
        0x00, 0x7F,              // Max lectura
        0x00, 0x73,              // Max escritura
        0x04, 0x06,              // NDEF File Control TLV
        (byte)0xE1, 0x04,        // ← ISO File ID E104
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

    private boolean authenticatePiccAuto(byte[] masterKey) throws Exception {
        try {
            byte[] key = (masterKey != null && masterKey.length == 16) ? masterKey : DEFAULT_KEY_AES;
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128, buildKeyData(key, "AES"));
            Log.d(TAG, "Auth PICC AES OK");
            return false;
        } catch (Exception e) {
            Log.w(TAG, "Auth PICC AES falló: " + e.getMessage());
        }
        try {
            byte[] key = (masterKey != null && masterKey.length == 8) ? masterKey : DEFAULT_KEY_DES;
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES, buildKeyData(key, "DES"));
            Log.d(TAG, "Auth PICC DES OK");
            return true;
        } catch (Exception e) {
            throw new Exception("No se pudo autenticar en el PICC.");
        }
    }

    private boolean authenticateAppAuto(byte[] appKey, int keyNo) throws Exception {
        try {
            byte[] key = (appKey != null && appKey.length == 16) ? appKey : DEFAULT_KEY_AES;
            cardV1.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.AES128, buildKeyData(key, "AES"));
            Log.d(TAG, "Auth App AES OK");
            return false;
        } catch (Exception e) {
            Log.w(TAG, "Auth App AES falló: " + e.getMessage());
        }
        try {
            byte[] key = (appKey != null && appKey.length == 8) ? appKey : DEFAULT_KEY_DES;
            cardV1.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, buildKeyData(key, "DES"));
            Log.d(TAG, "Auth App DES OK");
            return true;
        } catch (Exception e) {
            throw new Exception("No se pudo autenticar en la app.");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CREAR APLICACIÓN NDEF CON ISO DF NAME + ISO FILE IDs
    //
    // Firma real del SDK (verificada con javap en el AAR):
    //   IDESFireEV3.createApplication(byte[] aid, EV3ApplicationKeySettings, byte[] isoFID, byte[] dfName)
    //   IDESFireEV3.createFile(int fileNo, byte[] isoFileId, EV3FileSettings)
    // ─────────────────────────────────────────────────────────────────────────

    public void createNdefApp(byte[] appMasterKey) throws Exception {
        Log.i(TAG, "=== createNdefApp con ISO DF Name + ISO File IDs ===");

        // 1. Seleccionar Master App y autenticar
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        boolean wasDes = authenticatePiccAuto(null);

        // 2. Borrar app NDEF si ya existe
        ArrayList<byte[]> apps = readApplicationIds();
        boolean appExists = false;
        for (byte[] aid : apps) {
            if (Arrays.equals(aid, NDEF_AID)) { appExists = true; break; }
        }
        if (appExists) {
            Log.w(TAG, "App NDEF existe — borrando para recrear con ISO IDs");
            cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
            if (wasDes) {
                cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
                    buildKeyData(DEFAULT_KEY_DES, "DES"));
            } else {
                cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
                    buildKeyData(DEFAULT_KEY_AES, "AES"));
            }
            try { cardV1.deleteApplication(NDEF_AID); } catch (Exception e) {
                Log.w(TAG, "deleteApplication: " + e.getMessage());
            }
            // Re-autenticar tras borrar (DESFire lo exige)
            cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
            if (wasDes) {
                cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
                    buildKeyData(DEFAULT_KEY_DES, "DES"));
            } else {
                cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
                    buildKeyData(DEFAULT_KEY_AES, "AES"));
            }
        }

        // 3. Crear la aplicación con ISO DF Name
        //    Firma: createApplication(byte[] aid, EV3ApplicationKeySettings, byte[] isoFID, byte[] dfName)
        //    isoFID = null → la app no tiene ISO File Identifier propio, solo DF Name
        //    dfName = D2 76 00 00 85 01 01 → nombre estándar NDEF
        EV3ApplicationKeySettings keySettings = new EV3ApplicationKeySettings.Builder()
            .setKeyTypeOfApplicationKeys(KeyType.AES128)
            .setMaxNumberOfApplicationKeys(2)
            .setAppMasterKeyChangeable(true)
            .setAppKeySettingsChangeable(true)
            .setAuthenticationRequiredForFileManagement(false)
            .setIsoFileIdentifierPresent(true)  // ← habilita el campo ISO en el APDU
            .build();

        cardV3.createApplication(NDEF_AID, keySettings, null, ISO_DF_NAME);
        Log.d(TAG, "App NDEF creada con ISO DF Name: " + bytesToHex(ISO_DF_NAME));

        // 4. Seleccionar la nueva app y autenticar con AES
        cardV1.selectApplication(NDEF_AID);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
            buildKeyData(DEFAULT_KEY_AES, "AES"));

        if (appMasterKey != null && !Arrays.equals(appMasterKey, DEFAULT_KEY_AES)) {
            cardV1.changeKey(0, KeyType.AES128, appMasterKey, DEFAULT_KEY_AES, (byte)0x01);
        }

        // 5. Crear File CC con ISO File ID E103
        //    Firma: createFile(int fileNo, byte[] isoFileId, EV3FileSettings)
        createCapabilityContainerFile();

        // 6. Crear File NDEF con ISO File ID E104
        createNdefDataFile();

        // 7. Escribir CC y NDEF vacío
        cardV1.writeData(NDEF_CC_FILE_ID, 0, CC_DATA);
        cardV1.writeData(NDEF_DATA_FILE_ID, 0, new byte[]{0x00, 0x00});

        Log.i(TAG, "=== App NDEF lista — tarjeta legible por móviles ===");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ESCRIBIR URL NDEF
    // ─────────────────────────────────────────────────────────────────────────

    public void writeNdefUrl(String url) throws Exception {
        byte[] ndefMessage = buildNdefUriMessage(url);
        if (ndefMessage.length > NDEF_FILE_SIZE) {
            throw new Exception("URL demasiado larga (" + ndefMessage.length + " bytes).");
        }

        Log.i(TAG, "writeNdefUrl: " + url);
        cardV1.selectApplication(NDEF_AID);

        boolean wasDes = false;
        boolean authOk = false;
        try {
            wasDes = authenticateAppAuto(null, 0);
            authOk = true;
        } catch (Exception e) {
            Log.w(TAG, "Auth falló — intentando escritura directa: " + e.getMessage());
        }

        if (authOk && wasDes) {
            Log.i(TAG, "Tarjeta DES — reformateando a AES...");
            reformatCardToAes(url);
            return;
        }

        cardV1.writeData(NDEF_DATA_FILE_ID, 0, ndefMessage);
        Log.d(TAG, "URL escrita OK: " + url);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // REFORMATEO DES → AES (mantiene ISO File IDs)
    // ─────────────────────────────────────────────────────────────────────────

    private void reformatCardToAes(String url) throws Exception {
        Log.i(TAG, "=== reformatCardToAes ===");

        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
            buildKeyData(DEFAULT_KEY_DES, "DES"));
        try { cardV1.deleteApplication(NDEF_AID); } catch (Exception e) {
            Log.w(TAG, "deleteApplication: " + e.getMessage());
        }

        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
            buildKeyData(DEFAULT_KEY_DES, "DES"));

        // Crear app con ISO DF Name
        EV3ApplicationKeySettings keySettings = new EV3ApplicationKeySettings.Builder()
            .setKeyTypeOfApplicationKeys(KeyType.AES128)
            .setMaxNumberOfApplicationKeys(2)
            .setAppMasterKeyChangeable(true)
            .setAppKeySettingsChangeable(true)
            .setAuthenticationRequiredForFileManagement(false)
            .setIsoFileIdentifierPresent(true)
            .build();

        cardV3.createApplication(NDEF_AID, keySettings, null, ISO_DF_NAME);

        cardV1.selectApplication(NDEF_AID);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
            buildKeyData(DEFAULT_KEY_AES, "AES"));

        createCapabilityContainerFile();
        createNdefDataFile();

        cardV1.writeData(NDEF_CC_FILE_ID, 0, CC_DATA);
        cardV1.writeData(NDEF_DATA_FILE_ID, 0, buildNdefUriMessage(url));

        Log.i(TAG, "Reformateo DES→AES completado: " + url);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURAR SDM
    // ─────────────────────────────────────────────────────────────────────────

    public void configureSdm(SdmConfig config) throws Exception {
        Log.i(TAG, "=== configureSdm ===");

        cardV1.selectApplication(NDEF_AID);

        boolean wasDes = false;
        try {
            wasDes = authenticateAppAuto(null, 0);
        } catch (Exception e) {
            throw new Exception("Auth SDM fallida: " + e.getMessage());
        }

        if (wasDes) {
            String currentUrl = "";
            try {
                byte[] raw = cardV1.readData(NDEF_DATA_FILE_ID, 0, 0);
                if (raw != null && raw.length > 2) {
                    int ndefLen = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
                    if (ndefLen > 0) currentUrl = parseNdefUriRecord(raw, 2, ndefLen);
                }
            } catch (Exception e) {
                Log.w(TAG, "No se pudo leer URL: " + e.getMessage());
            }
            if (currentUrl == null || currentUrl.isEmpty()) {
                throw new Exception("Tarjeta en DES sin URL. Escribe una URL primero.");
            }
            reformatCardToAes(currentUrl);
            cardV1.selectApplication(NDEF_AID);
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
                buildKeyData(DEFAULT_KEY_AES, "AES"));
        }

        DESFireEV3File.EV3FileSettings settings = cardV3.getDESFireEV3FileSettings(NDEF_DATA_FILE_ID);
        if (!(settings instanceof DESFireEV3File.StdEV3DataFileSettings)) {
            throw new Exception("El fichero NDEF no es StdEV3DataFileSettings.");
        }

        DESFireEV3File.StdEV3DataFileSettings ds = (DESFireEV3File.StdEV3DataFileSettings) settings;

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
        ds.setSdmMacOffset(intTo3Bytes(config.getSdmMacOffset()));
        // MacInputOffset = inicio del NDEF (byte 2, tras los 2 bytes NLEN)
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
        try { authenticateAppAuto(null, 0); } catch (Exception e) {
            Log.w(TAG, "Auth opcional readSdmSettings: " + e.getMessage());
        }
        DESFireEV3File.EV3FileSettings settings = cardV3.getDESFireEV3FileSettings(NDEF_DATA_FILE_ID);
        if (settings instanceof DESFireEV3File.StdEV3DataFileSettings) {
            return (DESFireEV3File.StdEV3DataFileSettings) settings;
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CALCULAR OFFSETS SDM
    // ─────────────────────────────────────────────────────────────────────────

    public void calculateSdmOffsets(String url, SdmConfig config) {
        int prefixLen = 0;
        if      (url.startsWith("https://www.")) prefixLen = 12;
        else if (url.startsWith("https://"))     prefixLen = 8;
        else if (url.startsWith("http://www."))  prefixLen = 11;
        else if (url.startsWith("http://"))      prefixLen = 7;

        // NLEN(2) + D1(1) + TypeLen(1) + PayloadLen(1) + 'U'(1) + UriId(1) = 7
        final int BASE = 7;

        int piccPos = url.indexOf("00000000000000000000000000000000");
        if (piccPos >= 0) config.setPiccDataOffset(BASE + (piccPos - prefixLen));

        String u2 = url.replace("00000000000000000000000000000000", "################################");
        int macPos = u2.indexOf("0000000000000000");
        if (macPos >= 0) config.setSdmMacOffset(BASE + (macPos - prefixLen));

        String u3 = u2.replace("0000000000000000", "################");
        int ctrPos = u3.indexOf("000000");
        if (ctrPos >= 0) config.setSdmReadCounterOffset(BASE + (ctrPos - prefixLen));

        Log.d(TAG, "Offsets: PICC=" + config.getPiccDataOffset()
            + " MAC=" + config.getSdmMacOffset()
            + " CTR=" + config.getSdmReadCounterOffset());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS PRIVADOS — Creación de ficheros
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Crea File CC (File 01) con ISO File ID E103.
     *
     * Firma SDK usada:
     *   cardV3.createFile(int fileNo, byte[] isoFileId, DESFireEV3File.EV3FileSettings)
     *
     * Constructor StdEV3DataFileSettings con ISO ID:
     *   new StdEV3DataFileSettings(CommType, rw, r, w, car, size, ver, byte[] isoFileId)
     */
    private void createCapabilityContainerFile() throws Exception {
        DESFireEV3File.StdEV3DataFileSettings ccSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                (byte)0xEE,   // Read&Write: libre
                (byte)0xEE,   // Read: libre
                (byte)0x00,   // Write: clave 0
                (byte)0xEE,   // ChangeAccessRights: libre
                15,           // Tamaño: 15 bytes
                (byte)0x00,   // versión
                ISO_FILE_ID_CC // ← ISO File ID E103
            );
        // Usar createFile CON ISO File ID como segundo parámetro
        cardV3.createFile(NDEF_CC_FILE_ID, ISO_FILE_ID_CC, ccSettings);
        Log.d(TAG, "File CC creado con ISO ID E103");
    }

    /**
     * Crea File NDEF (File 02) con ISO File ID E104.
     *
     * Sin este ISO ID los móviles no pueden seleccionar el fichero NDEF
     * y por tanto no pueden leer ni escribir NDEF por la vía estándar.
     */
    private void createNdefDataFile() throws Exception {
        DESFireEV3File.StdEV3DataFileSettings ndefSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                (byte)0xEE,      // Read&Write: libre
                (byte)0xEE,      // Read: libre
                (byte)0x00,      // Write: clave 0
                (byte)0xEE,      // ChangeAccessRights: libre
                NDEF_FILE_SIZE,  // 255 bytes
                (byte)0x00,      // versión
                ISO_FILE_ID_NDEF // ← ISO File ID E104
            );
        // Usar createFile CON ISO File ID como segundo parámetro
        cardV3.createFile(NDEF_DATA_FILE_ID, ISO_FILE_ID_NDEF, ndefSettings);
        Log.d(TAG, "File NDEF creado con ISO ID E104");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS PRIVADOS — NDEF
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] buildNdefUriMessage(String url) {
        byte uriId;
        String payload;
        if      (url.startsWith("https://www.")) { uriId = 0x02; payload = url.substring(12); }
        else if (url.startsWith("https://"))     { uriId = 0x04; payload = url.substring(8);  }
        else if (url.startsWith("http://www."))  { uriId = 0x01; payload = url.substring(11); }
        else if (url.startsWith("http://"))      { uriId = 0x03; payload = url.substring(7);  }
        else                                     { uriId = 0x00; payload = url;               }

        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        int payloadLen = 1 + payloadBytes.length;

        byte[] record = new byte[4 + payloadLen];
        record[0] = (byte)0xD1;
        record[1] = 0x01;
        record[2] = (byte)(payloadLen & 0xFF);
        record[3] = 0x55;
        record[4] = uriId;
        System.arraycopy(payloadBytes, 0, record, 5, payloadBytes.length);

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
            String rest = new String(buf, payloadStart + 1, payloadLen - 1, StandardCharsets.UTF_8);
            return uriIdPrefix(uriId) + rest;
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

    private IKeyData buildKeyData(byte[] keyBytes, String algorithm) throws Exception {
        SecretKey secretKey;
        if ("DES".equals(algorithm)) {
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
