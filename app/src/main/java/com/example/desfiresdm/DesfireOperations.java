package com.example.desfiresdm;

import android.util.Log;

import com.nxp.nfclib.KeyType;
import com.nxp.nfclib.desfire.DESFireEV3File;
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
 * SOLUCIÓN AL ERROR "cannot find symbol setISODFName":
 * EV3ApplicationKeySettings.Builder no expone setISODFName() en TapLinx.
 * En su lugar enviamos los comandos CreateApplication y CreateFile como
 * APDUs raw usando cardV1.sendCommand(), replicando byte a byte el script Python.
 *
 * APDUs críticos (calculados del Python):
 *   CreateApplication con ISO DF Name:
 *     90 CA 00 00 0E  D2 76 00  0F 21  10 E1  D2 76 00 00 85 01 01  00
 *
 *   CreateFile CC (File 01, ISO ID E103, Plain, libre, 15 bytes):
 *     90 CD 00 00 09  01  03 E1  00 E0  EE  0F 00 00  00
 *
 *   CreateFile NDEF (File 02, ISO ID E104, Plain, libre, 255 bytes):
 *     90 CD 00 00 09  02  04 E1  00 E0  EE  FF 00 00  00
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    // ── AIDs y File IDs ───────────────────────────────────────────────────────
    public static final byte[] NDEF_AID          = new byte[]{(byte)0xD2, 0x76, 0x00};
    public static final int    NDEF_CC_FILE_ID   = 0x01;
    public static final int    NDEF_DATA_FILE_ID = 0x02;
    public static final int    NDEF_FILE_SIZE    = 255;

    // Claves de fábrica
    public static final byte[] DEFAULT_KEY_AES = new byte[16]; // 16 x 0x00
    public static final byte[] DEFAULT_KEY_DES = new byte[8];  // 8  x 0x00

    // CC correcto — apunta a ISO File ID E104
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

    // ── APDUs raw (idénticos al script Python) ────────────────────────────────

    /**
     * CreateApplication con ISO DF Name D2760000850101
     * Python: payload = DESFIRE_AID + [0x0F, 0x21] + [0x10, 0xE1] + ISO_DF_NAME
     *         cmd = [0x90, 0xCA, 0x00, 0x00, len(payload)] + payload + [0x00]
     * Resultado: 90 CA 00 00 0E D2 76 00 0F 21 10 E1 D2 76 00 00 85 01 01 00
     */
    private static final byte[] APDU_CREATE_APP_ISO = new byte[]{
        (byte)0x90, (byte)0xCA, 0x00, 0x00, 0x0E,
        (byte)0xD2, 0x76, 0x00,                    // AID
        0x0F,                                       // KeySettings1
        0x21,                                       // KeySettings2: AES + ISO File IDs habilitados
        0x10, (byte)0xE1,                           // flags ISO DF Name
        (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01, // ISO DF Name
        0x00
    };

    /**
     * CreateFile CC: File 01, ISO ID E103, Plain, acceso EE (libre), 15 bytes
     * Python: [0x90, 0xCD, 0x00, 0x00, 0x09, 0x01, 0x03, 0xE1, 0x00, 0xE0, 0xEE, 0x0F, 0x00, 0x00, 0x00]
     */
    private static final byte[] APDU_CREATE_FILE_CC = new byte[]{
        (byte)0x90, (byte)0xCD, 0x00, 0x00, 0x09,
        0x01,                    // File No = 01
        0x03, (byte)0xE1,        // ISO File ID = E103
        0x00,                    // Communication: Plain
        (byte)0xE0,              // Access rights byte 1
        (byte)0xEE,              // Access rights byte 2
        0x0F, 0x00, 0x00,        // File size = 15 bytes (little-endian)
        0x00
    };

    /**
     * CreateFile NDEF: File 02, ISO ID E104, Plain, acceso EE (libre), 255 bytes
     * Python: [0x90, 0xCD, 0x00, 0x00, 0x09, 0x02, 0x04, 0xE1, 0x00, 0xE0, 0xEE, 0xFF, 0x00, 0x00, 0x00]
     */
    private static final byte[] APDU_CREATE_FILE_NDEF = new byte[]{
        (byte)0x90, (byte)0xCD, 0x00, 0x00, 0x09,
        0x02,                    // File No = 02
        0x04, (byte)0xE1,        // ISO File ID = E104
        0x00,                    // Communication: Plain
        (byte)0xE0,              // Access rights byte 1
        (byte)0xEE,              // Access rights byte 2
        (byte)0xFF, 0x00, 0x00,  // File size = 255 bytes (little-endian)
        0x00
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
    // ENVÍO DE APDU RAW via TapLinx
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Envía un APDU raw usando cardV1.sendCommand().
     * TapLinx devuelve la respuesta con SW1 SW2 al final.
     * Lanza excepción si SW != 9000 / 9100.
     */
    private byte[] sendRaw(byte[] apdu, String desc) throws Exception {
        byte[] response = cardV1.sendCommand(apdu);
        if (response == null || response.length < 2) {
            throw new Exception(desc + ": respuesta vacía del SDK");
        }
        int sw1 = response[response.length - 2] & 0xFF;
        int sw2 = response[response.length - 1] & 0xFF;
        boolean ok = (sw1 == 0x91 && sw2 == 0x00)
                  || (sw1 == 0x90 && sw2 == 0x00)
                  || (sw1 == 0x91 && sw2 == 0xAF);
        if (!ok) {
            throw new Exception(desc + " fallido: SW " + String.format("%02X %02X", sw1, sw2));
        }
        Log.d(TAG, desc + " OK (SW " + String.format("%02X %02X", sw1, sw2) + ")");
        return response;
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
            throw new Exception("No se pudo autenticar en el PICC. Clave no reconocida.");
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
            throw new Exception("No se pudo autenticar en la app. Clave no reconocida.");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CREAR APLICACIÓN NDEF CON ISO FILE IDs (APDUs raw — igual que Python)
    // ─────────────────────────────────────────────────────────────────────────

    public void createNdefApp(byte[] appMasterKey) throws Exception {
        Log.i(TAG, "=== createNdefApp (APDUs raw con ISO DF Name + ISO File IDs) ===");

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

        // 3. CreateApplication con ISO DF Name — APDU raw
        //    90 CA 00 00 0E  D2 76 00  0F 21  10 E1  D2 76 00 00 85 01 01  00
        sendRaw(APDU_CREATE_APP_ISO, "CreateApplication con ISO DF Name");

        // 4. Seleccionar nueva app y autenticar con AES
        cardV1.selectApplication(NDEF_AID);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
            buildKeyData(DEFAULT_KEY_AES, "AES"));

        if (appMasterKey != null && !Arrays.equals(appMasterKey, DEFAULT_KEY_AES)) {
            cardV1.changeKey(0, KeyType.AES128, appMasterKey, DEFAULT_KEY_AES, (byte)0x01);
        }

        // 5. CreateFile CC con ISO ID E103 — APDU raw
        //    90 CD 00 00 09  01  03 E1  00 E0 EE  0F 00 00  00
        sendRaw(APDU_CREATE_FILE_CC, "CreateFile CC (ISO E103)");

        // 6. CreateFile NDEF con ISO ID E104 — APDU raw
        //    90 CD 00 00 09  02  04 E1  00 E0 EE  FF 00 00  00
        sendRaw(APDU_CREATE_FILE_NDEF, "CreateFile NDEF (ISO E104)");

        // 7. Escribir CC
        cardV1.writeData(NDEF_CC_FILE_ID, 0, CC_DATA);

        // 8. Inicializar NDEF vacío
        cardV1.writeData(NDEF_DATA_FILE_ID, 0, new byte[]{0x00, 0x00});

        Log.i(TAG, "=== App NDEF lista con ISO File IDs — móviles pueden leerla ===");
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
            Log.w(TAG, "Auth falló — intentando escritura sin auth (acceso libre EE): " + e.getMessage());
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

        sendRaw(APDU_CREATE_APP_ISO, "CreateApplication ISO (reformat)");

        cardV1.selectApplication(NDEF_AID);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
            buildKeyData(DEFAULT_KEY_AES, "AES"));

        sendRaw(APDU_CREATE_FILE_CC,   "CreateFile CC (reformat)");
        sendRaw(APDU_CREATE_FILE_NDEF, "CreateFile NDEF (reformat)");

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
        // MacInputOffset = inicio del NDEF (byte 2, después de los 2 bytes NLEN)
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
    //
    // Layout fichero NDEF desde byte 0:
    //   [0-1] NLEN big-endian — longitud del NDEF record
    //   [2]   0xD1 — MB/ME/SR/TNF flags
    //   [3]   0x01 — Type Length
    //   [4]   payload length
    //   [5]   0x55 — Type 'U' (URI)
    //   [6]   URI Identifier Code (0x04=https://)
    //   [7..] URL sin prefijo
    //
    // BASE = 7 → primer byte de la URL sin prefijo en el fichero
    // ─────────────────────────────────────────────────────────────────────────

    public void calculateSdmOffsets(String url, SdmConfig config) {
        int prefixLen = 0;
        if      (url.startsWith("https://www.")) prefixLen = 12;
        else if (url.startsWith("https://"))     prefixLen = 8;
        else if (url.startsWith("http://www."))  prefixLen = 11;
        else if (url.startsWith("http://"))      prefixLen = 7;

        final int BASE = 7;

        int piccPos = url.indexOf("00000000000000000000000000000000");
        if (piccPos >= 0) config.setPiccDataOffset(BASE + (piccPos - prefixLen));

        String u2 = url.replace("00000000000000000000000000000000",
                                 "################################");
        int macPos = u2.indexOf("0000000000000000");
        if (macPos >= 0) config.setSdmMacOffset(BASE + (macPos - prefixLen));

        String u3 = u2.replace("0000000000000000", "################");
        int ctrPos = u3.indexOf("000000");
        if (ctrPos >= 0) config.setSdmReadCounterOffset(BASE + (ctrPos - prefixLen));

        Log.d(TAG, "Offsets calculados: PICC=" + config.getPiccDataOffset()
            + " MAC=" + config.getSdmMacOffset()
            + " CTR=" + config.getSdmReadCounterOffset());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS PRIVADOS
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
