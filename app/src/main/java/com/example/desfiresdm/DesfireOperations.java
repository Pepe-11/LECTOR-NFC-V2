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
 * Operaciones DESFire EV3.
 *
 * Detección automática de clave:
 *  - Tarjetas formateadas con el script Python usan DES 8 bytes (clave fábrica 00..00)
 *  - Tarjetas nuevas o formateadas con esta app usan AES-128 16 bytes (clave fábrica 00..00)
 *  - La app prueba AES primero, luego DES, y si la tarjeta está en DES la reformatea a AES
 *    para que el SDM funcione correctamente (SDM requiere AES en DESFire EV3)
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    // AID DESFire = siempre 3 bytes
    public static final byte[] NDEF_AID          = new byte[]{(byte)0xD2, 0x76, 0x00};
    public static final int    NDEF_CC_FILE_ID   = 0x01;
    public static final int    NDEF_DATA_FILE_ID = 0x02;
    public static final int    NDEF_FILE_SIZE    = 255;
    public static final byte[] DEFAULT_KEY_AES   = new byte[16]; // 16 x 0x00
    public static final byte[] DEFAULT_KEY_DES   = new byte[8];  // 8  x 0x00

    // CC correcto con ISO File ID 0xE104 — imprescindible para que los móviles lean NDEF
    private static final byte[] CC_DATA = new byte[]{
        0x00, 0x0F,              // Tamaño CC: 15 bytes
        0x20,                    // Versión NDEF 2.0
        0x00, 0x7F,              // Max lectura
        0x00, 0x73,              // Max escritura
        0x04, 0x06,              // NDEF File Control TLV
        (byte)0xE1, 0x04,        // ISO File ID 0xE104 — clave para móviles NFC
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
        // TapLinx exige seleccionar app maestra antes de getApplicationIDs()
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
    //
    // Las tarjetas formateadas con el script Python tienen clave DES 8 bytes.
    // Las tarjetas nuevas o formateadas con esta app tienen clave AES-128.
    // Probamos AES primero (más seguro), si falla probamos DES.
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Autentica en el PICC (aplicación maestra).
     * Detecta automáticamente si la tarjeta usa AES o DES.
     * Devuelve true si usó DES (indica que la tarjeta necesita ser migrada a AES).
     */
    private boolean authenticatePiccAuto(byte[] masterKey) throws Exception {
        // Intento 1: AES-128
        try {
            byte[] key = (masterKey != null && masterKey.length == 16) ? masterKey : DEFAULT_KEY_AES;
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128, buildKeyData(key, "AES"));
            Log.d(TAG, "Auth PICC con AES OK");
            return false; // no es DES
        } catch (Exception e) {
            Log.w(TAG, "Auth PICC AES falló, probando DES: " + e.getMessage());
        }

        // Intento 2: DES 8 bytes (tarjetas formateadas con script Python)
        try {
            byte[] key = (masterKey != null && masterKey.length == 8) ? masterKey : DEFAULT_KEY_DES;
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.DES, buildKeyData(key, "DES"));
            Log.d(TAG, "Auth PICC con DES OK — tarjeta necesita migración a AES");
            return true; // es DES
        } catch (Exception e) {
            Log.e(TAG, "Auth PICC DES también falló: " + e.getMessage());
            throw new Exception("No se pudo autenticar en el PICC. Clave no reconocida.");
        }
    }

    /**
     * Autentica en la aplicación NDEF.
     * Detecta automáticamente AES o DES.
     */
    private boolean authenticateAppAuto(byte[] appKey, int keyNo) throws Exception {
        // Intento 1: AES-128
        try {
            byte[] key = (appKey != null && appKey.length == 16) ? appKey : DEFAULT_KEY_AES;
            cardV1.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.AES128, buildKeyData(key, "AES"));
            Log.d(TAG, "Auth App con AES OK");
            return false;
        } catch (Exception e) {
            Log.w(TAG, "Auth App AES falló, probando DES: " + e.getMessage());
        }

        // Intento 2: DES
        try {
            byte[] key = (appKey != null && appKey.length == 8) ? appKey : DEFAULT_KEY_DES;
            cardV1.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.DES, buildKeyData(key, "DES"));
            Log.d(TAG, "Auth App con DES OK");
            return true;
        } catch (Exception e) {
            throw new Exception("No se pudo autenticar en la aplicación. Clave no reconocida.");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ESCRIBIR URL NDEF
    // Flujo completo: detecta tarjeta DES → la reformatea a AES → escribe URL
    // ─────────────────────────────────────────────────────────────────────────

    public void writeNdefUrl(String url) throws Exception {
        byte[] ndefMessage = buildNdefUriMessage(url);
        if (ndefMessage.length > NDEF_FILE_SIZE) {
            throw new Exception("URL demasiado larga (" + ndefMessage.length + " bytes).");
        }

        // Paso 1: seleccionar app NDEF y autenticar (detecta DES o AES)
        cardV1.selectApplication(NDEF_AID);
        boolean wasDes = authenticateAppAuto(null, 0);

        if (wasDes) {
            // La tarjeta está en DES — necesita reformateo completo a AES
            Log.i(TAG, "Tarjeta DES detectada — reformateando a AES...");
            reformatCardToAes(url);
            return;
        }

        // Tarjeta ya en AES — escribir directamente
        cardV1.writeData(NDEF_DATA_FILE_ID, 0, ndefMessage);
        Log.d(TAG, "URL escrita: " + url);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // REFORMATEO COMPLETO: DES → AES
    // Borra la app NDEF, la recrea con AES y escribe la URL
    // ─────────────────────────────────────────────────────────────────────────

    private void reformatCardToAes(String url) throws Exception {
        Log.i(TAG, "Iniciando reformateo DES→AES");

        // 1. Seleccionar PICC y autenticar con DES
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.DES,
            buildKeyData(DEFAULT_KEY_DES, "DES"));

        // 2. Borrar la app NDEF si existe
        try {
            cardV1.deleteApplication(NDEF_AID);
            Log.d(TAG, "App NDEF borrada");
        } catch (Exception e) {
            Log.w(TAG, "deleteApplication: " + e.getMessage());
        }

        // 3. Re-autenticar tras borrar (requerido por DESFire)
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.DES,
            buildKeyData(DEFAULT_KEY_DES, "DES"));

        // 4. Crear app NDEF con AES-128
        EV3ApplicationKeySettings keySettings = new EV3ApplicationKeySettings.Builder()
            .setKeyTypeOfApplicationKeys(KeyType.AES128)
            .setMaxNumberOfApplicationKeys(2)
            .setAppMasterKeyChangeable(true)
            .setAppKeySettingsChangeable(true)
            .setAuthenticationRequiredForFileManagement(false)
            .build();

        cardV3.createApplication(NDEF_AID, keySettings);
        Log.d(TAG, "App NDEF creada con AES");

        // 5. Seleccionar nueva app y autenticar con AES
        cardV1.selectApplication(NDEF_AID);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
            buildKeyData(DEFAULT_KEY_AES, "AES"));

        // 6. Crear ficheros CC y NDEF
        createCapabilityContainerFile();
        createNdefDataFile();

        // 7. Escribir URL
        byte[] ndefMessage = buildNdefUriMessage(url);
        cardV1.writeData(NDEF_DATA_FILE_ID, 0, ndefMessage);
        Log.i(TAG, "Reformateo completado y URL escrita: " + url);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CREAR APLICACIÓN NDEF (cuando la tarjeta está completamente vacía)
    // ─────────────────────────────────────────────────────────────────────────

    public void createNdefApp(byte[] appMasterKey) throws Exception {
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        boolean wasDes = authenticatePiccAuto(null);

        // Si estaba en DES, re-autenticar con DES explícitamente (ya lo hizo authenticatePiccAuto)
        ArrayList<byte[]> existingApps = readApplicationIds();
        for (byte[] aid : existingApps) {
            if (Arrays.equals(aid, NDEF_AID)) {
                Log.w(TAG, "App NDEF ya existe");
                return;
            }
        }

        if (wasDes) {
            // Crear app con AES desde PICC autenticado con DES
            Log.i(TAG, "PICC en DES — creando app NDEF con AES");
            cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.DES,
                buildKeyData(DEFAULT_KEY_DES, "DES"));
        }

        EV3ApplicationKeySettings keySettings = new EV3ApplicationKeySettings.Builder()
            .setKeyTypeOfApplicationKeys(KeyType.AES128)
            .setMaxNumberOfApplicationKeys(2)
            .setAppMasterKeyChangeable(true)
            .setAppKeySettingsChangeable(true)
            .setAuthenticationRequiredForFileManagement(false)
            .build();

        cardV3.createApplication(NDEF_AID, keySettings);
        Log.d(TAG, "Aplicación NDEF creada");

        cardV1.selectApplication(NDEF_AID);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
            buildKeyData(DEFAULT_KEY_AES, "AES"));

        if (appMasterKey != null && !Arrays.equals(appMasterKey, DEFAULT_KEY_AES)) {
            cardV1.changeKey(0, KeyType.AES128, appMasterKey, DEFAULT_KEY_AES, (byte) 0x01);
        }

        createCapabilityContainerFile();
        createNdefDataFile();
        Log.d(TAG, "App NDEF lista");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURAR SDM
    // ─────────────────────────────────────────────────────────────────────────

    public void configureSdm(SdmConfig config) throws Exception {
        cardV1.selectApplication(NDEF_AID);
        boolean wasDes = authenticateAppAuto(null, 0);

        if (wasDes) {
            throw new Exception(
                "La tarjeta está en formato DES. Escribe primero una URL para migrarla a AES, " +
                "luego aplica el SDM.");
        }

        DESFireEV3File.EV3FileSettings settings = cardV3.getDESFireEV3FileSettings(NDEF_DATA_FILE_ID);
        if (!(settings instanceof DESFireEV3File.StdEV3DataFileSettings)) {
            throw new Exception("El fichero NDEF no es StdEV3DataFileSettings");
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
        ds.setSdmMacInputOffset(intTo3Bytes(config.getSdmMacOffset()));
        ds.setSdmAccessRights(new byte[]{config.getSdmAccessRights(), config.getSdmAccessRights()});

        cardV3.changeDESFireEV3FileSettings(NDEF_DATA_FILE_ID, ds);
        Log.d(TAG, "SDM configurado");
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
        authenticateAppAuto(null, 0);
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
        // Layout NDEF: [2 bytes NLEN][D1 01 payloadLen 55 uriId][url sin prefijo]
        // Los 7 bytes de cabecera son el offset base
        int urlBase = 7;
        int protocolLen = url.startsWith("https://") ? 8 : (url.startsWith("http://") ? 7 : 0);

        int piccPos = url.indexOf("00000000000000000000000000000000");
        if (piccPos >= 0) config.setPiccDataOffset(urlBase + (piccPos - protocolLen));

        String u2 = url.replace("00000000000000000000000000000000", "################################");
        int macPos = u2.indexOf("0000000000000000");
        if (macPos >= 0) config.setSdmMacOffset(urlBase + (macPos - protocolLen));

        String u3 = u2.replace("0000000000000000", "################");
        int ctrPos = u3.indexOf("000000");
        if (ctrPos >= 0) config.setSdmReadCounterOffset(urlBase + (ctrPos - protocolLen));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS PRIVADOS
    // ─────────────────────────────────────────────────────────────────────────

    private void createCapabilityContainerFile() throws Exception {
        DESFireEV3File.StdEV3DataFileSettings ccSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                (byte)0xEE, (byte)0xEE, (byte)0x00, (byte)0xEE,
                15, (byte)0x00, null
            );
        cardV3.createFile(NDEF_CC_FILE_ID, ccSettings);
        cardV1.writeData(NDEF_CC_FILE_ID, 0, CC_DATA);
        Log.d(TAG, "Fichero CC creado con ISO ID E104");
    }

    private void createNdefDataFile() throws Exception {
        DESFireEV3File.StdEV3DataFileSettings ndefSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                (byte)0xEE, (byte)0xEE, (byte)0x00, (byte)0xEE,
                NDEF_FILE_SIZE, (byte)0x00, null
            );
        cardV3.createFile(NDEF_DATA_FILE_ID, ndefSettings);
        Log.d(TAG, "Fichero NDEF creado");
    }

    private byte[] buildNdefUriMessage(String url) {
        byte uriId;
        String payload;
        if      (url.startsWith("https://")) { uriId = 0x04; payload = url.substring(8); }
        else if (url.startsWith("http://"))  { uriId = 0x03; payload = url.substring(7); }
        else                                 { uriId = 0x00; payload = url; }

        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        int payloadLen = 1 + payloadBytes.length;
        byte[] record = new byte[4 + payloadLen];
        record[0] = (byte)0xD1; record[1] = 0x01;
        record[2] = (byte)payloadLen; record[3] = 0x55; record[4] = uriId;
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
            int typeLen = buf[offset + 1] & 0xFF;
            int payloadLen = buf[offset + 2] & 0xFF;
            int payloadStart = offset + 3 + typeLen;
            if (payloadStart >= buf.length || payloadLen < 1) return "(error NDEF)";
            byte uriId = buf[payloadStart];
            String prefix = uriIdPrefix(uriId);
            String rest = new String(buf, payloadStart + 1, payloadLen - 1, StandardCharsets.UTF_8);
            return prefix + rest;
        } catch (Exception e) { return "(error: " + e.getMessage() + ")"; }
    }

    private String uriIdPrefix(byte id) {
        switch (id & 0xFF) {
            case 0x01: return "http://www.";
            case 0x02: return "https://www.";
            case 0x03: return "http://";
            case 0x04: return "https://";
            default:   return "";
        }
    }

    private byte[] intTo3Bytes(int v) {
        return new byte[]{(byte)(v & 0xFF), (byte)((v >> 8) & 0xFF), (byte)((v >> 16) & 0xFF)};
    }

    /**
     * Construye IKeyData a partir de un byte[] de clave.
     * AAR confirma: KeyData() constructor vacío + setKey(java.security.Key)
     *
     * @param keyBytes bytes de la clave
     * @param algorithm "AES" para AES-128, "DES" para DES de 8 bytes
     */
    private IKeyData buildKeyData(byte[] keyBytes, String algorithm) throws Exception {
        SecretKey secretKey = new SecretKeySpec(keyBytes, algorithm);
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
