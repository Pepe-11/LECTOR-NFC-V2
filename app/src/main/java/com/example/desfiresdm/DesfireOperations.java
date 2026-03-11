package com.example.desfiresdm;

import android.util.Log;

import com.nxp.nfclib.KeyType;
import com.nxp.nfclib.desfire.DESFireEV3File;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.IDESFireEV3;
import com.nxp.nfclib.interfaces.IKeyData;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Operaciones DESFire EV3 usando las interfaces públicas del SDK TapLinx.
 *
 * Usa IDESFireEV3 e IDESFireEV1 (interfaces públicas) en lugar de DESFireEV3.
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    public static final byte[] NDEF_AID       = new byte[]{(byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01};
    public static final byte   NDEF_CC_FILE_ID   = 0x01;
    public static final byte   NDEF_DATA_FILE_ID = 0x02;
    public static final int    NDEF_FILE_SIZE    = 256;
    public static final byte[] DEFAULT_KEY       = new byte[16]; // 16 x 0x00

    private final IDESFireEV1 cardV1;
    private final IDESFireEV3 cardV3;

    public DesfireOperations(IDESFireEV3 card) {
        this.cardV3 = card;
        this.cardV1 = card; // IDESFireEV3 extiende IDESFireEV1 e IDESFireEV2
    }

    // Constructor para cuando no se necesita tarjeta (calcular offsets)
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

    public byte[][] readApplicationIds() throws Exception {
        return cardV1.getApplicationIDs();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AUTENTICACIÓN
    // ─────────────────────────────────────────────────────────────────────────

    public void authenticatePicc(byte[] masterKey) throws Exception {
        byte[] key = (masterKey != null) ? masterKey : DEFAULT_KEY;
        IKeyData keyData = buildKeyData(key);
        cardV1.authenticate(keyData, 0, false, IDESFireEV1.AuthType.Native);
        Log.d(TAG, "Autenticado en PICC");
    }

    public void selectAndAuthenticate(byte[] aid, int keyNo, byte[] appKey) throws Exception {
        cardV1.selectApplication(aid);
        byte[] key = (appKey != null) ? appKey : DEFAULT_KEY;
        IKeyData keyData = buildKeyData(key);
        cardV1.authenticate(keyData, keyNo, false, IDESFireEV1.AuthType.Native);
        Log.d(TAG, "Autenticado en app " + bytesToHex(aid));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CREAR APLICACIÓN NDEF
    // ─────────────────────────────────────────────────────────────────────────

    public void createNdefApp(byte[] appMasterKey) throws Exception {
        // Ir a PICC (app raíz)
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        authenticatePicc(null);

        // Verificar si ya existe
        byte[][] existingApps = cardV1.getApplicationIDs();
        if (existingApps != null) {
            for (byte[] aid : existingApps) {
                if (Arrays.equals(aid, NDEF_AID)) {
                    Log.w(TAG, "App NDEF ya existe");
                    return;
                }
            }
        }

        // Crear app: AES, 2 claves
        byte keySettings = 0x0F;
        byte numberOfKeys = (byte) 0x82; // cast explícito para evitar error de compilación
        cardV3.createApplication(NDEF_AID, keySettings, numberOfKeys);
        Log.d(TAG, "Aplicación NDEF creada");

        // Seleccionar y autenticar
        cardV1.selectApplication(NDEF_AID);
        authenticateApp(null, 0);

        // Cambiar clave si se proporcionó
        if (appMasterKey != null && !Arrays.equals(appMasterKey, DEFAULT_KEY)) {
            IKeyData newKey = buildKeyData(appMasterKey);
            cardV1.changeKey(0, newKey, KeyType.AES128);
        }

        createCapabilityContainerFile();
        createNdefDataFile();
        Log.d(TAG, "App NDEF con SDM lista");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ESCRIBIR URL NDEF
    // ─────────────────────────────────────────────────────────────────────────

    public void writeNdefUrl(String url) throws Exception {
        byte[] ndefMessage = buildNdefUriMessage(url);

        if (ndefMessage.length > NDEF_FILE_SIZE) {
            throw new Exception("URL demasiado larga (" + ndefMessage.length + " bytes). Máximo " + NDEF_FILE_SIZE);
        }

        cardV1.selectApplication(NDEF_AID);
        authenticateApp(null, 0);

        cardV1.writeData(
            NDEF_DATA_FILE_ID,
            0,
            ndefMessage.length,
            ndefMessage,
            IDESFireEV1.CommunicationType.Plain
        );
        Log.d(TAG, "URL escrita: " + url);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURAR SDM
    // ─────────────────────────────────────────────────────────────────────────

    public void configureSdm(SdmConfig config) throws Exception {
        cardV1.selectApplication(NDEF_AID);
        authenticateApp(null, 0);

        DESFireEV3File.EV3FileSettings settings = cardV3.getDESFireEV3FileSettings(NDEF_DATA_FILE_ID);

        if (!(settings instanceof DESFireEV3File.StdEV3DataFileSettings)) {
            throw new Exception("El fichero no es StdEV3DataFileSettings");
        }

        DESFireEV3File.StdEV3DataFileSettings ds = (DESFireEV3File.StdEV3DataFileSettings) settings;

        ds.setSDMEnabled(true);

        // UID mirroring
        ds.setUIDMirroringEnabled(config.isUidMirroringEnabled());
        if (config.isUidMirroringEnabled()) {
            ds.setUidOffset(intToBytes3(config.getPiccDataOffset()));
        }

        // Contador
        ds.setSDMReadCounterEnabled(config.isSdmReadCounterEnabled());
        if (config.isSdmReadCounterEnabled()) {
            ds.setSdmReadCounterOffset(intToBytes3(config.getSdmReadCounterOffset()));
        }

        // Límite de contador
        ds.setSDMReadCounterLimitEnabled(config.isSdmReadCounterLimitEnabled());
        if (config.isSdmReadCounterLimitEnabled()) {
            ds.setSdmReadCounterLimit(intToBytes3(config.getSdmReadCounterLimit()));
        }

        // Cifrado
        ds.setSDMEncryptFileDataEnabled(config.isSdmEncryptionEnabled());
        if (config.isSdmEncryptionEnabled()) {
            ds.setSdmEncryptionOffset(intToBytes3(config.getSdmEncOffset()));
            ds.setSdmEncryptionLength(intToBytes3(config.getSdmEncLength()));
        }

        // MAC
        ds.setSdmMacOffset(intToBytes3(config.getSdmMacOffset()));
        ds.setSdmMacInputOffset(intToBytes3(config.getSdmMacOffset()));

        // Derechos de acceso SDM
        ds.setSdmAccessRights(new byte[]{config.getSdmAccessRights(), config.getSdmAccessRights()});

        cardV3.changeDESFireEV3FileSettings(NDEF_DATA_FILE_ID, ds);
        Log.d(TAG, "SDM configurado");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LEER NDEF
    // ─────────────────────────────────────────────────────────────────────────

    public byte[] readNdefFile() throws Exception {
        cardV1.selectApplication(NDEF_AID);
        return cardV1.readData(NDEF_DATA_FILE_ID, 0, 0, IDESFireEV1.CommunicationType.Plain);
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
        authenticateApp(null, 0);
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
        // El fichero NDEF: [2 bytes NLEN][NDEF record]
        // Record URI: [0xD1][0x01][payloadLen][0x55][uriId][url_sin_prefijo]
        // Offset base de la URL en el fichero = 7 bytes
        int urlOffsetInFile = 7;
        int protocolLen = url.startsWith("https://") ? 8 : (url.startsWith("http://") ? 7 : 0);

        // Buscar placeholder PICC (32 ceros)
        int piccPos = url.indexOf("00000000000000000000000000000000");
        if (piccPos >= 0) {
            config.setPiccDataOffset(urlOffsetInFile + (piccPos - protocolLen));
        }

        // Buscar placeholder MAC (16 ceros, no parte de los 32)
        String urlTemp = url.replace("00000000000000000000000000000000", "################################");
        int macPos = urlTemp.indexOf("0000000000000000");
        if (macPos >= 0) {
            config.setSdmMacOffset(urlOffsetInFile + (macPos - protocolLen));
        }

        // Buscar placeholder contador (6 ceros)
        String urlTemp2 = urlTemp.replace("0000000000000000", "################");
        int ctrPos = urlTemp2.indexOf("000000");
        if (ctrPos >= 0) {
            config.setSdmReadCounterOffset(urlOffsetInFile + (ctrPos - protocolLen));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AUXILIARES PRIVADOS
    // ─────────────────────────────────────────────────────────────────────────

    private void authenticateApp(byte[] key, int keyNo) throws Exception {
        byte[] k = (key != null) ? key : DEFAULT_KEY;
        cardV1.authenticate(buildKeyData(k), keyNo, false, IDESFireEV1.AuthType.Native);
    }

    private void createCapabilityContainerFile() throws Exception {
        byte readAccess  = (byte) 0xEE;
        byte writeAccess = (byte) 0x00;

        DESFireEV3File.StdEV3DataFileSettings ccSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                readAccess, readAccess, writeAccess, readAccess,
                15,
                (byte) 0x00, // SDM deshabilitado
                null
            );

        cardV3.createFile(NDEF_CC_FILE_ID, ccSettings);

        byte[] cc = new byte[]{
            0x00, 0x0F, 0x20,
            0x00, (byte)(NDEF_FILE_SIZE >> 8), (byte)NDEF_FILE_SIZE,
            0x00, (byte)0xFF,
            0x04, 0x06,
            0x00, NDEF_DATA_FILE_ID,
            0x00, (byte)(NDEF_FILE_SIZE >> 8), (byte)NDEF_FILE_SIZE,
            0x00, (byte)0x80
        };

        cardV1.writeData(NDEF_CC_FILE_ID, 0, cc.length, cc, IDESFireEV1.CommunicationType.Plain);
        Log.d(TAG, "Fichero CC creado");
    }

    private void createNdefDataFile() throws Exception {
        byte readAccess  = (byte) 0xEE;
        byte writeAccess = (byte) 0x00;

        DESFireEV3File.StdEV3DataFileSettings ndefSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                readAccess, readAccess, writeAccess, readAccess,
                NDEF_FILE_SIZE,
                (byte) 0x00,
                null
            );

        cardV3.createFile(NDEF_DATA_FILE_ID, ndefSettings);
        Log.d(TAG, "Fichero NDEF creado");
    }

    private byte[] buildNdefUriMessage(String url) {
        byte uriId;
        String payload;
        if (url.startsWith("https://")) { uriId = 0x04; payload = url.substring(8); }
        else if (url.startsWith("http://")) { uriId = 0x03; payload = url.substring(7); }
        else { uriId = 0x00; payload = url; }

        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        int payloadLen = 1 + payloadBytes.length;

        byte[] record = new byte[4 + payloadLen];
        record[0] = (byte) 0xD1;
        record[1] = 0x01;
        record[2] = (byte) payloadLen;
        record[3] = 0x55;
        record[4] = uriId;
        System.arraycopy(payloadBytes, 0, record, 5, payloadBytes.length);

        byte[] message = new byte[2 + record.length];
        message[0] = (byte) ((record.length >> 8) & 0xFF);
        message[1] = (byte) (record.length & 0xFF);
        System.arraycopy(record, 0, message, 2, record.length);
        return message;
    }

    private String parseNdefUriRecord(byte[] buf, int offset, int length) {
        try {
            if (length < 5) return new String(buf, offset, length, StandardCharsets.UTF_8);
            int typeLen = buf[offset + 1] & 0xFF;
            int payloadLen = buf[offset + 2] & 0xFF;
            int payloadStart = offset + 3 + typeLen;
            if (payloadStart >= buf.length || payloadLen < 1) return "(error NDEF)";
            byte uriId = buf[payloadStart];
            String prefix = uriIdToPrefix(uriId);
            String rest = new String(buf, payloadStart + 1, payloadLen - 1, StandardCharsets.UTF_8);
            return prefix + rest;
        } catch (Exception e) { return "(error: " + e.getMessage() + ")"; }
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
     * Convierte un int a 3 bytes little-endian (formato que usa DESFire para offsets)
     */
    private byte[] intToBytes3(int value) {
        return new byte[]{
            (byte)(value & 0xFF),
            (byte)((value >> 8) & 0xFF),
            (byte)((value >> 16) & 0xFF)
        };
    }

    /**
     * Construye IKeyData para AES-128.
     * Usa reflexión para acceder a la implementación interna del SDK.
     */
    private IKeyData buildKeyData(byte[] keyBytes) throws Exception {
        // El SDK NXP expone una forma de construir claves a través de DESFireFactory
        // o mediante la clase interna. Usamos reflexión como fallback seguro.
        try {
            Class<?> keyClass = Class.forName("com.nxp.nfclib.desfire.DESFireKeyUtils");
            java.lang.reflect.Method getKey = keyClass.getMethod("getKey", byte[].class, KeyType.class);
            return (IKeyData) getKey.invoke(null, keyBytes, KeyType.AES128);
        } catch (Exception e) {
            // Fallback: intentar con la clase de implementación directa
            try {
                Class<?> implClass = Class.forName("com.nxp.nfclib.desfire.DESFireEV1");
                java.lang.reflect.Method getKey = implClass.getMethod("getDefaultKey", byte[].class);
                return (IKeyData) getKey.invoke(cardV1, keyBytes);
            } catch (Exception e2) {
                throw new Exception("No se pudo construir IKeyData: " + e.getMessage() + " / " + e2.getMessage());
            }
        }
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
