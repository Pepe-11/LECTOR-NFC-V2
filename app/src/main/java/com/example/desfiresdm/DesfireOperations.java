package com.example.desfiresdm;

import android.util.Log;

import com.nxp.nfclib.KeyType;
import com.nxp.nfclib.desfire.DESFireEV3File;
import com.nxp.nfclib.desfire.EV3ApplicationKeySettings;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.IDESFireEV3;
import com.nxp.nfclib.interfaces.IKeyData;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Operaciones DESFire EV3.
 * Signaturas verificadas contra el AAR de TapLinx v5.0.0.
 *
 * authenticate  : (int keyNo, AuthType, KeyType, IKeyData) -> void
 * getApplicationIDs : () -> ArrayList
 * readData      : (int, int, int) -> byte[]
 * writeData     : (int, int, byte[]) -> void  |  (int, int, byte[], CommunicationType) -> void
 * createApplication (EV3): (byte[], EV3ApplicationKeySettings) -> void
 *                       or (byte[], EV3ApplicationKeySettings, byte[], byte[]) -> void
 * createFile (EV3): (int, EV3FileSettings) -> void
 * changeKey : (int, KeyType, byte[], byte[], byte) -> void
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    public static final byte[] NDEF_AID        = new byte[]{(byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01};
    public static final int    NDEF_CC_FILE_ID  = 0x01;
    public static final int    NDEF_DATA_FILE_ID = 0x02;
    public static final int    NDEF_FILE_SIZE   = 256;
    public static final byte[] DEFAULT_KEY      = new byte[16]; // 16 x 0x00

    private final IDESFireEV1 cardV1;
    private final IDESFireEV3 cardV3;

    public DesfireOperations(IDESFireEV3 card) {
        this.cardV3 = card;
        this.cardV1 = card;
    }

    /** Constructor sin tarjeta (solo para calcular offsets) */
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

    /**
     * getApplicationIDs() devuelve ArrayList en TapLinx v5 — se convierte a lista legible.
     */
    @SuppressWarnings("unchecked")
    public ArrayList<byte[]> readApplicationIds() throws Exception {
        Object result = cardV1.getApplicationIDs();
        if (result instanceof ArrayList) {
            return (ArrayList<byte[]>) result;
        }
        // fallback: int[] (versiones antiguas)
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
    // AUTENTICACIÓN
    // Signatura: authenticate(int keyNo, AuthType authType, KeyType keyType, IKeyData keyData)
    // ─────────────────────────────────────────────────────────────────────────

    public void authenticatePicc(byte[] masterKey) throws Exception {
        byte[] key = (masterKey != null) ? masterKey : DEFAULT_KEY;
        IKeyData keyData = buildKeyData(key);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128, keyData);
        Log.d(TAG, "Autenticado en PICC");
    }

    public void authenticateApp(byte[] appKey, int keyNo) throws Exception {
        byte[] k = (appKey != null) ? appKey : DEFAULT_KEY;
        cardV1.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.AES128, buildKeyData(k));
    }

    public void selectAndAuthenticate(byte[] aid, int keyNo, byte[] appKey) throws Exception {
        cardV1.selectApplication(aid);
        authenticateApp(appKey, keyNo);
        Log.d(TAG, "Autenticado en app " + bytesToHex(aid));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CREAR APLICACIÓN NDEF
    // ─────────────────────────────────────────────────────────────────────────

    public void createNdefApp(byte[] appMasterKey) throws Exception {
        cardV1.selectApplication(new byte[]{0x00, 0x00, 0x00});
        authenticatePicc(null);

        // Verificar si ya existe
        ArrayList<byte[]> existingApps = readApplicationIds();
        for (byte[] aid : existingApps) {
            if (Arrays.equals(aid, NDEF_AID)) {
                Log.w(TAG, "App NDEF ya existe");
                return;
            }
        }

        // Construir EV3ApplicationKeySettings con el Builder público
        // (createEV3ApplicationKeySettings es package-private en TapLinx v5;
        //  se usa new EV3ApplicationKeySettings.Builder() como en EV1/EV2ApplicationKeySettings)
        EV3ApplicationKeySettings.Builder keySettingsBuilder = new EV3ApplicationKeySettings.Builder();
        keySettingsBuilder.setKeyTypeOfApplicationKeys(KeyType.AES128);
        keySettingsBuilder.setMaxNumberOfApplicationKeys(2);
        keySettingsBuilder.setAppMasterKeyChangeable(true);
        keySettingsBuilder.setAppKeySettingsChangeable(true);
        keySettingsBuilder.setAuthenticationRequiredForFileManagement(false);
        EV3ApplicationKeySettings keySettings = keySettingsBuilder.build();

        // createApplication(byte[] aid, EV3ApplicationKeySettings)
        cardV3.createApplication(NDEF_AID, keySettings);
        Log.d(TAG, "Aplicación NDEF creada");

        cardV1.selectApplication(NDEF_AID);
        authenticateApp(null, 0);

        // Cambiar clave si se proporcionó
        if (appMasterKey != null && !Arrays.equals(appMasterKey, DEFAULT_KEY)) {
            // changeKey(int keyNo, KeyType, byte[] newKey, byte[] oldKey, byte keyVersion)
            cardV1.changeKey(0, KeyType.AES128, appMasterKey, DEFAULT_KEY, (byte) 0x01);
        }

        createCapabilityContainerFile();
        createNdefDataFile();
        Log.d(TAG, "App NDEF lista");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ESCRIBIR URL NDEF
    // writeData(int fileNo, int offset, byte[]) -> void
    // ─────────────────────────────────────────────────────────────────────────

    public void writeNdefUrl(String url) throws Exception {
        byte[] ndefMessage = buildNdefUriMessage(url);
        if (ndefMessage.length > NDEF_FILE_SIZE) {
            throw new Exception("URL demasiado larga (" + ndefMessage.length + " bytes).");
        }

        cardV1.selectApplication(NDEF_AID);
        authenticateApp(null, 0);

        // writeData(int fileNo, int offset, byte[] data)
        cardV1.writeData(NDEF_DATA_FILE_ID, 0, ndefMessage);
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
    // readData(int fileNo, int offset, int length) -> byte[]
    // ─────────────────────────────────────────────────────────────────────────

    public byte[] readNdefFile() throws Exception {
        cardV1.selectApplication(NDEF_AID);
        // readData(int fileNo, int offset, int length) — length 0 = leer todo
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
        // NDEF file layout: [2 bytes NLEN][D1 01 payloadLen 55 uriId][url sin prefijo]
        // offset base hasta el comienzo de la url en el fichero = 7 bytes
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
                15,
                (byte)0x00,
                null
            );
        cardV3.createFile(NDEF_CC_FILE_ID, ccSettings);

        byte[] cc = new byte[]{
            0x00, 0x0F, 0x20,
            0x00, (byte)(NDEF_FILE_SIZE >> 8), (byte)NDEF_FILE_SIZE,
            0x00, (byte)0xFF,
            0x04, 0x06,
            0x00, (byte)NDEF_DATA_FILE_ID,
            0x00, (byte)(NDEF_FILE_SIZE >> 8), (byte)NDEF_FILE_SIZE,
            0x00, (byte)0x80
        };
        cardV1.writeData(NDEF_CC_FILE_ID, 0, cc);
        Log.d(TAG, "Fichero CC creado");
    }

    private void createNdefDataFile() throws Exception {
        DESFireEV3File.StdEV3DataFileSettings ndefSettings =
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                (byte)0xEE, (byte)0xEE, (byte)0x00, (byte)0xEE,
                NDEF_FILE_SIZE,
                (byte)0x00,
                null
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

    /** int → 3 bytes little-endian (formato DESFire para offsets) */
    private byte[] intTo3Bytes(int v) {
        return new byte[]{(byte)(v & 0xFF), (byte)((v >> 8) & 0xFF), (byte)((v >> 16) & 0xFF)};
    }

    /**
     * Construye IKeyData para AES-128.
     * Usa reflexión para acceder a DESFireKeyUtils (clase interna no pública).
     */
    private IKeyData buildKeyData(byte[] keyBytes) throws Exception {
        try {
            Class<?> cls = Class.forName("com.nxp.nfclib.desfire.DESFireKeyUtils");
            java.lang.reflect.Method m = cls.getMethod("getKey", byte[].class, KeyType.class);
            return (IKeyData) m.invoke(null, keyBytes, KeyType.AES128);
        } catch (Exception e) {
            // Fallback: DefaultKeyData
            try {
                Class<?> cls = Class.forName("com.nxp.nfclib.defaultimpl.KeyData");
                java.lang.reflect.Constructor<?> ctor = cls.getConstructor(byte[].class, KeyType.class);
                return (IKeyData) ctor.newInstance(keyBytes, KeyType.AES128);
            } catch (Exception e2) {
                throw new Exception("No se pudo construir IKeyData: " + e2.getMessage());
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
