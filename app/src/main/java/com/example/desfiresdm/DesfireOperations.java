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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Operaciones DESFire EV3 — réplica exacta del script Python nfc_writer.py
 *
 * CORRECCIONES clave respecto a versión anterior:
 *
 *  1. isoFID de la APLICACIÓN no puede ser null.
 *     El SDK lanza: UsageException("iso file ID [isoFID] should not be null")
 *     Valor correcto según spec NDEF/DESFire: {0x10, 0xE1}
 *
 *  2. Flujo completamente automático en writeNdefUrl():
 *     - Detecta si la tarjeta ya tiene app NDEF con ISO IDs correctos.
 *     - Si CC apunta a E104 → app OK → solo escribe URL.
 *     - Si no existe o CC incorrecto → crea/recrea app con ISO IDs → escribe URL.
 *     - Sin checkbox, sin opción manual para el usuario.
 *
 * ISO IDs estándar NDEF para DESFire:
 *   APP_ISO_FID : {0x10, 0xE1}  — obligatorio (no null)
 *   ISO_DF_NAME : D2 76 00 00 85 01 01  — SELECT por DF Name en móviles
 *   CC  (E103)  : {0xE1, 0x03}
 *   NDEF (E104) : {0xE1, 0x04}
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    public static final byte[] MASTER_AID      = {0x00, 0x00, 0x00};
    public static final byte[] NDEF_AID        = {(byte)0xD2, 0x76, 0x00};

    public static final int    CC_FILE_ID      = 0x01;
    public static final int    NDEF_FILE_ID    = 0x02;
    public static final int    NDEF_FILE_SIZE  = 255;

    /** ISO FID de la aplicación — 2 bytes, NO puede ser null */
    private static final byte[] APP_ISO_FID    = {0x10, (byte)0xE1};

    /** ISO DF Name — SELECT 00 A4 04 00 07 D2 76 00 00 85 01 01 */
    private static final byte[] ISO_DF_NAME    = {
        (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01
    };

    private static final byte[] ISO_FID_CC     = {(byte)0xE1, 0x03};
    private static final byte[] ISO_FID_NDEF   = {(byte)0xE1, 0x04};

    public static final byte[] KEY_AES_DEFAULT = new byte[16]; // 16 × 0x00
    public static final byte[] KEY_DES_DEFAULT = new byte[8];  //  8 × 0x00

    /** CC correcto — 15 bytes, apunta a E104 */
    private static final byte[] CC_DATA = {
        0x00, 0x0F, 0x20, 0x00, 0x7F, 0x00, 0x73,
        0x04, 0x06,
        (byte)0xE1, 0x04,   // ← ISO FID fichero NDEF
        0x00, (byte)0xFF,   // max NDEF
        0x00, 0x00          // acceso libre
    };

    private final IDESFireEV1 cardV1;
    private final IDESFireEV3 cardV3;

    public DesfireOperations(IDESFireEV3 card) {
        this.cardV3 = card;
        this.cardV1 = card;
    }

    /** Constructor sin tarjeta (solo para preview de offsets en la UI) */
    public DesfireOperations() {
        this.cardV3 = null;
        this.cardV1 = null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PUNTO DE ENTRADA — WriteUrlActivity pulsa ESCRIBIR
    //
    // Flujo automático:
    //   1. Intentar leer CC de la app NDEF.
    //   2. Si CC correcto (E104) → solo escribir URL.
    //   3. Si no → crear/recrear app → escribir URL.
    // ─────────────────────────────────────────────────────────────────────────

    public void writeNdefUrl(String url) throws Exception {
        if (url == null || url.isEmpty())
            throw new Exception("La URL no puede estar vacía.");

        byte[] ndefMsg = buildNdefUriMessage(url);
        if (ndefMsg.length > NDEF_FILE_SIZE)
            throw new Exception("URL demasiado larga (" + ndefMsg.length + " bytes, máx " + NDEF_FILE_SIZE + ").");

        Log.i(TAG, "writeNdefUrl: " + url);

        // ── Comprobar si la app ya está bien formateada ───────────────────────
        boolean needsSetup = true;
        try {
            cardV1.selectApplication(NDEF_AID);
            try { authApp(KEY_AES_DEFAULT, 0); } catch (Exception ignored) {}
            byte[] cc = cardV1.readData(CC_FILE_ID, 0, 15);
            if (ccIsCorrect(cc)) {
                Log.i(TAG, "App NDEF con ISO IDs OK — solo escribo URL.");
                needsSetup = false;
            } else {
                Log.w(TAG, "CC incorrecto (sin ISO IDs) — se recreará la app.");
            }
        } catch (Exception e) {
            Log.i(TAG, "App NDEF no disponible: " + e.getMessage() + " — se creará.");
        }

        if (needsSetup) {
            setupNdefApp(url);
        } else {
            // App correcta: solo escribir URL
            cardV1.selectApplication(NDEF_AID);
            authApp(KEY_AES_DEFAULT, 0);
            cardV1.writeData(NDEF_FILE_ID, 0, ndefMsg);
            Log.i(TAG, "URL actualizada OK.");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CREAR / RECREAR APP NDEF CON ISO IDs
    // ─────────────────────────────────────────────────────────────────────────

    private void setupNdefApp(String url) throws Exception {
        Log.i(TAG, "=== setupNdefApp ===");

        // 1. PICC master auth
        cardV1.selectApplication(MASTER_AID);
        boolean wasDes = authPicc();

        // 2. Borrar app NDEF si existe
        if (ndefAppExists()) {
            Log.w(TAG, "Borrando app NDEF existente...");
            deleteNdefApp(wasDes);
            // Tras borrar, re-seleccionar y re-autenticar PICC
            cardV1.selectApplication(MASTER_AID);
            if (wasDes)
                cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES, keyData(KEY_DES_DEFAULT, "DES"));
            else
                cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,   keyData(KEY_AES_DEFAULT, "AES"));
        }

        // 3. Crear app con APP_ISO_FID + ISO_DF_NAME
        //    NOTA: isoFID={0x10,0xE1} — el SDK lanza UsageException si es null
        EV3ApplicationKeySettings ks = new EV3ApplicationKeySettings.Builder()
            .setKeyTypeOfApplicationKeys(KeyType.AES128)
            .setMaxNumberOfApplicationKeys(2)
            .setAppMasterKeyChangeable(true)
            .setAppKeySettingsChangeable(true)
            .setAuthenticationRequiredForFileManagement(false)
            .setIsoFileIdentifierPresent(true)
            .build();

        cardV3.createApplication(NDEF_AID, ks, APP_ISO_FID, ISO_DF_NAME);
        Log.d(TAG, "App creada — APP_ISO_FID=" + bytesToHex(APP_ISO_FID)
            + " DF_NAME=" + bytesToHex(ISO_DF_NAME));

        // 4. Seleccionar y autenticar la nueva app
        cardV1.selectApplication(NDEF_AID);
        cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
            keyData(KEY_AES_DEFAULT, "AES"));

        // 5. Crear fichero CC con ISO FID E103
        cardV3.createFile(CC_FILE_ID, ISO_FID_CC,
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                (byte)0xEE, (byte)0xEE, (byte)0x00, (byte)0xEE,
                15, (byte)0x00, ISO_FID_CC));
        Log.d(TAG, "File CC creado (E103).");

        // 6. Crear fichero NDEF con ISO FID E104
        cardV3.createFile(NDEF_FILE_ID, ISO_FID_NDEF,
            new DESFireEV3File.StdEV3DataFileSettings(
                IDESFireEV1.CommunicationType.Plain,
                (byte)0xEE, (byte)0xEE, (byte)0x00, (byte)0xEE,
                NDEF_FILE_SIZE, (byte)0x00, ISO_FID_NDEF));
        Log.d(TAG, "File NDEF creado (E104).");

        // 7. Escribir CC y URL
        cardV1.writeData(CC_FILE_ID, 0, CC_DATA);
        cardV1.writeData(NDEF_FILE_ID, 0, buildNdefUriMessage(url));
        Log.i(TAG, "=== setupNdefApp OK. URL: " + url + " ===");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURAR SDM
    // ─────────────────────────────────────────────────────────────────────────

    public void configureSdm(SdmConfig config) throws Exception {
        Log.i(TAG, "=== configureSdm ===");
        cardV1.selectApplication(NDEF_AID);
        if (authApp(KEY_AES_DEFAULT, 0))
            throw new Exception("Tarjeta en DES. Escribe una URL primero para migrar a AES.");

        DESFireEV3File.EV3FileSettings raw = cardV3.getDESFireEV3FileSettings(NDEF_FILE_ID);
        if (!(raw instanceof DESFireEV3File.StdEV3DataFileSettings))
            throw new Exception("El fichero NDEF no es StdEV3DataFileSettings.");

        DESFireEV3File.StdEV3DataFileSettings ds = (DESFireEV3File.StdEV3DataFileSettings) raw;
        ds.setSDMEnabled(true);
        ds.setUIDMirroringEnabled(config.isUidMirroringEnabled());
        if (config.isUidMirroringEnabled())
            ds.setUidOffset(intTo3LE(config.getPiccDataOffset()));
        ds.setSDMReadCounterEnabled(config.isSdmReadCounterEnabled());
        if (config.isSdmReadCounterEnabled())
            ds.setSdmReadCounterOffset(intTo3LE(config.getSdmReadCounterOffset()));
        ds.setSDMReadCounterLimitEnabled(config.isSdmReadCounterLimitEnabled());
        if (config.isSdmReadCounterLimitEnabled())
            ds.setSdmReadCounterLimit(intTo3LE(config.getSdmReadCounterLimit()));
        ds.setSDMEncryptFileDataEnabled(config.isSdmEncryptionEnabled());
        if (config.isSdmEncryptionEnabled()) {
            ds.setSdmEncryptionOffset(intTo3LE(config.getSdmEncOffset()));
            ds.setSdmEncryptionLength(intTo3LE(config.getSdmEncLength()));
        }
        ds.setSdmMacOffset(intTo3LE(config.getSdmMacOffset()));
        ds.setSdmMacInputOffset(intTo3LE(2));
        ds.setSdmAccessRights(new byte[]{config.getSdmAccessRights(), config.getSdmAccessRights()});
        cardV3.changeDESFireEV3FileSettings(NDEF_FILE_ID, ds);
        Log.d(TAG, "SDM configurado.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LEER
    // ─────────────────────────────────────────────────────────────────────────

    public IDESFireEV1.CardDetails readCardDetails() throws Exception {
        return cardV1.getCardDetails();
    }

    /** Devuelve los AIDs de todas las aplicaciones en la tarjeta */
    public int[] getApplicationIDs() throws Exception {
        cardV1.selectApplication(MASTER_AID);
        return cardV1.getApplicationIDs();
    }

    public byte[] readNdefRaw() throws Exception {
        cardV1.selectApplication(NDEF_AID);
        return cardV1.readData(NDEF_FILE_ID, 0, 0);
    }

    public String readNdefAsString() throws Exception {
        byte[] raw = readNdefRaw();
        if (raw == null || raw.length < 4) return "(vacío)";
        int nlen = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
        if (nlen == 0) return "(sin NDEF)";
        return parseNdefUri(raw, 2, nlen);
    }

    public DESFireEV3File.StdEV3DataFileSettings readSdmSettings() throws Exception {
        cardV1.selectApplication(NDEF_AID);
        try { authApp(KEY_AES_DEFAULT, 0); } catch (Exception ignored) {}
        DESFireEV3File.EV3FileSettings s = cardV3.getDESFireEV3FileSettings(NDEF_FILE_ID);
        return (s instanceof DESFireEV3File.StdEV3DataFileSettings)
            ? (DESFireEV3File.StdEV3DataFileSettings) s : null;
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

        final int BASE = 7; // NLEN(2)+flags(1)+typeLen(1)+payloadLen(1)+'U'(1)+uriId(1)

        String u = url;
        int piccPos = u.indexOf("00000000000000000000000000000000");
        if (piccPos >= 0) {
            config.setPiccDataOffset(BASE + (piccPos - prefixLen));
            u = u.replace("00000000000000000000000000000000", "################################");
        }
        int macPos = u.indexOf("0000000000000000");
        if (macPos >= 0) {
            config.setSdmMacOffset(BASE + (macPos - prefixLen));
            u = u.replace("0000000000000000", "################");
        }
        int ctrPos = u.indexOf("000000");
        if (ctrPos >= 0)
            config.setSdmReadCounterOffset(BASE + (ctrPos - prefixLen));

        Log.d(TAG, "SDM offsets → PICC=" + config.getPiccDataOffset()
            + " MAC=" + config.getSdmMacOffset()
            + " CTR=" + config.getSdmReadCounterOffset());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS PRIVADOS
    // ─────────────────────────────────────────────────────────────────────────

    /** Auth PICC: prueba AES, luego DES. Devuelve true si era DES. */
    private boolean authPicc() throws Exception {
        try {
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
                keyData(KEY_AES_DEFAULT, "AES"));
            return false;
        } catch (Exception ignored) {}
        try {
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
                keyData(KEY_DES_DEFAULT, "DES"));
            return true;
        } catch (Exception e) {
            throw new Exception("No se pudo autenticar en PICC: " + e.getMessage());
        }
    }

    /** Auth app: prueba AES, luego DES. Devuelve true si era DES. */
    private boolean authApp(byte[] key, int keyNo) throws Exception {
        try {
            byte[] k = (key != null && key.length == 16) ? key : KEY_AES_DEFAULT;
            cardV1.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.AES128, keyData(k, "AES"));
            return false;
        } catch (Exception ignored) {}
        try {
            cardV1.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
                keyData(KEY_DES_DEFAULT, "DES"));
            return true;
        } catch (Exception e) {
            throw new Exception("No se pudo autenticar en app: " + e.getMessage());
        }
    }

    private boolean ndefAppExists() {
        try {
            int[] ids = cardV1.getApplicationIDs();
            if (ids == null) return false;
            int target = (NDEF_AID[0] & 0xFF)
                | ((NDEF_AID[1] & 0xFF) << 8)
                | ((NDEF_AID[2] & 0xFF) << 16);
            for (int id : ids) if (id == target) return true;
        } catch (Exception ignored) {}
        return false;
    }

    private void deleteNdefApp(boolean wasDes) throws Exception {
        cardV1.selectApplication(MASTER_AID);
        if (wasDes)
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
                keyData(KEY_DES_DEFAULT, "DES"));
        else
            cardV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.AES128,
                keyData(KEY_AES_DEFAULT, "AES"));
        try { cardV1.deleteApplication(NDEF_AID); } catch (Exception e) {
            Log.w(TAG, "deleteApplication: " + e.getMessage());
        }
    }

    /** CC correcto si los bytes [8..9] son E1 04 (ISO FID del fichero NDEF). */
    private boolean ccIsCorrect(byte[] cc) {
        return cc != null && cc.length >= 11
            && (cc[8] & 0xFF) == 0xE1 && (cc[9] & 0xFF) == 0x04;
    }

    private byte[] buildNdefUriMessage(String url) {
        byte uriId; String payload;
        if      (url.startsWith("https://www.")) { uriId = 0x02; payload = url.substring(12); }
        else if (url.startsWith("https://"))     { uriId = 0x04; payload = url.substring(8);  }
        else if (url.startsWith("http://www."))  { uriId = 0x01; payload = url.substring(11); }
        else if (url.startsWith("http://"))      { uriId = 0x03; payload = url.substring(7);  }
        else                                     { uriId = 0x00; payload = url;               }

        byte[] pb = payload.getBytes(StandardCharsets.UTF_8);
        int plen = 1 + pb.length;
        byte[] rec = new byte[4 + plen];
        rec[0] = (byte)0xD1; rec[1] = 0x01;
        rec[2] = (byte)(plen & 0xFF); rec[3] = 0x55;
        rec[4] = uriId;
        System.arraycopy(pb, 0, rec, 5, pb.length);
        byte[] msg = new byte[2 + rec.length];
        msg[0] = (byte)((rec.length >> 8) & 0xFF);
        msg[1] = (byte)(rec.length & 0xFF);
        System.arraycopy(rec, 0, msg, 2, rec.length);
        return msg;
    }

    private String parseNdefUri(byte[] buf, int off, int len) {
        try {
            int typeLen = buf[off + 1] & 0xFF;
            int ps = off + 3 + typeLen;
            int plen = buf[off + 2] & 0xFF;
            if (ps >= buf.length || plen < 1) return "(NDEF inválido)";
            byte uid = buf[ps];
            String rest = new String(buf, ps + 1,
                Math.min(plen - 1, buf.length - ps - 1), StandardCharsets.UTF_8);
            return uriPrefix(uid) + rest;
        } catch (Exception e) { return "(error: " + e.getMessage() + ")"; }
    }

    private String uriPrefix(byte id) {
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

    private byte[] intTo3LE(int v) {
        return new byte[]{(byte)(v & 0xFF), (byte)((v >> 8) & 0xFF), (byte)((v >> 16) & 0xFF)};
    }

    private IKeyData keyData(byte[] raw, String algo) throws Exception {
        SecretKey sk;
        if ("DES".equals(algo)) {
            byte[] ede = new byte[24];
            System.arraycopy(raw, 0, ede, 0, 8);
            System.arraycopy(raw, 0, ede, 8, 8);
            System.arraycopy(raw, 0, ede, 16, 8);
            sk = new SecretKeySpec(ede, "DESede");
        } else {
            sk = new SecretKeySpec(raw, algo);
        }
        KeyData kd = new KeyData();
        kd.setKey(sk);
        return kd;
    }

    public static String bytesToHex(byte[] b) {
        if (b == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }
}
