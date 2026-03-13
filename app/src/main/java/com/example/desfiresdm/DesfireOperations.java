package com.example.desfiresdm;

import android.nfc.tech.IsoDep;
import android.util.Log;

import com.nxp.nfclib.KeyType;
import com.nxp.nfclib.defaultimpl.KeyData;
import com.nxp.nfclib.desfire.DESFireEV3File;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.IDESFireEV3;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Traducción fiel de nfc_writer.py a Java/Android.
 *
 * ARQUITECTURA:
 *   - Formateo + escritura NDEF → IsoDep.transceive() directo (APDUs raw)
 *   - SDM → TapLinx IDESFireEV3 (auth AES + changeDESFireEV3FileSettings)
 *
 * FLUJO writeNdefUrl():
 *   1. checkCardStatus()  → 'ready' / 'needs_cc' / 'needs_format'
 *   2. formatear()        → DES auth nativo + CreateApp + CreateFiles + WriteCC
 *   3. corregirCC()       → solo corrige el CC si E103/E104 existen
 *   4. escribir()         → ISO SELECT + ISO UPDATE BINARY sin auth
 *
 * FLUJO configureSdm():
 *   - Auth AES via TapLinx + changeDESFireEV3FileSettings
 *   - Requiere que la tarjeta ya esté formateada con writeNdefUrl()
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    // ── Constantes — idénticas al script Python ───────────────────────────────
    public static final int    NDEF_FILE_SIZE  = 253;
    public static final byte[] MASTER_KEY_DES  = new byte[8]; // 8 × 0x00

    private static final byte[] DESFIRE_AID = {(byte)0xD2, 0x76, 0x00};
    private static final byte[] ISO_DF_NAME = {
        (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01
    };

    // CC_DATA idéntico al script Python
    private static final byte[] CC_DATA = {
        0x00, 0x0F,             // CC size: 15 bytes
        0x20,                   // NDEF version 2.0
        0x00, 0x7F,             // MLe max read
        0x00, 0x73,             // MLc max write
        0x04, 0x06,             // NDEF File Control TLV
        (byte)0xE1, 0x04,       // ← ISO File ID E104 (clave para móviles)
        0x00, (byte)0xFF,       // max NDEF: 255 bytes
        0x00,                   // lectura libre
        0x00                    // escritura libre
    };

    private final IDESFireEV3 cardV3;   // solo para SDM (TapLinx)
    private final IsoDep      isoDep;   // canal raw para todo lo demás

    /**
     * Constructor principal — requiere tarjeta activa en NfcManager.
     */
    public DesfireOperations(IDESFireEV3 card) {
        this.cardV3 = card;
        this.isoDep = NfcManager.getInstance().getCurrentIsoDep();
        if (this.isoDep == null)
            Log.e(TAG, "IsoDep null — las operaciones de escritura fallarán");
    }

    /**
     * Constructor vacío — solo para calcular offsets SDM en la UI sin tarjeta.
     */
    public DesfireOperations() {
        this.cardV3 = null;
        this.isoDep = null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  ESCRITURA NDEF — punto de entrada principal
    // ─────────────────────────────────────────────────────────────────────────

    public void writeNdefUrl(String url) throws Exception {
        checkIsoDep();
        if (url == null || url.isEmpty()) throw new Exception("URL vacía.");

        byte[] ndefData = buildUri(url);
        if (ndefData.length > NDEF_FILE_SIZE)
            throw new Exception("URL demasiado larga (" + ndefData.length + " bytes, máx " + NDEF_FILE_SIZE + ").");

        Log.i(TAG, "writeNdefUrl: " + url);

        String status = checkCardStatus();
        Log.i(TAG, "Estado tarjeta: " + status);

        switch (status) {
            case "ready":
                Log.i(TAG, "Tarjeta lista — escribiendo directamente.");
                break;
            case "needs_cc":
                Log.w(TAG, "CC incorrecto — corrigiendo...");
                corregirCC();
                break;
            case "needs_format":
            default:
                Log.w(TAG, "Sin formato NDEF ISO — formateando...");
                formatear();
                break;
        }

        escribir(ndefData);
        Log.i(TAG, "✅ URL escrita: " + url);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  checkCardStatus() — idéntico a check_card_status() del Python
    // ─────────────────────────────────────────────────────────────────────────

    private String checkCardStatus() {
        // Intentar SELECT app por DF Name
        if (!swOk(send(apduSelectApp()))) return "needs_format";

        // Intentar SELECT E103 y E104
        if (!swOk(send(apduSelectFile(0xE1, 0x03)))) return "needs_format";
        if (!swOk(send(apduSelectFile(0xE1, 0x04)))) return "needs_format";

        // Leer CC (15 bytes) y verificar que apunta a E104
        byte[] cc = send(new byte[]{0x00, (byte)0xB0, 0x00, 0x00, 0x0F});
        if (!swOk(cc) || cc.length < 13) return "needs_cc";

        // El CC tiene SW al final; datos[8] y datos[9] deben ser E1 04
        if ((cc[8] & 0xFF) == 0xE1 && (cc[9] & 0xFF) == 0x04) return "ready";
        return "needs_cc";
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  formatear() — idéntico a formatear() del Python
    // ─────────────────────────────────────────────────────────────────────────

    private void formatear() throws Exception {
        Log.i(TAG, "=== formatear() ===");

        // SELECT Master App: 90 5A 00 00 03 00 00 00 00
        sendOk(new byte[]{(byte)0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00},
            "SELECT Master App");

        // Auth DES clave maestra
        if (!authenticateDes(0x00, MASTER_KEY_DES))
            throw new Exception("Auth master DES fallida.");
        Log.d(TAG, "Auth master DES OK");

        // GetApplicationIDs: 90 6A 00 00 00
        byte[] appsRaw = send(new byte[]{(byte)0x90, 0x6A, 0x00, 0x00, 0x00});
        if (ndefAppExists(appsRaw)) {
            Log.w(TAG, "App NDEF existe — borrando...");
            sendOk(concat(
                new byte[]{(byte)0x90, (byte)0xDA, 0x00, 0x00, 0x03},
                DESFIRE_AID,
                new byte[]{0x00}
            ), "DeleteApplication");

            // Re-seleccionar y re-auth tras borrar
            sendOk(new byte[]{(byte)0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00},
                "SELECT Master App (re-auth)");
            if (!authenticateDes(0x00, MASTER_KEY_DES))
                throw new Exception("Re-auth master DES fallida.");
        }

        // CreateApplication con ISO DF Name
        // payload = AID(3) + keySettings(0x0F) + numKeys(0x21) + isoFID(0x10,0xE1) + dfName(7)
        byte[] payload = concat(
            DESFIRE_AID,
            new byte[]{0x0F, 0x21, 0x10, (byte)0xE1},
            ISO_DF_NAME
        );
        sendOk(concat(
            new byte[]{(byte)0x90, (byte)0xCA, 0x00, 0x00, (byte)payload.length},
            payload,
            new byte[]{0x00}
        ), "CreateApplication");
        Log.d(TAG, "App creada con ISO DF Name + ISO FID 10E1");

        // SELECT nueva app
        send(concat(
            new byte[]{(byte)0x90, 0x5A, 0x00, 0x00, 0x03},
            DESFIRE_AID,
            new byte[]{0x00}
        ));

        // Auth DES en la nueva app (misma clave de fábrica)
        if (!authenticateDes(0x00, MASTER_KEY_DES))
            throw new Exception("Auth app DES fallida.");
        Log.d(TAG, "Auth app DES OK");

        // CreateFile 01 (CC) con ISO File ID E103
        // 90 CD 00 00 09  01 03E1  00  E0EE  0F0000  00
        sendOk(new byte[]{
            (byte)0x90, (byte)0xCD, 0x00, 0x00, 0x09,
            0x01,               // file number
            0x03, (byte)0xE1,   // ISO File ID E103
            0x00,               // communication: Plain
            (byte)0xE0, (byte)0xEE, // access rights
            0x0F, 0x00, 0x00,   // size: 15 bytes
            0x00                // Le
        }, "CreateFile 01 CC→E103");

        // CreateFile 02 (NDEF) con ISO File ID E104
        // 90 CD 00 00 09  02 04E1  00  E0EE  FF0000  00
        sendOk(new byte[]{
            (byte)0x90, (byte)0xCD, 0x00, 0x00, 0x09,
            0x02,               // file number
            0x04, (byte)0xE1,   // ISO File ID E104
            0x00,               // communication: Plain
            (byte)0xE0, (byte)0xEE, // access rights
            (byte)0xFF, 0x00, 0x00, // size: 255 bytes
            0x00                // Le
        }, "CreateFile 02 NDEF→E104");

        // Escribir CC con comando nativo DESFire 90 3D
        writeDesfire(0x01, CC_DATA);
        // Inicializar NDEF con 2 bytes nulos
        writeDesfire(0x02, new byte[]{0x00, 0x00});

        // Verificar acceso ISO completo
        if (!swOk(send(apduSelectApp()))
            || !swOk(send(apduSelectFile(0xE1, 0x03)))
            || !swOk(send(apduSelectFile(0xE1, 0x04))))
            throw new Exception("Formateo completado pero verificación ISO fallida.");

        Log.i(TAG, "✅ Formateo completado — tarjeta lista para móviles.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  corregirCC() — idéntico a corregir_cc() del Python
    // ─────────────────────────────────────────────────────────────────────────

    private void corregirCC() throws Exception {
        Log.i(TAG, "corregirCC()");
        send(apduSelectApp());
        send(apduSelectFile(0xE1, 0x03));
        sendOk(concat(
            new byte[]{0x00, (byte)0xD6, 0x00, 0x00, (byte)CC_DATA.length},
            CC_DATA
        ), "UPDATE BINARY CC");
        Log.d(TAG, "CC corregido.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  escribir() — idéntico a escribir() del Python
    //  ISO SELECT app + SELECT E104 + ISO UPDATE BINARY sin autenticación
    // ─────────────────────────────────────────────────────────────────────────

    private void escribir(byte[] ndefData) throws Exception {
        // Rellenar hasta 253 bytes (igual que Python: padded = ndef_data + bytes(MAX - len))
        byte[] padded = new byte[NDEF_FILE_SIZE];
        System.arraycopy(ndefData, 0, padded, 0, ndefData.length);

        if (!swOk(send(apduSelectApp())))
            throw new Exception("SELECT app NDEF fallido.");
        if (!swOk(send(apduSelectFile(0xE1, 0x04))))
            throw new Exception("SELECT fichero E104 fallido.");

        // ISO UPDATE BINARY en chunks de 59 bytes
        writeIso(padded);

        // Verificar — releer primeros 4 bytes
        send(apduSelectApp());
        send(apduSelectFile(0xE1, 0x04));
        byte[] v = send(new byte[]{0x00, (byte)0xB0, 0x00, 0x00, 0x04});
        if (swOk(v) && v.length >= 4) {
            int written = ((v[0] & 0xFF) << 8) | (v[1] & 0xFF);
            Log.d(TAG, "NDEF verificado: " + written + " bytes en tarjeta");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  SDM — usa TapLinx (requiere auth AES 128)
    //  La tarjeta debe estar previamente formateada con writeNdefUrl()
    // ─────────────────────────────────────────────────────────────────────────

    public void configureSdm(SdmConfig config) throws Exception {
        if (cardV3 == null) throw new Exception("No hay tarjeta EV3 disponible.");
        Log.i(TAG, "=== configureSdm ===");

        // Auth AES con clave por defecto (16 × 0x00)
        KeyData kd = new KeyData();
        kd.setKey(new SecretKeySpec(new byte[16], "AES"));
        ((IDESFireEV1) cardV3).selectApplication(DESFIRE_AID);
        ((IDESFireEV1) cardV3).authenticate(0,
            IDESFireEV1.AuthType.Native, KeyType.AES128, kd);

        // Leer file settings actuales del fichero NDEF (file 02)
        DESFireEV3File.EV3FileSettings raw = cardV3.getDESFireEV3FileSettings(0x02);
        if (!(raw instanceof DESFireEV3File.StdEV3DataFileSettings))
            throw new Exception("El fichero NDEF no es StdEV3DataFileSettings.");

        DESFireEV3File.StdEV3DataFileSettings ds =
            (DESFireEV3File.StdEV3DataFileSettings) raw;

        // Configurar SDM según config
        ds.setSDMEnabled(config.isUidMirroringEnabled()
            || config.isSdmReadCounterEnabled()
            || config.isSdmEncryptionEnabled());

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
        ds.setSdmMacInputOffset(intTo3LE(2)); // tras los 2 bytes NLEN

        // Access rights: 0x0E = clave app sin auth para SDM MAC
        ds.setSdmAccessRights(new byte[]{
            config.getSdmAccessRights(), config.getSdmAccessRights()
        });

        cardV3.changeDESFireEV3FileSettings(0x02, ds);
        Log.i(TAG, "✅ SDM configurado.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  LECTURA — usa IsoDep raw para NDEF, TapLinx para file settings y card info
    // ─────────────────────────────────────────────────────────────────────────

    public IDESFireEV1.CardDetails readCardDetails() throws Exception {
        return ((IDESFireEV1) cardV3).getCardDetails();
    }

    public int[] getApplicationIDs() throws Exception {
        // SELECT Master App primero
        send(new byte[]{(byte)0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00});
        return ((IDESFireEV1) cardV3).getApplicationIDs();
    }

    public byte[] readNdefRaw() throws Exception {
        checkIsoDep();
        send(apduSelectApp());
        send(apduSelectFile(0xE1, 0x04));
        byte[] data = send(new byte[]{0x00, (byte)0xB0, 0x00, 0x00, (byte)0xFE});
        if (!swOk(data) || data.length < 4) return null;
        // Quitar 2 bytes SW del final
        byte[] result = new byte[data.length - 2];
        System.arraycopy(data, 0, result, 0, result.length);
        return result;
    }

    public String readNdefAsString() throws Exception {
        byte[] raw = readNdefRaw();
        if (raw == null || raw.length < 4) return "(vacío)";
        int nlen = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
        if (nlen == 0) return "(sin NDEF)";
        return parseNdefUri(raw, 2, nlen);
    }

    public DESFireEV3File.StdEV3DataFileSettings readSdmSettings() throws Exception {
        KeyData kd = new KeyData();
        kd.setKey(new SecretKeySpec(new byte[16], "AES"));
        ((IDESFireEV1) cardV3).selectApplication(DESFIRE_AID);
        try {
            ((IDESFireEV1) cardV3).authenticate(0,
                IDESFireEV1.AuthType.Native, KeyType.AES128, kd);
        } catch (Exception ignored) {}
        DESFireEV3File.EV3FileSettings s = cardV3.getDESFireEV3FileSettings(0x02);
        return (s instanceof DESFireEV3File.StdEV3DataFileSettings)
            ? (DESFireEV3File.StdEV3DataFileSettings) s : null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  CALCULAR OFFSETS SDM
    // ─────────────────────────────────────────────────────────────────────────

    public void calculateSdmOffsets(String url, SdmConfig config) {
        // Longitud del prefijo que el URI identifier code sustituye
        int prefixLen = 0;
        if      (url.startsWith("https://www.")) prefixLen = 12;
        else if (url.startsWith("https://"))     prefixLen = 8;
        else if (url.startsWith("http://www."))  prefixLen = 11;
        else if (url.startsWith("http://"))      prefixLen = 7;

        // Estructura NDEF: NLEN(2) + 0xD1(1) + typeLen(1) + payloadLen(1) + 'U'(1) + uriId(1) = 7
        final int BASE = 7;
        String u = url;

        // PICC placeholder: 32 ceros = 16 bytes UID cifrado en hex
        int piccPos = u.indexOf("00000000000000000000000000000000");
        if (piccPos >= 0) {
            config.setPiccDataOffset(BASE + (piccPos - prefixLen));
            u = u.replace("00000000000000000000000000000000",
                          "################################");
        }

        // MAC placeholder: 16 ceros = 8 bytes MAC en hex
        int macPos = u.indexOf("0000000000000000");
        if (macPos >= 0) {
            config.setSdmMacOffset(BASE + (macPos - prefixLen));
            u = u.replace("0000000000000000", "################");
        }

        // Counter placeholder: 6 ceros = 3 bytes contador en hex
        int ctrPos = u.indexOf("000000");
        if (ctrPos >= 0)
            config.setSdmReadCounterOffset(BASE + (ctrPos - prefixLen));

        Log.d(TAG, "SDM offsets → PICC=" + config.getPiccDataOffset()
            + " MAC=" + config.getSdmMacOffset()
            + " CTR=" + config.getSdmReadCounterOffset());
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  AUTH DES — idéntico a authenticate_des() del Python
    // ─────────────────────────────────────────────────────────────────────────

    private boolean authenticateDes(int keyNo, byte[] key) {
        try {
            // Step 1: 90 0A 00 00 01 <keyNo> 00
            byte[] step1 = send(new byte[]{
                (byte)0x90, 0x0A, 0x00, 0x00, 0x01, (byte)keyNo, 0x00
            });
            Log.d(TAG, "DES auth step1 SW=" + swHex(step1)
                + " len=" + (step1 != null ? step1.length : 0));

            if (step1 == null || step1.length < 10) return false;
            int sw1 = step1[step1.length - 2] & 0xFF;
            int sw2 = step1[step1.length - 1] & 0xFF;
            if (sw1 != 0x91 || sw2 != 0xAF) {
                Log.e(TAG, "DES step1 SW inesperado: " + String.format("%02X %02X", sw1, sw2));
                return false;
            }

            // rndB_enc = datos sin SW (8 bytes)
            byte[] rndB_enc = new byte[step1.length - 2];
            System.arraycopy(step1, 0, rndB_enc, 0, rndB_enc.length);

            // Descifrar rndB: DES CBC IV=00..00
            byte[] rndB = desCbcDecrypt(key, new byte[8], rndB_enc);

            // rndA aleatorio 8 bytes
            byte[] rndA = new byte[8];
            new SecureRandom().nextBytes(rndA);

            // token = rndA + rotateLeft(rndB)
            byte[] token = new byte[16];
            System.arraycopy(rndA,           0, token, 0, 8);
            System.arraycopy(rotateLeft(rndB), 0, token, 8, 8);

            // Cifrar token: DES CBC IV=rndB_enc
            byte[] tokenEnc = desCbcEncrypt(key, rndB_enc, token);

            // Step 2: 90 AF 00 00 <len> <tokenEnc> 00
            byte[] step2 = send(concat(
                new byte[]{(byte)0x90, (byte)0xAF, 0x00, 0x00, (byte)tokenEnc.length},
                tokenEnc,
                new byte[]{0x00}
            ));
            Log.d(TAG, "DES auth step2 SW=" + swHex(step2));

            if (step2 == null || step2.length < 2) return false;
            boolean ok = (step2[step2.length - 2] & 0xFF) == 0x91
                      && (step2[step2.length - 1] & 0xFF) == 0x00;
            Log.d(TAG, "Auth DES keyNo=" + keyNo + " → " + (ok ? "✅ OK" : "❌ FAIL"));
            return ok;
        } catch (Exception e) {
            Log.e(TAG, "authenticateDes error: " + e.getMessage(), e);
            return false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  writeDesfire() — comando nativo 90 3D (Python: write_desfire)
    // ─────────────────────────────────────────────────────────────────────────

    private void writeDesfire(int fileNo, byte[] data) throws Exception {
        int offset = 0;
        final int CHUNK = 48;
        while (offset < data.length) {
            byte[] chunk = sub(data, offset, Math.min(offset + CHUNK, data.length));
            int clen = chunk.length;
            // 90 3D 00 00 <Lc> <fileNo> <off3LE> <len3LE> <data> 00
            byte[] cmd = new byte[6 + 1 + 3 + 3 + clen + 1];
            cmd[0] = (byte)0x90; cmd[1] = 0x3D; cmd[2] = 0x00; cmd[3] = 0x00;
            cmd[4] = (byte)(1 + 3 + 3 + clen);
            cmd[5] = (byte)fileNo;
            cmd[6] = (byte)(offset & 0xFF);
            cmd[7] = (byte)((offset >> 8) & 0xFF);
            cmd[8] = 0x00;
            cmd[9]  = (byte)(clen & 0xFF);
            cmd[10] = (byte)((clen >> 8) & 0xFF);
            cmd[11] = 0x00;
            System.arraycopy(chunk, 0, cmd, 12, clen);
            cmd[cmd.length - 1] = 0x00;
            byte[] resp = send(cmd);
            if (!swOk(resp))
                throw new Exception("writeDesfire file=" + fileNo
                    + " off=" + offset + " SW=" + swHex(resp));
            offset += clen;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  writeIso() — ISO UPDATE BINARY 00 D6 (Python: write_iso)
    // ─────────────────────────────────────────────────────────────────────────

    private void writeIso(byte[] data) throws Exception {
        int offset = 0;
        final int CHUNK = 59;
        while (offset < data.length) {
            byte[] chunk = sub(data, offset, Math.min(offset + CHUNK, data.length));
            byte[] cmd = new byte[5 + chunk.length];
            cmd[0] = 0x00;
            cmd[1] = (byte)0xD6;
            cmd[2] = (byte)((offset >> 8) & 0xFF);
            cmd[3] = (byte)(offset & 0xFF);
            cmd[4] = (byte)chunk.length;
            System.arraycopy(chunk, 0, cmd, 5, chunk.length);
            byte[] resp = send(cmd);
            if (!swOk(resp))
                throw new Exception("ISO UPDATE BINARY off=" + offset + " SW=" + swHex(resp));
            offset += chunk.length;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  COMUNICACIÓN — IsoDep.transceive() directo
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] send(byte[] apdu) {
        try {
            if (!isoDep.isConnected()) {
                isoDep.connect();
                isoDep.setTimeout(5000);
            }
            byte[] resp = isoDep.transceive(apdu);
            Log.v(TAG, "TX " + bytesToHex(apdu));
            Log.v(TAG, "RX " + bytesToHex(resp));
            return resp;
        } catch (Exception e) {
            Log.e(TAG, "transceive error: " + e.getMessage());
            return null;
        }
    }

    private void sendOk(byte[] apdu, String desc) throws Exception {
        byte[] resp = send(apdu);
        if (!swOk(resp))
            throw new Exception(desc + " fallido. SW=" + swHex(resp));
        Log.d(TAG, "✅ " + desc);
    }

    /** OK si SW = 90 00 / 91 00 / 91 AF / 61 XX */
    private boolean swOk(byte[] resp) {
        if (resp == null || resp.length < 2) return false;
        int s1 = resp[resp.length - 2] & 0xFF;
        int s2 = resp[resp.length - 1] & 0xFF;
        return (s1 == 0x90 && s2 == 0x00)
            || (s1 == 0x91 && s2 == 0x00)
            || (s1 == 0x91 && s2 == 0xAF)
            || (s1 == 0x61);
    }

    private String swHex(byte[] resp) {
        if (resp == null || resp.length < 2) return "null";
        return String.format("%02X %02X",
            resp[resp.length - 2] & 0xFF, resp[resp.length - 1] & 0xFF);
    }

    private void checkIsoDep() throws Exception {
        if (isoDep == null)
            throw new Exception("No hay conexión NFC activa (IsoDep null). Acerca la tarjeta.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  APDUs de selección
    // ─────────────────────────────────────────────────────────────────────────

    /** 00 A4 04 00 07 D2 76 00 00 85 01 01 00 */
    private byte[] apduSelectApp() {
        return new byte[]{
            0x00, (byte)0xA4, 0x04, 0x00, 0x07,
            (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01,
            0x00
        };
    }

    /** 00 A4 00 0C 02 <b1> <b2> */
    private byte[] apduSelectFile(int b1, int b2) {
        return new byte[]{0x00, (byte)0xA4, 0x00, 0x0C, 0x02, (byte)b1, (byte)b2};
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  CRIPTOGRAFÍA DES
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] desCbcDecrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(desEde(key), "DESede"),
            new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    private byte[] desCbcEncrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(desEde(key), "DESede"),
            new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    /** Expande DES 8 bytes → DESede 24 bytes (K||K||K) */
    private byte[] desEde(byte[] k8) {
        byte[] k = new byte[24];
        System.arraycopy(k8, 0, k, 0,  8);
        System.arraycopy(k8, 0, k, 8,  8);
        System.arraycopy(k8, 0, k, 16, 8);
        return k;
    }

    private byte[] rotateLeft(byte[] d) {
        byte[] r = new byte[d.length];
        System.arraycopy(d, 1, r, 0, d.length - 1);
        r[d.length - 1] = d[0];
        return r;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  buildUri() — idéntico a build_uri() del Python
    // ─────────────────────────────────────────────────────────────────────────

    public static byte[] buildUri(String url) {
        byte code = 0x00;
        String body = url;
        if      (url.startsWith("https://www.")) { code = 0x03; body = url.substring(12); }
        else if (url.startsWith("https://"))     { code = 0x04; body = url.substring(8);  }
        else if (url.startsWith("http://www."))  { code = 0x01; body = url.substring(11); }
        else if (url.startsWith("http://"))      { code = 0x02; body = url.substring(7);  }
        else if (url.startsWith("tel:"))         { code = 0x05; body = url.substring(4);  }
        else if (url.startsWith("mailto:"))      { code = 0x06; body = url.substring(7);  }

        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        // payload = [code] + body
        byte[] payload = new byte[1 + b.length];
        payload[0] = code;
        System.arraycopy(b, 0, payload, 1, b.length);
        // record = [D1 01 len 55] + payload
        byte[] record = new byte[4 + payload.length];
        record[0] = (byte)0xD1; record[1] = 0x01;
        record[2] = (byte)(payload.length & 0xFF);
        record[3] = 0x55;
        System.arraycopy(payload, 0, record, 4, payload.length);
        // msg = [00 len] + record
        byte[] msg = new byte[2 + record.length];
        msg[0] = 0x00;
        msg[1] = (byte)(record.length & 0xFF);
        System.arraycopy(record, 0, msg, 2, record.length);
        return msg;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    private boolean ndefAppExists(byte[] raw) {
        if (raw == null || raw.length < 5) return false;
        int dlen = raw.length - 2;
        for (int i = 0; i + 2 < dlen; i += 3) {
            if ((raw[i]   & 0xFF) == (DESFIRE_AID[0] & 0xFF)
             && (raw[i+1] & 0xFF) == (DESFIRE_AID[1] & 0xFF)
             && (raw[i+2] & 0xFF) == (DESFIRE_AID[2] & 0xFF))
                return true;
        }
        return false;
    }

    private String parseNdefUri(byte[] buf, int off, int len) {
        try {
            int typeLen = buf[off + 1] & 0xFF;
            int pLen    = buf[off + 2] & 0xFF;
            int ps      = off + 3 + typeLen;
            if (ps >= buf.length || pLen < 1) return "(NDEF inválido)";
            String rest = new String(buf, ps + 1,
                Math.min(pLen - 1, buf.length - ps - 1), StandardCharsets.UTF_8);
            return uriPrefix(buf[ps]) + rest;
        } catch (Exception e) { return "(error: " + e.getMessage() + ")"; }
    }

    private String uriPrefix(byte id) {
        switch (id & 0xFF) {
            case 0x01: return "http://www.";
            case 0x02: return "http://";
            case 0x03: return "https://www.";
            case 0x04: return "https://";
            case 0x05: return "tel:";
            case 0x06: return "mailto:";
            default:   return "";
        }
    }

    private byte[] intTo3LE(int v) {
        return new byte[]{(byte)(v&0xFF),(byte)((v>>8)&0xFF),(byte)((v>>16)&0xFF)};
    }

    private byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) if (a != null) len += a.length;
        byte[] r = new byte[len]; int pos = 0;
        for (byte[] a : arrays) { if (a == null) continue;
            System.arraycopy(a, 0, r, pos, a.length); pos += a.length; }
        return r;
    }

    private byte[] sub(byte[] src, int from, int to) {
        byte[] r = new byte[to - from];
        System.arraycopy(src, from, r, 0, r.length);
        return r;
    }

    public static String bytesToHex(byte[] b) {
        if (b == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }
}
