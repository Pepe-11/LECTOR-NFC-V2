package com.example.desfiresdm;

import android.util.Log;

import com.nxp.nfclib.IsoDepReader;
import com.nxp.nfclib.desfire.DESFireEV3File;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.IDESFireEV3;
import com.nxp.nfclib.interfaces.IReader;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Traducción fiel del script Python nfc_writer.py a Java/Android.
 *
 * ARQUITECTURA:
 *   - Toda la comunicación con la tarjeta usa APDUs ISO directos via IsoDepReader.transceive()
 *   - No se usa la API de alto nivel de TapLinx para formateo/escritura (causa errores de auth)
 *   - Solo se usa TapLinx para obtener el lector (getReader()) y para SDM (changeDESFireEV3FileSettings)
 *
 * FLUJO IDÉNTICO AL SCRIPT PYTHON:
 *   1. check_card_status() → detecta si necesita formateo, corrección de CC, o está lista
 *   2. formatear()         → DES auth + CreateApp + CreateFiles + WriteCC
 *   3. escribir()          → ISO SELECT app + SELECT E104 + ISO UPDATE BINARY (sin auth)
 *   4. configureSdm()      → usa TapLinx (auth AES necesaria para SDM)
 */
public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    // ── Constantes ────────────────────────────────────────────────────────────
    public static final int    NDEF_FILE_SIZE  = 253; // igual que el script MAX=253
    public static final byte[] MASTER_KEY_DES  = new byte[8];  // 8 × 0x00

    private static final byte[] DESFIRE_AID    = {(byte)0xD2, 0x76, 0x00};
    private static final byte[] ISO_DF_NAME    = {
        (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01
    };

    /** CC correcto — idéntico al script Python */
    private static final byte[] CC_DATA = {
        0x00, 0x0F, 0x20, 0x00, 0x7F, 0x00, 0x73,
        0x04, 0x06,
        (byte)0xE1, 0x04,   // ← ISO FID fichero NDEF
        0x00, (byte)0xFF,
        0x00, 0x00
    };

    private final IDESFireEV3 cardV3;
    private final IReader     reader;

    public DesfireOperations(IDESFireEV3 card) {
        this.cardV3 = card;
        this.reader = ((IDESFireEV1) card).getReader();
    }

    /** Constructor sin tarjeta — solo para calcular offsets en UI */
    public DesfireOperations() {
        this.cardV3 = null;
        this.reader = null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PUNTO DE ENTRADA — writeNdefUrl()
    // Lógica idéntica a conectar() del script Python
    // ─────────────────────────────────────────────────────────────────────────

    public void writeNdefUrl(String url) throws Exception {

        byte[] ndefMessage = buildNdefUriMessage(url);
    
        if (ndefMessage.length > NDEF_FILE_SIZE) {
            throw new Exception("URL demasiado larga");
        }
    
        // seleccionar aplicación NDEF
        card.selectApplication(NDEF_AID);
    
        // autenticar con key 0
        authenticateApp(null, 0);
    
        // borrar contenido previo
        byte[] empty = new byte[NDEF_FILE_SIZE];
        card.writeData(
            NDEF_DATA_FILE_ID,
            0,
            empty.length,
            empty,
            IDESFireEV1.CommunicationType.Plain
        );
    
        // escribir mensaje NDEF
        card.writeData(
            NDEF_DATA_FILE_ID,
            0,
            ndefMessage.length,
            ndefMessage,
            IDESFireEV1.CommunicationType.Plain
        );
    
        Log.d(TAG, "NDEF escrito correctamente: " + url);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // check_card_status() — traducción fiel
    // ─────────────────────────────────────────────────────────────────────────

    private String checkCardStatus() {
        // Intentar SELECT app por DF Name
        byte[] rApp = send(apdu_selectApp());
        if (!swOk(rApp)) return "needs_format";

        // Intentar SELECT E103 y E104
        byte[] rCC   = send(apdu_selectFile(new byte[]{(byte)0xE1, 0x03}));
        byte[] rNDEF = send(apdu_selectFile(new byte[]{(byte)0xE1, 0x04}));

        if (!swOk(rCC) || !swOk(rNDEF)) return "needs_format";

        // Leer CC y verificar que apunta a E104
        byte[] ccRaw = send(new byte[]{0x00, (byte)0xB0, 0x00, 0x00, 0x0F});
        if (!swOk(ccRaw) || ccRaw.length < 13) return "needs_cc";

        // data = ccRaw sin los 2 bytes SW al final
        // bytes[8] y [9] del CC (índices 8 y 9 del data) deben ser E1 04
        // ccRaw incluye SW, así que data termina en ccRaw.length-2
        if ((ccRaw[8] & 0xFF) == 0xE1 && (ccRaw[9] & 0xFF) == 0x04) {
            return "ready";
        }
        return "needs_cc";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // formatear() — traducción fiel del Python
    // ─────────────────────────────────────────────────────────────────────────

    private void formatear() throws Exception {
        Log.i(TAG, "=== formatear() ===");

        // SELECT Master App (90 5A 00 00 03 00 00 00 00)
        sendOk(new byte[]{(byte)0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00},
            "SELECT Master App");

        // Auth DES con clave maestra
        if (!authenticateDes(0x00, MASTER_KEY_DES)) {
            throw new Exception("Auth master DES fallida durante formateo.");
        }
        Log.d(TAG, "Auth master OK");

        // GetApplicationIDs (90 6A 00 00 00)
        byte[] appsRaw = send(new byte[]{(byte)0x90, 0x6A, 0x00, 0x00, 0x00});
        if (ndefAppExistsInResponse(appsRaw)) {
            Log.w(TAG, "App NDEF existe — borrando...");
            sendOk(new byte[]{
                (byte)0x90, (byte)0xDA, 0x00, 0x00, 0x03,
                DESFIRE_AID[0], DESFIRE_AID[1], DESFIRE_AID[2],
                0x00
            }, "DeleteApplication");
            // Re-auth tras borrar
            send(new byte[]{(byte)0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00});
            if (!authenticateDes(0x00, MASTER_KEY_DES)) {
                throw new Exception("Re-auth master DES fallida tras borrar app.");
            }
        }

        // CreateApplication con ISO File IDs
        // payload = AID(3) + keySettings(0x0F) + numKeys(0x21) + isoFID(0x10,0xE1) + dfName(7)
        // idéntico a: payload = DESFIRE_AID + [0x0F, 0x21] + [0x10, 0xE1] + ISO_DF_NAME
        byte[] createPayload = concat(
            DESFIRE_AID,
            new byte[]{0x0F, 0x21, 0x10, (byte)0xE1},
            ISO_DF_NAME
        );
        byte[] createCmd = concat(
            new byte[]{(byte)0x90, (byte)0xCA, 0x00, 0x00, (byte)createPayload.length},
            createPayload,
            new byte[]{0x00}
        );
        sendOk(createCmd, "CreateApplication (ISO)");
        Log.d(TAG, "App creada con ISO DF Name");

        // SELECT nueva app
        send(concat(
            new byte[]{(byte)0x90, 0x5A, 0x00, 0x00, 0x03},
            DESFIRE_AID,
            new byte[]{0x00}
        ));

        // Auth DES en la nueva app
        if (!authenticateDes(0x00, MASTER_KEY_DES)) {
            throw new Exception("Auth app DES fallida tras crear app.");
        }

        // CreateFile 01 (CC) → ISO ID E103
        // 90 CD 00 00 09  01 03 E1  00 E0 EE  0F 00 00  00
        sendOk(new byte[]{
            (byte)0x90, (byte)0xCD, 0x00, 0x00, 0x09,
            0x01,               // file number
            0x03, (byte)0xE1,   // ISO File ID E103
            0x00,               // Plain
            (byte)0xE0, (byte)0xEE, // access rights
            0x0F, 0x00, 0x00,   // size 15 bytes
            0x00
        }, "CreateFile 01 (CC → E103)");

        // CreateFile 02 (NDEF) → ISO ID E104
        // 90 CD 00 00 09  02 04 E1  00 E0 EE  FF 00 00  00
        sendOk(new byte[]{
            (byte)0x90, (byte)0xCD, 0x00, 0x00, 0x09,
            0x02,               // file number
            0x04, (byte)0xE1,   // ISO File ID E104
            0x00,               // Plain
            (byte)0xE0, (byte)0xEE, // access rights
            (byte)0xFF, 0x00, 0x00, // size 255 bytes
            0x00
        }, "CreateFile 02 (NDEF → E104)");

        // Escribir CC con comando DESFire nativo (90 3D)
        writeDesfire(0x01, CC_DATA);
        // Inicializar fichero NDEF con 2 bytes nulos
        writeDesfire(0x02, new byte[]{0x00, 0x00});

        // Verificar acceso ISO
        boolean ok1 = swOk(send(apdu_selectApp()));
        boolean ok2 = swOk(send(apdu_selectFile(new byte[]{(byte)0xE1, 0x03})));
        boolean ok3 = swOk(send(apdu_selectFile(new byte[]{(byte)0xE1, 0x04})));
        if (!ok1 || !ok2 || !ok3) {
            throw new Exception("Formateo completado pero verificación ISO fallida.");
        }
        Log.i(TAG, "Formateo completado — tarjeta lista para móviles.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // corregirCC() — traducción fiel del Python
    // ─────────────────────────────────────────────────────────────────────────

    private void corregirCC() throws Exception {
        Log.i(TAG, "corregirCC()");
        send(apdu_selectApp());
        send(apdu_selectFile(new byte[]{(byte)0xE1, 0x03}));
        byte[] cmd = concat(
            new byte[]{0x00, (byte)0xD6, 0x00, 0x00, (byte)CC_DATA.length},
            CC_DATA
        );
        sendOk(cmd, "UPDATE BINARY CC");
        Log.d(TAG, "CC corregido.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // escribir() — traducción fiel del Python
    // Usa ISO SELECT + ISO UPDATE BINARY, SIN autenticación previa
    // ─────────────────────────────────────────────────────────────────────────

    private void escribir(byte[] ndefData) throws Exception {
        // Rellenar hasta 253 bytes (igual que el script: padded = ndef_data + bytes(MAX - len))
        byte[] padded = new byte[NDEF_FILE_SIZE];
        System.arraycopy(ndefData, 0, padded, 0, ndefData.length);

        // SELECT app por DF Name
        if (!swOk(send(apdu_selectApp()))) {
            throw new Exception("No se pudo seleccionar la app NDEF.");
        }
        // SELECT fichero E104
        if (!swOk(send(apdu_selectFile(new byte[]{(byte)0xE1, 0x04})))) {
            throw new Exception("No se pudo seleccionar el fichero NDEF (E104).");
        }

        // ISO UPDATE BINARY en chunks de 59 bytes (igual que el script chunk_size=59)
        writeIso(padded);

        // Verificar — releer primeros bytes
        send(apdu_selectApp());
        send(apdu_selectFile(new byte[]{(byte)0xE1, 0x04}));
        byte[] verify = send(new byte[]{0x00, (byte)0xB0, 0x00, 0x00, 0x04});
        if (swOk(verify) && verify.length >= 4) {
            int written = ((verify[0] & 0xFF) << 8) | (verify[1] & 0xFF);
            Log.d(TAG, "NDEF escrito: " + written + " bytes");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SDM — usa TapLinx (requiere auth AES, solo funciona tras formateo)
    // ─────────────────────────────────────────────────────────────────────────

    public void configureSdm(SdmConfig config) throws Exception {
        Log.i(TAG, "=== configureSdm ===");

        // Auth AES en la app NDEF
        com.nxp.nfclib.defaultimpl.KeyData kd = new com.nxp.nfclib.defaultimpl.KeyData();
        kd.setKey(new javax.crypto.spec.SecretKeySpec(new byte[16], "AES"));
        ((IDESFireEV1) cardV3).selectApplication(DESFIRE_AID);
        ((IDESFireEV1) cardV3).authenticate(0,
            IDESFireEV1.AuthType.Native,
            com.nxp.nfclib.KeyType.AES128, kd);

        DESFireEV3File.EV3FileSettings raw =
            cardV3.getDESFireEV3FileSettings(0x02);
        if (!(raw instanceof DESFireEV3File.StdEV3DataFileSettings))
            throw new Exception("El fichero NDEF no es StdEV3DataFileSettings.");

        DESFireEV3File.StdEV3DataFileSettings ds =
            (DESFireEV3File.StdEV3DataFileSettings) raw;

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
        ds.setSdmAccessRights(new byte[]{
            config.getSdmAccessRights(), config.getSdmAccessRights()
        });
        cardV3.changeDESFireEV3FileSettings(0x02, ds);
        Log.d(TAG, "SDM configurado.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LEER
    // ─────────────────────────────────────────────────────────────────────────

    public IDESFireEV1.CardDetails readCardDetails() throws Exception {
        return ((IDESFireEV1) cardV3).getCardDetails();
    }

    public int[] getApplicationIDs() throws Exception {
        send(new byte[]{(byte)0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00});
        return ((IDESFireEV1) cardV3).getApplicationIDs();
    }

    public byte[] readNdefRaw() throws Exception {
        send(apdu_selectApp());
        send(apdu_selectFile(new byte[]{(byte)0xE1, 0x04}));
        byte[] data = send(new byte[]{0x00, (byte)0xB0, 0x00, 0x00, (byte)0xFE});
        if (!swOk(data) || data.length < 4) return null;
        // Quitar los 2 bytes SW al final
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
        com.nxp.nfclib.defaultimpl.KeyData kd = new com.nxp.nfclib.defaultimpl.KeyData();
        kd.setKey(new javax.crypto.spec.SecretKeySpec(new byte[16], "AES"));
        ((IDESFireEV1) cardV3).selectApplication(DESFIRE_AID);
        try {
            ((IDESFireEV1) cardV3).authenticate(0,
                IDESFireEV1.AuthType.Native,
                com.nxp.nfclib.KeyType.AES128, kd);
        } catch (Exception ignored) {}
        DESFireEV3File.EV3FileSettings s = cardV3.getDESFireEV3FileSettings(0x02);
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

        // NLEN(2) + 0xD1(1) + typeLen(1) + payloadLen(1) + 'U'(1) + uriId(1) = 7
        final int BASE = 7;

        String u = url;
        int piccPos = u.indexOf("00000000000000000000000000000000");
        if (piccPos >= 0) {
            config.setPiccDataOffset(BASE + (piccPos - prefixLen));
            u = u.replace("00000000000000000000000000000000",
                          "################################");
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
    // AUTENTICACIÓN DES — traducción fiel del Python
    // ─────────────────────────────────────────────────────────────────────────

    private boolean authenticateDes(int keyNo, byte[] key) {
        try {
            // Step 1: 90 0A 00 00 01 keyNo 00
            byte[] step1 = send(new byte[]{
                (byte)0x90, 0x0A, 0x00, 0x00, 0x01, (byte)keyNo, 0x00
            });
            if (step1 == null || step1.length < 10) return false;
            // SW debe ser 91 AF
            int sw1 = step1[step1.length - 2] & 0xFF;
            int sw2 = step1[step1.length - 1] & 0xFF;
            if (sw1 != 0x91 || sw2 != 0xAF) return false;

            // rndB_enc = respuesta sin los 2 bytes SW
            byte[] rndB_enc = new byte[step1.length - 2];
            System.arraycopy(step1, 0, rndB_enc, 0, rndB_enc.length);

            // Descifrar rndB con DES CBC IV=00..00
            byte[] rndB = desCbcDecrypt(key, new byte[8], rndB_enc);

            // rndA aleatorio
            byte[] rndA = new byte[8];
            new SecureRandom().nextBytes(rndA);

            // token = rndA + rotateLeft(rndB)
            byte[] token = new byte[16];
            System.arraycopy(rndA, 0, token, 0, 8);
            System.arraycopy(rotateLeft(rndB), 0, token, 8, 8);

            // Cifrar token con IV = rndB_enc
            byte[] tokenEnc = desCbcEncrypt(key, rndB_enc, token);

            // Step 2: 90 AF 00 00 10 <tokenEnc> 00
            byte[] step2Cmd = new byte[6 + tokenEnc.length + 1];
            step2Cmd[0] = (byte)0x90; step2Cmd[1] = (byte)0xAF;
            step2Cmd[2] = 0x00; step2Cmd[3] = 0x00;
            step2Cmd[4] = (byte)tokenEnc.length;
            System.arraycopy(tokenEnc, 0, step2Cmd, 5, tokenEnc.length);
            step2Cmd[step2Cmd.length - 1] = 0x00;

            byte[] step2 = send(step2Cmd);
            if (step2 == null || step2.length < 2) return false;
            int r1 = step2[step2.length - 2] & 0xFF;
            int r2 = step2[step2.length - 1] & 0xFF;
            boolean ok = (r1 == 0x91 && r2 == 0x00);
            Log.d(TAG, "Auth DES keyNo=" + keyNo + " → " + (ok ? "OK" : "FAIL") +
                " SW:" + String.format("%02X %02X", r1, r2));
            return ok;
        } catch (Exception e) {
            Log.e(TAG, "authenticateDes error: " + e.getMessage());
            return false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // write_desfire() — escritura nativa DESFire (90 3D)
    // ─────────────────────────────────────────────────────────────────────────

    private void writeDesfire(int fileNo, byte[] data) throws Exception {
        int offset = 0;
        int chunkSize = 48;
        while (offset < data.length) {
            byte[] chunk = subarray(data, offset, Math.min(offset + chunkSize, data.length));
            byte[] cmd = new byte[1 + 3 + 3 + 3 + chunk.length];
            int i = 0;
            // Header: 90 3D 00 00 <len>
            // Dentro del campo de datos: fileNo + off(3LE) + len(3LE) + data
            int dataFieldLen = 1 + 3 + 3 + chunk.length;
            byte[] full = new byte[6 + dataFieldLen];
            full[0] = (byte)0x90; full[1] = 0x3D; full[2] = 0x00; full[3] = 0x00;
            full[4] = (byte)dataFieldLen;
            full[5] = (byte)fileNo;
            full[6] = (byte)(offset & 0xFF);
            full[7] = (byte)((offset >> 8) & 0xFF);
            full[8] = 0x00;
            full[9]  = (byte)(chunk.length & 0xFF);
            full[10] = (byte)((chunk.length >> 8) & 0xFF);
            full[11] = 0x00;
            System.arraycopy(chunk, 0, full, 12, chunk.length);
            // Le falta el 0x00 final del wrap
            byte[] finalCmd = new byte[full.length + 1];
            System.arraycopy(full, 0, finalCmd, 0, full.length);
            finalCmd[finalCmd.length - 1] = 0x00;
            byte[] resp = send(finalCmd);
            if (!swOk(resp))
                throw new Exception("writeDesfire file " + fileNo + " offset " + offset + " fallido SW: " + swHex(resp));
            offset += chunk.length;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // write_iso() — ISO UPDATE BINARY (00 D6)
    // ─────────────────────────────────────────────────────────────────────────

    private void writeIso(byte[] data) throws Exception {
        int offset = 0;
        int chunkSize = 59; // igual que el script
        while (offset < data.length) {
            byte[] chunk = subarray(data, offset, Math.min(offset + chunkSize, data.length));
            byte[] cmd = new byte[5 + chunk.length];
            cmd[0] = 0x00;
            cmd[1] = (byte)0xD6;
            cmd[2] = (byte)((offset >> 8) & 0xFF);
            cmd[3] = (byte)(offset & 0xFF);
            cmd[4] = (byte)chunk.length;
            System.arraycopy(chunk, 0, cmd, 5, chunk.length);
            byte[] resp = send(cmd);
            if (!swOk(resp))
                throw new Exception("ISO UPDATE BINARY offset " + offset + " fallido SW: " + swHex(resp));
            offset += chunk.length;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // APDUs de selección
    // ─────────────────────────────────────────────────────────────────────────

    /** ISO SELECT app por DF Name: 00 A4 04 00 07 D2 76 00 00 85 01 01 00 */
    private byte[] apdu_selectApp() {
        return new byte[]{
            0x00, (byte)0xA4, 0x04, 0x00, 0x07,
            (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01,
            0x00
        };
    }

    /** ISO SELECT EF: 00 A4 00 0C 02 <fid> */
    private byte[] apdu_selectFile(byte[] fid) {
        return new byte[]{0x00, (byte)0xA4, 0x00, 0x0C, 0x02, fid[0], fid[1]};
    }

    // ─────────────────────────────────────────────────────────────────────────
    // COMUNICACIÓN RAW — usa IsoDepReader.transceive()
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Envía un APDU y devuelve la respuesta (datos + 2 bytes SW).
     * Nunca lanza excepción — devuelve null si falla.
     */
    private byte[] send(byte[] apdu) {
        try {
            return reader.transceive(apdu);
        } catch (Exception e) {
            Log.e(TAG, "transceive error: " + e.getMessage());
            return null;
        }
    }

    /** Envía y lanza excepción si el SW no es OK */
    private void sendOk(byte[] apdu, String desc) throws Exception {
        byte[] resp = send(apdu);
        if (!swOk(resp))
            throw new Exception(desc + " fallido. SW: " + swHex(resp));
        Log.d(TAG, desc + " OK");
    }

    /**
     * SW OK si:
     *   90 00 → éxito estándar ISO
     *   91 00 → éxito DESFire
     *   91 AF → más datos (challenge/response)
     *   61 XX → más datos ISO
     */
    private boolean swOk(byte[] resp) {
        if (resp == null || resp.length < 2) return false;
        int sw1 = resp[resp.length - 2] & 0xFF;
        int sw2 = resp[resp.length - 1] & 0xFF;
        return (sw1 == 0x90 && sw2 == 0x00)
            || (sw1 == 0x91 && sw2 == 0x00)
            || (sw1 == 0x91 && sw2 == 0xAF)
            || (sw1 == 0x61);
    }

    private String swHex(byte[] resp) {
        if (resp == null || resp.length < 2) return "null";
        return String.format("%02X %02X",
            resp[resp.length - 2] & 0xFF,
            resp[resp.length - 1] & 0xFF);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS CRIPTOGRÁFICOS — traducción fiel del Python
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] rotateLeft(byte[] data) {
        byte[] result = new byte[data.length];
        System.arraycopy(data, 1, result, 0, data.length - 1);
        result[data.length - 1] = data[0];
        return result;
    }

    private byte[] desCbcDecrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        // DES single key → DESede (K||K||K) igual que el Python usa DES.MODE_CBC
        byte[] ede = new byte[24];
        System.arraycopy(key, 0, ede, 0,  8);
        System.arraycopy(key, 0, ede, 8,  8);
        System.arraycopy(key, 0, ede, 16, 8);
        Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec(ede, "DESede"),
            new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    private byte[] desCbcEncrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        byte[] ede = new byte[24];
        System.arraycopy(key, 0, ede, 0,  8);
        System.arraycopy(key, 0, ede, 8,  8);
        System.arraycopy(key, 0, ede, 16, 8);
        Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(ede, "DESede"),
            new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BUILDERS NDEF — traducción fiel del Python build_uri()
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Construye el mensaje NDEF para una URI.
     * Idéntico al Python: bytes([0x00, len(record)]) + record
     */
    public static byte[] buildUri(String url) {
        byte code = 0x00;
        String body = url;

        // Orden igual que el Python — más largo primero para evitar match parcial
        if      (url.startsWith("https://www.")) { code = 0x03; body = url.substring(12); }
        else if (url.startsWith("https://"))     { code = 0x04; body = url.substring(8);  }
        else if (url.startsWith("http://www."))  { code = 0x01; body = url.substring(11); }
        else if (url.startsWith("http://"))      { code = 0x02; body = url.substring(7);  }
        else if (url.startsWith("tel:"))         { code = 0x05; body = url.substring(4);  }
        else if (url.startsWith("mailto:"))      { code = 0x06; body = url.substring(7);  }

        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[1 + bodyBytes.length];
        payload[0] = code;
        System.arraycopy(bodyBytes, 0, payload, 1, bodyBytes.length);

        // record = [0xD1, 0x01, len(payload), 0x55] + payload
        byte[] record = new byte[4 + payload.length];
        record[0] = (byte)0xD1;
        record[1] = 0x01;
        record[2] = (byte)(payload.length & 0xFF);
        record[3] = 0x55;
        System.arraycopy(payload, 0, record, 4, payload.length);

        // mensaje = [0x00, len(record)] + record
        byte[] msg = new byte[2 + record.length];
        msg[0] = 0x00;
        msg[1] = (byte)(record.length & 0xFF);
        System.arraycopy(record, 0, msg, 2, record.length);
        return msg;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS GENERALES
    // ─────────────────────────────────────────────────────────────────────────

    private boolean ndefAppExistsInResponse(byte[] appsRaw) {
        if (appsRaw == null || appsRaw.length < 5) return false;
        // appsRaw = datos + SW(2). Los datos son grupos de 3 bytes (AIDs)
        int dataLen = appsRaw.length - 2;
        for (int i = 0; i + 2 < dataLen; i += 3) {
            if ((appsRaw[i]   & 0xFF) == (DESFIRE_AID[0] & 0xFF) &&
                (appsRaw[i+1] & 0xFF) == (DESFIRE_AID[1] & 0xFF) &&
                (appsRaw[i+2] & 0xFF) == (DESFIRE_AID[2] & 0xFF)) {
                return true;
            }
        }
        return false;
    }

    private String parseNdefUri(byte[] buf, int off, int len) {
        try {
            int typeLen  = buf[off + 1] & 0xFF;
            int pLen     = buf[off + 2] & 0xFF;
            int ps       = off + 3 + typeLen;
            if (ps >= buf.length || pLen < 1) return "(NDEF inválido)";
            byte uid  = buf[ps];
            String rest = new String(buf, ps + 1,
                Math.min(pLen - 1, buf.length - ps - 1), StandardCharsets.UTF_8);
            return uriPrefix(uid) + rest;
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
        return new byte[]{(byte)(v & 0xFF), (byte)((v >> 8) & 0xFF), (byte)((v >> 16) & 0xFF)};
    }

    private byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) if (a != null) len += a.length;
        byte[] result = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            if (a == null) continue;
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    private byte[] subarray(byte[] src, int from, int to) {
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
