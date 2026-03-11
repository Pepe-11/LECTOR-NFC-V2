package com.example.desfiresdm;

/**
 * Modelo de datos para la configuración SDM (Secure Dynamic Messaging).
 *
 * SDM permite que la tarjeta genere automáticamente una URL dinámica con
 * parámetros criptográficamente protegidos cada vez que se lee por NFC.
 *
 * Ejemplo de URL dinámica generada:
 * https://tudominio.com/nfc?picc=AABBCCDD&enc=EEFFGG&mac=HHIIJJ&ctr=001234
 *
 * Dónde:
 *  - picc: datos cifrados del PICC (UID + contador)
 *  - enc:  datos de fichero cifrados (opcional)
 *  - mac:  MAC de autenticidad calculado por la tarjeta
 *  - ctr:  contador de lecturas (en claro, opcional)
 */
public class SdmConfig {

    // URL base que se escribe en la tarjeta (parte estática)
    private String baseUrl;

    // ── Offsets dentro de la URL donde la tarjeta inyecta los datos dinámicos ─
    // Los offsets son posiciones en bytes dentro del fichero NDEF.
    // El SDK necesita saber EXACTAMENTE dónde empieza cada campo en el fichero.

    /** Offset del campo PICC Data (UID cifrado + contador) */
    private int piccDataOffset;

    /** Offset del MAC generado por la tarjeta */
    private int sdmMacOffset;

    /** Offset del campo de datos cifrados (si se usa SDM Encryption) */
    private int sdmEncOffset;

    /** Longitud de los datos cifrados */
    private int sdmEncLength;

    /** Offset del contador de lecturas en claro */
    private int sdmReadCounterOffset;

    // ── Opciones habilitadas ──────────────────────────────────────────────────

    /** true = la tarjeta incluirá el UID cifrado en la URL */
    private boolean uidMirroringEnabled;

    /** true = la tarjeta incluirá el contador de lecturas */
    private boolean sdmReadCounterEnabled;

    /** true = se cifrarán parte de los datos del fichero */
    private boolean sdmEncryptionEnabled;

    /** true = se añade límite al contador de lecturas */
    private boolean sdmReadCounterLimitEnabled;

    /** Límite máximo de lecturas (si sdmReadCounterLimitEnabled = true) */
    private int sdmReadCounterLimit;

    // ── Derechos de acceso SDM (nibbles de 4 bits) ──────────────────────────
    // Valor 0x0E = clave de aplicación 14 (sin autenticación necesaria = lectura libre)
    // Valor 0x0F = acceso libre sin clave

    /**
     * Byte de derechos SDM.
     * Formato: [SDMMACInputKey (4b) | SDMMetaReadKey (4b)]
     * 0xEE = libre lectura para ambos (típico para SDM con URL pública)
     */
    private byte sdmAccessRights;

    // ── Constructor con valores por defecto razonables ───────────────────────

    public SdmConfig() {
        // URL de ejemplo - el usuario la personaliza en la UI
        this.baseUrl = "https://sdm.example.com/nfc";
        this.uidMirroringEnabled = true;
        this.sdmReadCounterEnabled = true;
        this.sdmEncryptionEnabled = false;
        this.sdmReadCounterLimitEnabled = false;
        this.sdmReadCounterLimit = 0;
        this.sdmAccessRights = (byte) 0xEE; // libre lectura
        // Los offsets se calculan en DesfireOperations según la URL
        this.piccDataOffset = 0;
        this.sdmMacOffset = 0;
        this.sdmEncOffset = 0;
        this.sdmEncLength = 32;
        this.sdmReadCounterOffset = 0;
    }

    // ── Getters y Setters ────────────────────────────────────────────────────

    public String getBaseUrl() { return baseUrl; }
    public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }

    public int getPiccDataOffset() { return piccDataOffset; }
    public void setPiccDataOffset(int piccDataOffset) { this.piccDataOffset = piccDataOffset; }

    public int getSdmMacOffset() { return sdmMacOffset; }
    public void setSdmMacOffset(int sdmMacOffset) { this.sdmMacOffset = sdmMacOffset; }

    public int getSdmEncOffset() { return sdmEncOffset; }
    public void setSdmEncOffset(int sdmEncOffset) { this.sdmEncOffset = sdmEncOffset; }

    public int getSdmEncLength() { return sdmEncLength; }
    public void setSdmEncLength(int sdmEncLength) { this.sdmEncLength = sdmEncLength; }

    public int getSdmReadCounterOffset() { return sdmReadCounterOffset; }
    public void setSdmReadCounterOffset(int sdmReadCounterOffset) { this.sdmReadCounterOffset = sdmReadCounterOffset; }

    public boolean isUidMirroringEnabled() { return uidMirroringEnabled; }
    public void setUidMirroringEnabled(boolean uidMirroringEnabled) { this.uidMirroringEnabled = uidMirroringEnabled; }

    public boolean isSdmReadCounterEnabled() { return sdmReadCounterEnabled; }
    public void setSdmReadCounterEnabled(boolean sdmReadCounterEnabled) { this.sdmReadCounterEnabled = sdmReadCounterEnabled; }

    public boolean isSdmEncryptionEnabled() { return sdmEncryptionEnabled; }
    public void setSdmEncryptionEnabled(boolean sdmEncryptionEnabled) { this.sdmEncryptionEnabled = sdmEncryptionEnabled; }

    public boolean isSdmReadCounterLimitEnabled() { return sdmReadCounterLimitEnabled; }
    public void setSdmReadCounterLimitEnabled(boolean sdmReadCounterLimitEnabled) { this.sdmReadCounterLimitEnabled = sdmReadCounterLimitEnabled; }

    public int getSdmReadCounterLimit() { return sdmReadCounterLimit; }
    public void setSdmReadCounterLimit(int sdmReadCounterLimit) { this.sdmReadCounterLimit = sdmReadCounterLimit; }

    public byte getSdmAccessRights() { return sdmAccessRights; }
    public void setSdmAccessRights(byte sdmAccessRights) { this.sdmAccessRights = sdmAccessRights; }
}
