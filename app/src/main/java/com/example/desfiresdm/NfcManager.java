package com.example.desfiresdm;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;

import com.nxp.nfclib.CardType;
import com.nxp.nfclib.NxpNfcLib;
import com.nxp.nfclib.desfire.DESFireFactory;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.IDESFireEV3;

public class NfcManager {

    private static final String TAG = "NfcManager";

    // ↓ Pon aquí tu API key de TapLinx: https://inspire.nxp.com/mifare/index.html
    public static final String TAPLINX_API_KEY = "219779f86adf848e473e75a2c56b7da6";

    private static NfcManager instance;
    private NxpNfcLib   nxpLib;
    private NfcAdapter  nfcAdapter;
    private IDESFireEV1 currentCard;
    private IsoDep      currentIsoDep;   // canal raw directo — NO pasa por TapLinx
    private CardType    currentCardType;
    private boolean     sdkInitialized = false;

    public interface NfcCallback {
        void onCardDetected(CardType cardType);
        void onError(String message);
    }

    private NfcCallback callback;

    private NfcManager() {}

    public static NfcManager getInstance() {
        if (instance == null) instance = new NfcManager();
        return instance;
    }

    public boolean initSdk(Activity activity) {
        try {
            nxpLib = NxpNfcLib.getInstance();
            nxpLib.registerActivity(activity, TAPLINX_API_KEY);
            nfcAdapter = NfcAdapter.getDefaultAdapter(activity);
            sdkInitialized = true;
            Log.d(TAG, "TapLinx SDK inicializado");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error SDK: " + e.getMessage());
            sdkInitialized = false;
            return false;
        }
    }

    public void setCallback(NfcCallback cb) { this.callback = cb; }
    public boolean isSdkInitialized()       { return sdkInitialized; }
    public NfcAdapter getNfcAdapter()       { return nfcAdapter; }

    public void enableForegroundDispatch(Activity activity) {
        if (nxpLib != null) {
            try { nxpLib.startForeGroundDispatch(); }
            catch (Exception e) { Log.w(TAG, "startFGD: " + e.getMessage()); }
        }
    }

    public void disableForegroundDispatch(Activity activity) {
        if (nxpLib != null) {
            try { nxpLib.stopForeGroundDispatch(); }
            catch (Exception e) { Log.w(TAG, "stopFGD: " + e.getMessage()); }
        }
    }

    /**
     * Procesa el Tag NFC.
     *
     * CLAVE: obtenemos el IsoDep directo del Tag y lo conectamos ANTES
     * de que TapLinx haga nada. Esto nos da un canal raw independiente
     * para enviar APDUs nativos DESFire e ISO sin conflictos con el SDK.
     */
    public boolean processTag(Tag tag) {
        if (tag == null) return false;
        currentCard    = null;
        currentIsoDep  = null;
        currentCardType = null;

        // ── 1. IsoDep directo — timeout generoso ─────────────────────────────
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep != null) {
            try {
                if (!isoDep.isConnected()) isoDep.connect();
                isoDep.setTimeout(5000);
                currentIsoDep = isoDep;
                Log.d(TAG, "IsoDep conectado. MaxLen=" + isoDep.getMaxTransceiveLength());
            } catch (Exception e) {
                Log.w(TAG, "IsoDep connect: " + e.getMessage());
            }
        }

        // ── 2. TapLinx — identificación y wrapper de alto nivel ───────────────
        try {
            CardType cardType = nxpLib.getCardType(tag);
            currentCardType = cardType;
            Log.d(TAG, "Tarjeta: " + cardType);

            if (callback != null) callback.onCardDetected(cardType);

            if (cardType == CardType.DESFireEV3) {
                currentCard = DESFireFactory.getInstance()
                    .getDESFireEV3(nxpLib.getCustomModules());
                Log.d(TAG, "DESFire EV3 listo");
                return true;
            } else {
                String msg = "Tarjeta no compatible: " + cardType + ". Se requiere DESFire EV3.";
                if (callback != null) callback.onError(msg);
                return false;
            }
        } catch (Exception e) {
            Log.e(TAG, "processTag error: " + e.getMessage(), e);
            if (callback != null) callback.onError("Error: " + e.getMessage());
            return false;
        }
    }

    /** IsoDep raw — para APDUs directos (formateo, escritura NDEF) */
    public IsoDep getCurrentIsoDep() { return currentIsoDep; }

    /** IDESFireEV3 via TapLinx — para SDM y lectura de file settings */
    public IDESFireEV3 getCurrentCardEV3() {
        if (currentCard instanceof IDESFireEV3) return (IDESFireEV3) currentCard;
        return null;
    }

    public IDESFireEV1 getCurrentCard()     { return currentCard; }
    public boolean     hasCard()            { return currentCard != null; }
    public CardType    getCurrentCardType() { return currentCardType; }
}
